"""Detector: tails gateway evidence (read-only mount) and Hubble drops, raises alerts via the
control plane, and independently verifies containment from both telemetry sources."""
from __future__ import annotations

import asyncio
import json
import os
import time

import aiohttp

from sbx.common import internal
from sbx.common.evidence import GENESIS, _digest
from sbx.common.policy import ControlPlane
from sbx.detector.rules import Engine, alert

EVIDENCE = os.path.join(os.environ.get("EVIDENCE_DIR", "/evidence"), "gateway.jsonl")
HUBBLE_SERVER = os.environ.get("HUBBLE_SERVER", "hubble-relay.kube-system.svc:80")
REPLAY_GRACE_S = 60          # on restart, re-verify the whole chain but only alert on recent events

cp = ControlPlane(ttl=1.0)
engine = Engine()
policies: dict[str, dict] = {}
gateway_events: dict[str, list] = {}
sent: set[str] = set()
started = time.time()


def log(**kw) -> None:
    print(json.dumps({"ts": time.time(), **kw}), flush=True)


async def policy(sid: str) -> dict | None:
    status, body = await cp.policy(sid)
    if status == 200:
        policies[sid] = body
        return body
    return None


async def emit(http: aiohttp.ClientSession, a: dict) -> None:
    if a["alert_id"] in sent:
        return
    sent.add(a["alert_id"])
    async with http.post(f"{internal.CONTROL_PLANE_URL}/internal/alerts", json=a) as r:
        rec = await r.json()
    log(alert=a["rule"], severity=a["severity"], session=a["session_id"], summary=a["summary"],
        contained=bool((rec.get("containment") or {}).get("quarantined_at")))
    c = rec.get("containment") or {}
    if c.get("quarantined_at"):
        asyncio.create_task(verify(http, a, c))


async def verify(http: aiohttp.ClientSession, a: dict, c: dict) -> None:
    """Containment counts as verified only if two independent sources agree:
    Hubble shows the pod's traffic being DROPPED after quarantine, and the gateway saw no
    allowed request from the session after revocation. The control plane's in-pod probe is a third,
    weaker signal (its output comes from the untrusted pod)."""
    await asyncio.sleep(8)
    sid, q, r = a["session_id"], c["quarantined_at"], c["revoked_at"]
    drops = [d for d in engine.drops_by_session.get(sid, []) if d["time"] >= q]
    allows = [e for e in gateway_events.get(sid, []) if e.get("ts", 0) >= r and e.get("decision") == "allow"]
    sources = {"hubble_drops_after_quarantine": len(drops), "gateway_allows_after_revoke": len(allows),
               "probe": c.get("probe"), "probe_blocked": c.get("probe_blocked"),
               "containment_latency_s": round(q - r, 3)}
    ok = len(drops) > 0 and not allows and bool(c.get("probe_blocked"))
    async with http.post(f"{internal.CONTROL_PLANE_URL}/internal/alerts/verification",
                         json={"alert_id": a["alert_id"], "session_id": sid, "verified": ok, "sources": sources}):
        pass
    log(verification=sid, verified=ok, **{k: v for k, v in sources.items() if k != "probe"})


async def tail_gateway(http: aiohttp.ClientSession) -> None:
    pos, prev, broken = 0, GENESIS, False
    while True:
        if not os.path.exists(EVIDENCE):
            await asyncio.sleep(1)
            continue
        with open(EVIDENCE) as f:
            f.seek(pos)
            while line := f.readline():
                if not line.endswith("\n"):
                    break
                pos = f.tell()
                e = json.loads(line)
                claimed = e.pop("hash")
                if not broken and (e.get("prev_hash") != prev or _digest(prev, e) != claimed):
                    broken = True
                    await emit(http, alert("EV", "high", None, f"gateway evidence chain broken at seq {e.get('seq')}",
                                           {"file": EVIDENCE}, [{"source": "gateway", "seq": e.get("seq")}]))
                prev, e["hash"] = claimed, claimed
                sid = e.get("session_id")
                if sid:
                    gateway_events.setdefault(sid, []).append(e)
                if e.get("ts", 0) < started - REPLAY_GRACE_S or not sid:
                    continue
                for a in engine.on_gateway(e, await policy(sid)):
                    await emit(http, a)
        await asyncio.sleep(0.5)


async def tail_hubble(http: aiohttp.ClientSession) -> None:
    while True:
        proc = await asyncio.create_subprocess_exec(
            "hubble", "observe", "--server", HUBBLE_SERVER, "--namespace", "sbx-sessions", "--verdict", "DROPPED",
            "--follow", "-o", "json", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        log(hubble="connected", server=HUBBLE_SERVER)
        assert proc.stdout
        async for raw in proc.stdout:
            try:
                flow = json.loads(raw).get("flow", {})
            except ValueError:
                continue
            sid = next((l.split("=", 1)[1] for l in flow.get("source", {}).get("labels", [])
                        if l.startswith("k8s:sbx/session=")), None)
            if sid:
                await policy(sid)
            for a in engine.on_flow(flow, lambda s: policies.get(s)):
                await emit(http, a)
        err = (await proc.stderr.read()).decode()[:300] if proc.stderr else ""
        log(hubble="disconnected", rc=await proc.wait(), stderr=err)
        await asyncio.sleep(3)


async def main() -> None:
    async with aiohttp.ClientSession(headers=internal.headers(), timeout=aiohttp.ClientTimeout(total=60)) as http:
        for attempt in range(60):                     # the control plane may still be starting
            try:
                async with http.get(f"{internal.CONTROL_PLANE_URL}/internal/alerts") as r:
                    sent.update(a.get("alert_id") for a in await r.json() if a.get("alert_id"))
                break
            except aiohttp.ClientError:
                log(detector="waiting for control plane", attempt=attempt)
                await asyncio.sleep(2)
        log(detector="started", known_alerts=len(sent))
        await asyncio.gather(tail_gateway(http), tail_hubble(http))


if __name__ == "__main__":
    asyncio.run(main())
