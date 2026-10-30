"""Sentinel: continuously running detection and response, in its own namespace and on its own node.

  sources   shipped platform evidence (verified on arrival: sequence + hash chain)
            Hubble flows from session pods AND platform pods (kernel datapath, platform can't fake)
  detect    D1-D3, EV (evidence integrity), S2 (platform egress), S6 (leak after containment)
  respond   its OWN quarantine/freeze Cilium deny policies (works with the control plane down),
            then best-effort token revocation + snapshot via the control plane
  record    its own hash-chained alert/action log on its own volume

Ports: 9100 ingest (from the shipper only), 127.0.0.1:9101 admin (kubectl exec into this pod).
"""
from __future__ import annotations

import asyncio
import json
import os
import time

import aiohttp
from aiohttp import web

from sbx.common import internal
from sbx.common.evidence import GENESIS, EvidenceLog, _digest
from sbx.common.policy import ControlPlane
from sbx.sentinel import actions
from sbx.sentinel.rules import Engine, _ts, alert, leak_after_containment, platform_flow_alert

DATA = os.environ.get("SENTINEL_DATA", "/data")
HUBBLE = os.environ.get("HUBBLE_SERVER", "hubble-relay.kube-system.svc:80")
INGEST_KEY = os.environ.get("SENTINEL_INGEST_KEY", "")
DEFAULT_POLICY = {"state": "running", "policy": {"deny_burst": {"count": 5, "window_s": 60}}}
REPLAY_GRACE_S = 60

cp = ControlPlane(ttl=2.0)
engine = Engine()
log = EvidenceLog("sentinel", DATA)                         # alerts, actions, verifications
started = time.time()
sent: set[str] = set()
contained: dict[str, float] = {}                             # sid -> time containment took effect
forwarded: dict[str, list] = {}                              # sid -> times Cilium forwarded egress after containment
GRACE_S = 3.0
policies: dict[str, dict] = {}
positions: dict[str, int] = {}                              # file -> last verified seq
chain_head: dict[str, str] = {}
broken: set[str] = set()


def out(**kw) -> None:
    print(json.dumps({"ts": time.time(), **kw}), flush=True)


# ------------------------------------------------------------------------------------------ helpers
async def policy(sid: str) -> dict:
    try:
        status, body = await cp.policy(sid)
        if status == 200:
            policies[sid] = body
            return body
    except Exception:  # noqa: BLE001 - control plane down: keep detecting with defaults
        pass
    return policies.get(sid, DEFAULT_POLICY)


async def cp_post(http: aiohttp.ClientSession, path: str, body: dict) -> dict | None:
    try:
        async with http.post(internal.CONTROL_PLANE_URL + path, json=body,
                             timeout=aiohttp.ClientTimeout(total=30)) as r:
            return await r.json() if r.status == 200 else {"status": r.status}
    except Exception as e:  # noqa: BLE001
        return {"error": f"control plane unreachable: {type(e).__name__}"}


# ---------------------------------------------------------------------------------------- response
async def respond(http: aiohttp.ClientSession, a: dict) -> None:
    if a["alert_id"] in sent:
        return
    sent.add(a["alert_id"])
    sid = a.get("session_id")
    rec = {k: v for k, v in a.items() if k != "contain"}
    acted = None
    if a.get("contain") and sid:
        t0 = time.time()
        created = await asyncio.to_thread(actions.quarantine, sid)     # 1. our own deny policy, first
        contained.setdefault(sid, t0)
        acted = {"action": "sentinel_quarantine", "policy": f"sentinel-q-{sid}", "created": created,
                 "at": t0, "elapsed_s": round(time.time() - t0, 3)}
    log.write_sync("alert", **rec, sentinel_action=acted)
    # 2. best effort: control plane revokes the token, snapshots evidence, records the alert for users
    cp_result = await cp_post(http, "/internal/alerts", a)
    log.write_sync("control_plane_notified", alert_id=a["alert_id"], session_id=sid,
                   result={k: (cp_result or {}).get(k) for k in ("seq", "error", "status")})
    out(alert=a["rule"], severity=a["severity"], session=sid, summary=a["summary"], quarantined=bool(acted))
    if acted:
        asyncio.create_task(verify(http, a["alert_id"], sid, acted["at"]))


async def verify(http: aiohttp.ClientSession, alert_id: str, sid: str, at: float) -> None:
    """Containment counts only if the kernel agrees: Hubble shows the pod's traffic DROPPED after our
    quarantine and nothing FORWARDED after the grace period. Polls up to 60 s; with no traffic at all
    the result is recorded as inconclusive rather than claimed."""
    drops, fwd, present = [], [], False
    for _ in range(30):
        await asyncio.sleep(2)
        drops = [d for d in engine.drops_by_session.get(sid, []) if d["time"] >= at]
        fwd = [t for t in forwarded.get(sid, []) if t >= at + GRACE_S]
        if fwd or drops:
            break
    present = sid in await asyncio.to_thread(actions.quarantined_sessions)
    ok = present and bool(drops) and not fwd
    sources = {"hubble_drops_after_quarantine": len(drops), "forwarded_after_quarantine": len(fwd),
               "sentinel_policy_present": present, "result": "verified" if ok else
               ("leaking" if fwd else ("inconclusive: no traffic observed" if not drops else "policy missing"))}
    log.write_sync("containment_verification", alert_id=alert_id, session_id=sid, verified=ok, sources=sources)
    await cp_post(http, "/internal/alerts/verification",
                  {"alert_id": alert_id, "session_id": sid, "verified": ok, "sources": sources})
    out(verification=sid, verified=ok, **sources)


# ------------------------------------------------------------------------------- ingest (evidence)
async def ingest_position(request: web.Request) -> web.Response:
    if request.headers.get("X-Sbx-Ingest") != INGEST_KEY or not INGEST_KEY:
        raise web.HTTPUnauthorized()
    return web.json_response(positions)


async def ingest(request: web.Request) -> web.Response:
    if request.headers.get("X-Sbx-Ingest") != INGEST_KEY or not INGEST_KEY:
        raise web.HTTPUnauthorized()
    body = await request.json()
    name = body["file"]
    if name not in ("gateway.jsonl", "control-plane.jsonl"):
        raise web.HTTPBadRequest()
    http = request.app["http"]
    with open(os.path.join(DATA, "copy", name), "a") as copy:
        for e in body["events"]:
            last = positions.get(name, 0)
            if e["seq"] <= last:
                continue
            if e["seq"] != last + 1 and name not in broken:          # a hole: something was never shipped
                broken.add(name)
                await respond(http, alert("EV", "high", None, f"{name}: sequence gap {last} -> {e['seq']}",
                                          {"file": name}, [{"source": "shipper", "seq": e["seq"]}]))
            claimed = e.get("hash")
            body_ = {k: v for k, v in e.items() if k != "hash"}
            prev = chain_head.get(name, GENESIS)
            if (body_.get("prev_hash") != prev or _digest(prev, body_) != claimed) and name not in broken:
                broken.add(name)
                await respond(http, alert("EV", "high", None, f"{name}: hash chain broken at seq {e['seq']}",
                                          {"file": name}, [{"source": "shipper", "seq": e["seq"]}]))
            copy.write(json.dumps(e, sort_keys=True) + "\n")
            positions[name], chain_head[name] = e["seq"], claimed
            await handle_event(http, name, e)
    return web.json_response({"ok": True, "position": positions.get(name, 0)})


async def handle_event(http: aiohttp.ClientSession, name: str, e: dict) -> None:
    if name == "control-plane.jsonl":
        if e.get("action") == "session_contain" and e.get("session_id"):
            contained.setdefault(e["session_id"], e.get("quarantined_at") or e["ts"])
        elif e.get("action") == "fleet_freeze":
            for sid in e.get("frozen_sessions", []):
                contained.setdefault(sid, e["ts"])
        return
    sid = e.get("session_id")
    if not sid or e.get("ts", 0) < started - REPLAY_GRACE_S:
        return
    for a in engine.on_gateway(e, await policy(sid)):
        await respond(http, a)


# --------------------------------------------------------------------------------- Hubble streams
async def hubble_stream(http: aiohttp.ClientSession, namespace: str, handler) -> None:
    while True:
        proc = await asyncio.create_subprocess_exec(
            "hubble", "observe", "--server", HUBBLE, "--from-namespace", namespace, "--follow", "-o", "json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out(hubble="connected", namespace=namespace)
        assert proc.stdout
        async for raw in proc.stdout:
            try:
                flow = json.loads(raw).get("flow", {})
            except ValueError:
                continue
            await handler(http, flow)
        out(hubble="disconnected", namespace=namespace, rc=await proc.wait())
        await asyncio.sleep(3)


async def on_session_flow(http: aiohttp.ClientSession, flow: dict) -> None:
    sid = next((l.split("=", 1)[1] for l in flow.get("source", {}).get("labels", [])
                if l.startswith("k8s:sbx/session=")), None)
    if not sid:
        return
    if flow.get("verdict") == "DROPPED":
        pol = await policy(sid)
        for a in engine.on_flow(flow, lambda s: pol):
            await respond(http, a)
    elif sid in contained:
        if flow.get("verdict") == "FORWARDED" and flow.get("traffic_direction") == "EGRESS":
            forwarded.setdefault(sid, []).append(_ts(flow.get("time")))
        a = leak_after_containment(flow, contained[sid], GRACE_S)
        if a:
            if contained.get(sid, 0) < time.time() - GRACE_S:     # containment was lifted: ours takes over
                contained[sid] = time.time()
            await respond(http, a)


async def on_platform_flow(http: aiohttp.ClientSession, flow: dict) -> None:
    a = platform_flow_alert(flow)
    if a:
        await respond(http, a)


# ------------------------------------------------------------------------------ housekeeping, admin
async def gc() -> None:
    """Remove sentinel quarantines whose session pod no longer exists."""
    while True:
        await asyncio.sleep(30)
        try:
            stale = await asyncio.to_thread(lambda: actions.quarantined_sessions() - actions.live_sessions())
            for sid in stale:
                await asyncio.to_thread(actions.release, sid)
                log.write_sync("quarantine_released", session_id=sid, reason="pod gone")
        except Exception as e:  # noqa: BLE001
            out(gc_error=str(e)[:200])


async def admin(request: web.Request) -> web.Response:
    cmd = request.match_info["cmd"]
    body = await request.json() if request.can_read_body else {}
    actor = body.get("actor", "unknown")
    if cmd == "freeze":
        created = await asyncio.to_thread(actions.freeze)
        log.write_sync("sentinel_freeze", actor=actor, reason=body.get("reason", ""), created=created)
        return web.json_response({"frozen": True, "created": created})
    if cmd == "unfreeze":
        removed = await asyncio.to_thread(actions.unfreeze)
        log.write_sync("sentinel_unfreeze", actor=actor, removed=removed)
        return web.json_response({"frozen": False, "removed": removed})
    if cmd == "release":
        removed = await asyncio.to_thread(actions.release, body["session_id"])
        contained.pop(body["session_id"], None)
        log.write_sync("quarantine_released", session_id=body["session_id"], actor=actor, removed=removed)
        return web.json_response({"released": removed})
    if cmd == "alerts":
        with open(log.path) as f:
            rows = [json.loads(l) for l in f if l.strip()]
        return web.json_response(rows[-int(body.get("n", 50)):])
    if cmd == "status":
        return web.json_response({"positions": positions, "broken": sorted(broken), "contained": contained,
                                  "quarantined": sorted(await asyncio.to_thread(actions.quarantined_sessions))})
    raise web.HTTPNotFound()


def restore() -> None:
    """Rebuild positions/chain heads and known alerts from our own files after a restart."""
    os.makedirs(os.path.join(DATA, "copy"), exist_ok=True)
    for name in ("gateway.jsonl", "control-plane.jsonl"):
        path = os.path.join(DATA, "copy", name)
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    e = json.loads(line)
                    positions[name], chain_head[name] = e["seq"], e["hash"]
    if os.path.exists(log.path):
        with open(log.path) as f:
            for line in f:
                e = json.loads(line)
                if e.get("alert_id"):
                    sent.add(e["alert_id"])


async def main() -> None:
    restore()
    async with aiohttp.ClientSession(headers=internal.headers()) as http:
        ing = web.Application(client_max_size=64 * 1024 * 1024)
        ing["http"] = http
        ing.router.add_get("/ingest/position", ingest_position)
        ing.router.add_post("/ingest", ingest)
        ing.router.add_get("/healthz", lambda r: web.json_response({"ok": True}))
        adm = web.Application()
        adm.router.add_post("/admin/{cmd}", admin)
        for app, host, port in ((ing, "0.0.0.0", 9100), (adm, "127.0.0.1", 9101)):
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            await web.TCPSite(runner, host, port).start()
        out(sentinel="started", positions=positions, known_alerts=len(sent))
        await asyncio.gather(hubble_stream(http, "sbx-sessions", on_session_flow),
                             hubble_stream(http, "sbx-system", on_platform_flow), gc())


if __name__ == "__main__":
    asyncio.run(main())
