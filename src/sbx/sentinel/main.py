"""Sentinel: continuously running detection and response, in its own namespace and on its own node.

  sources   shipped platform evidence (verified on arrival: sequence + hash chain)
            Hubble flows from session pods AND platform pods (kernel datapath, platform can't fake)
  detect    D1-D3, EV (evidence integrity), S1 (gateway under-reporting: Cilium L7/L4 counts vs shipped
            gateway evidence), S2 (platform egress), S6 (leak after containment)
  policy    detection policy (rules, tuning, response actions) from the ConfigMap sentinel-detection,
            hot-reloaded, validated against a compiled-in floor; every load or rejection is recorded
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
from sbx.sentinel import policy as detpol
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
custom = detpol.CustomRules()
policy_rv: str | None = None                                 # ConfigMap resourceVersion last seen
# S1: what the kernel saw vs what the gateway logged, per session
seen_ai: dict[str, list] = {}       # Cilium L7: HTTP requests to the AI gateway (excl. /healthz)
seen_egress: dict[str, list] = {}   # Cilium L4: new TCP connections to the egress proxy (1 connection = 1 request)
logged_ai: dict[str, list] = {}     # shipped gateway evidence: ai_request events
logged_egress: dict[str, list] = {}  # shipped gateway evidence: egress events (excl. connect_close)
ip_to_sid: dict[str, str] = {}
_recent: dict[tuple, float] = {}
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
    """Run what the active detection policy says for this rule (and stage). Monitor mode records the
    alert and the steps it would have run, and does nothing else."""
    pol = engine.pol
    d = pol.decide(a["rule"], a.pop("stage", None))
    if not d["enabled"]:
        return
    if d["mode"] == "monitor":
        a["alert_id"] += "-monitor"
    if a["alert_id"] in sent:
        return
    sent.add(a["alert_id"])
    sid = a.get("session_id")
    a.update(severity=d["severity"], mode=d["mode"], response=d["response"], policy=pol.digest[:19])
    if d["mode"] == "monitor":
        log.write_sync("alert", **a, would_run=d["steps"], sentinel_action=None)
        out(alert=a["rule"], mode="monitor", session=sid, summary=a["summary"], would_run=d["steps"])
        return
    steps, acted = d["steps"], None
    if "quarantine" in steps and sid:
        t0 = time.time()
        created = await asyncio.to_thread(actions.quarantine, sid)     # 1. our own deny policy, first
        contained.setdefault(sid, t0)
        acted = {"action": "sentinel_quarantine", "policy": f"sentinel-q-{sid}", "created": created,
                 "at": t0, "elapsed_s": round(time.time() - t0, 3)}
    if "freeze" in steps:
        created = await asyncio.to_thread(actions.freeze)
        acted = {**(acted or {}), "freeze": {"policy": actions.FREEZE, "created": created}}
    log.write_sync("alert", **a, sentinel_action=acted)
    if "notify-control-plane" in steps:
        # 2. best effort: control plane revokes the token, snapshots evidence, records the alert for users
        cp_result = await cp_post(http, "/internal/alerts", {**a, "contain": "quarantine" in steps})
        log.write_sync("control_plane_notified", alert_id=a["alert_id"], session_id=sid,
                       result={k: (cp_result or {}).get(k) for k in ("seq", "error", "status")})
    out(alert=a["rule"], severity=a["severity"], session=sid, summary=a["summary"], response=d["response"],
        quarantined=bool(acted and "policy" in acted))
    if acted and "policy" in acted and "verify" in steps:
        asyncio.create_task(verify(http, a["alert_id"], sid, acted["at"]))


async def verify(http: aiohttp.ClientSession, alert_id: str, sid: str, at: float) -> None:
    """Containment counts only if the kernel agrees: Hubble shows the pod's traffic DROPPED after our
    quarantine and nothing FORWARDED after the grace period. Polls up to 60 s; with no traffic at all
    the result is recorded as inconclusive rather than claimed."""
    drops, fwd, present = [], [], False
    for _ in range(30):
        await asyncio.sleep(2)
        drops = [d for d in engine.drops_by_session.get(sid, []) if d["time"] >= at]
        fwd = [t for t in forwarded.get(sid, []) if t >= at + grace_s()]
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


def grace_s() -> float:
    return float(engine.pol.param("S6", "grace_s"))


async def run_custom(http: aiohttp.ClientSession, source: str, event: dict, sid: str | None) -> None:
    for c in custom.evaluate(engine.pol, source, event, sid):
        await respond(http, alert(c["rule"], "medium", sid, c["summary"], c["observed"], c["evidence"], key=c["key"]))


async def handle_event(http: aiohttp.ClientSession, name: str, e: dict) -> None:
    if e.get("ts", 0) >= started - REPLAY_GRACE_S:
        await run_custom(http, name.removesuffix(".jsonl"), e, e.get("session_id"))
    if name == "control-plane.jsonl":
        if e.get("action") == "session_contain" and e.get("session_id"):
            contained.setdefault(e["session_id"], e.get("quarantined_at") or e["ts"])
        elif e.get("action") == "fleet_freeze":
            for sid in e.get("frozen_sessions", []):
                contained.setdefault(sid, e["ts"])
        return
    sid = e.get("session_id") or ip_to_sid.get(e.get("pod_ip", ""))
    if sid and e.get("ts", 0) >= started:
        if e.get("action") == "ai_request":
            logged_ai.setdefault(sid, []).append(e["ts"])
        elif e.get("action", "").startswith("egress") and e.get("action") != "egress_connect_close":
            logged_egress.setdefault(sid, []).append(e["ts"])
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
    src_ip = flow.get("IP", {}).get("source")
    if src_ip:
        ip_to_sid[src_ip] = sid
    _count_for_s1(sid, flow)
    await run_custom(http, "hubble-sessions", flow, sid)
    if flow.get("verdict") == "DROPPED":
        pol = await policy(sid)
        for a in engine.on_flow(flow, lambda s: pol):
            await respond(http, a)
    elif sid in contained:
        if flow.get("verdict") == "FORWARDED" and flow.get("traffic_direction") == "EGRESS":
            forwarded.setdefault(sid, []).append(_ts(flow.get("time")))
        a = leak_after_containment(flow, contained[sid], grace_s())
        if a:
            if contained.get(sid, 0) < time.time() - grace_s():     # containment was lifted: ours takes over
                contained[sid] = time.time()
            await respond(http, a)


def _count_for_s1(sid: str, flow: dict) -> None:
    """Independent request counts from the datapath. Hubble may report one packet at several
    observation points (source and destination node), so de-duplicate by source port."""
    ts = _ts(flow.get("time"))
    if ts < started:
        return
    http = (flow.get("l7") or {}).get("http")
    if flow.get("l7", {}).get("type") == "REQUEST" and http:
        if "/healthz" in http.get("url", ""):
            return
        sport = (flow.get("l4", {}).get("TCP") or {}).get("source_port")
        key = ("l7", sid, sport, http.get("method"), http.get("url"), round(ts, 1))
        if key not in _recent:
            _recent[key] = ts
            seen_ai.setdefault(sid, []).append(ts)
        return
    tcp = (flow.get("l4") or {}).get("TCP") or {}
    flags = tcp.get("flags") or {}
    if (flow.get("verdict") == "FORWARDED" and tcp.get("destination_port") == 3128
            and flags.get("SYN") and not flags.get("ACK")):
        key = ("syn", sid, tcp.get("source_port"))
        if ts - _recent.get(key, 0) > 30:
            _recent[key] = ts
            seen_egress.setdefault(sid, []).append(ts)


async def reconcile(http: aiohttp.ClientSession) -> None:
    """S1: if the kernel saw materially more requests from a session than the gateway logged, the
    gateway's account of that session is incomplete (compromised, buggy or tampered): contain it."""
    while True:
        p = engine.pol.rules["S1"]["params"]
        await asyncio.sleep(p["interval_s"])
        if not engine.pol.enabled("S1"):
            continue
        horizon = time.time() - p["horizon_s"]
        for channel, seen, logged in (("AI", seen_ai, logged_ai), ("egress", seen_egress, logged_egress)):
            for sid in list(seen):
                n_seen = sum(1 for t in seen[sid] if t <= horizon)
                n_logged = sum(1 for t in logged.get(sid, []) if t <= horizon)
                deficit = n_seen - n_logged
                if deficit >= p["min_deficit"] and deficit >= p["min_ratio"] * n_seen:
                    await respond(http, alert(
                        "S1", "high", sid, f"gateway evidence incomplete ({channel}): the datapath saw {n_seen} "
                        f"requests, the gateway logged {n_logged}",
                        {"action": "evidence_reconciliation", "channel": channel, "seen": n_seen, "logged": n_logged},
                        [{"source": "hubble"}, {"source": "shipped-gateway-evidence"}], key=channel))
        cutoff = time.time() - 300
        for k in [k for k, v in _recent.items() if v < cutoff]:
            _recent.pop(k, None)


async def on_platform_flow(http: aiohttp.ClientSession, flow: dict) -> None:
    a = platform_flow_alert(flow, engine.pol.param("S2", "world_allowlist") or {})
    if a:
        await respond(http, a)
    await run_custom(http, "hubble-platform", flow, None)


# ---------------------------------------------------------------------------------- detection policy
async def load_policy(http: aiohttp.ClientSession, force: bool = False) -> dict:
    """Read ConfigMap sentinel-detection; on a change validate it and swap it in atomically. A policy
    that fails validation is recorded and alerted on, and the last good one stays active."""
    global policy_rv
    got = await asyncio.to_thread(actions.read_policy)
    if got is None:
        return {"loaded": False, "reason": "ConfigMap sentinel-detection not found", "active": engine.pol.digest}
    rv, text = got
    if rv == policy_rv and not force:
        return {"loaded": False, "reason": "unchanged", "active": engine.pol.digest}
    policy_rv = rv
    try:
        new = detpol.load(text, source=f"configmap@{rv}")
    except detpol.PolicyError as e:
        bad = "sha256:" + __import__("hashlib").sha256(text.encode()).hexdigest()
        log.write_sync("detection_policy_rejected", digest=bad, errors=e.errors, kept=engine.pol.digest)
        await respond(http, alert("POL", "high", None, f"detection policy {bad[:19]} rejected: {e.errors[0]}",
                                  {"action": "detection_policy_rejected", "errors": e.errors[:10]}, [],
                                  key=f"{bad}|{rv}"))    # every apply re-alerts (ids are deduped across restarts)
        return {"loaded": False, "errors": e.errors, "active": engine.pol.digest}
    if new.digest != engine.pol.digest:
        engine.pol = new
        s = new.summary()
        log.write_sync("detection_policy_loaded", digest=new.digest, name=new.name, version=new.version,
                       disabled=[k for k, v in {**s["rules"], **s["custom"]}.items() if not v["enabled"]],
                       monitor=[k for k, v in {**s["rules"], **s["custom"]}.items() if v["mode"] == "monitor"],
                       custom=sorted(s["custom"]))
        out(policy="loaded", digest=new.digest, version=new.version)
    return {"loaded": True, "active": engine.pol.digest}


async def policy_watch(http: aiohttp.ClientSession) -> None:
    while True:
        try:
            await load_policy(http)
        except Exception as e:  # noqa: BLE001 - API server blip: keep the active policy
            out(policy_error=str(e)[:200])
        await asyncio.sleep(10)


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
    if cmd == "policy":
        return web.json_response({**engine.pol.summary(), "text": engine.pol.text})
    if cmd == "reload":
        return web.json_response(await load_policy(request.app["http"], force=True))
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
        adm["http"] = http
        adm.router.add_post("/admin/{cmd}", admin)
        for app, host, port in ((ing, "0.0.0.0", 9100), (adm, "127.0.0.1", 9101)):
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            await web.TCPSite(runner, host, port).start()
        try:
            await load_policy(http)
        except Exception as e:  # noqa: BLE001 - start on the built-in defaults; policy_watch retries
            out(policy_error=str(e)[:200])
        out(sentinel="started", positions=positions, known_alerts=len(sent), policy=engine.pol.digest)
        await asyncio.gather(policy_watch(http), hubble_stream(http, "sbx-sessions", on_session_flow),
                             hubble_stream(http, "sbx-system", on_platform_flow), gc(), reconcile(http))


if __name__ == "__main__":
    asyncio.run(main())
