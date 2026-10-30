"""Sentinel: continuously running detection and response, in its own namespace and on its own node.

What it trusts:
  - Hubble flows from session pods AND platform pods: produced by Cilium's eBPF datapath, so no pod
    (platform or sandbox) can fake them. Treated as ground truth for where traffic went.
  - Shipped platform evidence (gateway.jsonl, control-plane.jsonl): claims made by the platform.
    Verified on arrival (sequence continuity + hash chain) and copied to the sentinel's own volume,
    so a gap or an edit raises EV; it may still be incomplete, which S1 checks.
  - The control plane only for per-session policy lookups (cached; built-in defaults if it is down).

What it does:
  detect    D1-D3, EV (evidence integrity), S1 (gateway completeness: Cilium L7/L4 request counts vs
            shipped gateway evidence), S2 (platform pod egress), S6 (traffic after containment),
            plus the detection policy's custom match rules
  policy    detection policy (rules, tuning, response actions) from the ConfigMap sentinel-detection,
            hot-reloaded, validated against a compiled-in floor; every load or rejection is recorded
  respond   its OWN quarantine/freeze Cilium deny policies (works with the control plane down),
            then best-effort token revocation + snapshot via the control plane
  record    its own hash-chained alert/action log on its own volume ($SENTINEL_DATA/sentinel.jsonl),
            a verified copy of shipped evidence ($SENTINEL_DATA/copy/), and one JSON line per event on stdout

Ports: 9100 ingest (from the evidence shipper only, keyed), 127.0.0.1:9101 admin (reached with
`kubectl exec` into this pod; see ctl.py).
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
from sbx.common.session_policy import ControlPlane
from sbx.sentinel import actions
from sbx.sentinel import detection_policy as detpol
from sbx.sentinel.rules import Engine, alert, leak_after_containment, parse_time, platform_flow_alert

DATA = os.environ.get("SENTINEL_DATA", "/data")
HUBBLE_SERVER = os.environ.get("HUBBLE_SERVER", "hubble-relay.kube-system.svc:80")
INGEST_KEY = os.environ.get("SENTINEL_INGEST_KEY", "")
# Session policy used when the control plane can't be asked and nothing is cached for the session.
DEFAULT_POLICY = {"state": "running", "policy": {"deny_burst": {"count": 5, "window_s": 60}}}
# Shipped events this much older than our start are replayed history: verified and copied, not alerted on.
REPLAY_GRACE_S = 60
BOOT_POLICY = os.environ.get("SENTINEL_BOOT_POLICY", "/app/config/sentinel/detection.yaml")

control_plane = ControlPlane(ttl=2.0)
engine = Engine()
log = EvidenceLog("sentinel", DATA)                         # alerts, actions, verifications
started = time.time()
raised_alert_ids: set[str] = set()                           # dedupe: every alert id ever written (survives restarts)
contained: dict[str, float] = {}                             # sid -> time containment took effect
forwarded: dict[str, list] = {}                              # sid -> times Cilium forwarded egress after containment
custom_rules = detpol.CustomRules()
policy_resource_version: str | None = None                   # ConfigMap resourceVersion last seen
# S1 (gateway completeness): what the kernel saw vs what the gateway logged, per session
seen_ai: dict[str, list] = {}       # Cilium L7: HTTP requests to the AI gateway (excl. /healthz)
seen_egress: dict[str, list] = {}   # Cilium L4: new TCP connections to the egress proxy (1 connection = 1 request)
logged_ai: dict[str, list] = {}     # shipped gateway evidence: ai_request events
logged_egress: dict[str, list] = {}  # shipped gateway evidence: egress events (excl. connect_close)
ip_to_sid: dict[str, str] = {}
datapath_dedup: dict[tuple, float] = {}                      # S1 counting: flow key -> last time counted
session_policies: dict[str, dict] = {}                       # sid -> last policy the control plane returned
positions: dict[str, int] = {}                              # file -> last verified seq
chain_head: dict[str, str] = {}                             # file -> hash of the last verified record
broken_files: set[str] = set()                              # files with a gap or chain break (alerted once)


def emit(**kw) -> None:
    """One JSON line on stdout (the pod log); the hash-chained log is the record of truth."""
    print(json.dumps({"ts": time.time(), **kw}), flush=True)


# ------------------------------------------------------------------------------------------ helpers
async def session_policy(sid: str) -> dict:
    """The session's policy (state + deny burst) from the control plane, falling back to the last
    answer we cached, then to DEFAULT_POLICY: detection never stops because the control plane is down."""
    try:
        status, body = await control_plane.policy(sid)
        if status == 200:
            session_policies[sid] = body
            return body
    except Exception:  # noqa: BLE001 - control plane down: keep detecting with defaults
        pass
    return session_policies.get(sid, DEFAULT_POLICY)


async def post_to_control_plane(http: aiohttp.ClientSession, path: str, body: dict) -> dict | None:
    """Best-effort POST to the control plane's internal API; failures come back as a dict, never raise."""
    try:
        async with http.post(internal.CONTROL_PLANE_URL + path, json=body,
                             timeout=aiohttp.ClientTimeout(total=30)) as r:
            return await r.json() if r.status == 200 else {"status": r.status}
    except Exception as e:  # noqa: BLE001
        return {"error": f"control plane unreachable: {type(e).__name__}"}


# ---------------------------------------------------------------------------------------- response
async def respond(http: aiohttp.ClientSession, new_alert: dict) -> None:
    """Run what the active detection policy says for this rule (and stage). Monitor mode records the
    alert and the steps it would have run, and does nothing else. Each alert id is handled once."""
    pol = engine.pol
    decision = pol.decide(new_alert["rule"], new_alert.pop("stage", None))
    if not decision["enabled"]:
        return
    if decision["mode"] == "monitor":
        new_alert["alert_id"] += "-monitor"
    if new_alert["alert_id"] in raised_alert_ids:
        return
    raised_alert_ids.add(new_alert["alert_id"])
    sid = new_alert.get("session_id")
    new_alert.update(severity=decision["severity"], mode=decision["mode"], response=decision["response"],
                     policy=pol.digest[:19])
    if decision["mode"] == "monitor":
        log.write_sync("alert", **new_alert, would_run=decision["steps"], sentinel_action=None)
        emit(alert=new_alert["rule"], mode="monitor", session=sid, summary=new_alert["summary"],
             would_run=decision["steps"])
        return
    steps, acted = decision["steps"], None
    if "quarantine" in steps and sid:
        t0 = time.time()
        created = await asyncio.to_thread(actions.quarantine, sid)     # 1. our own deny policy, first
        contained.setdefault(sid, t0)
        acted = {"action": "sentinel_quarantine", "policy": f"sentinel-q-{sid}", "created": created,
                 "at": t0, "elapsed_s": round(time.time() - t0, 3)}
    if "freeze" in steps:
        created = await asyncio.to_thread(actions.freeze)
        acted = {**(acted or {}), "freeze": {"policy": actions.FREEZE, "created": created}}
    log.write_sync("alert", **new_alert, sentinel_action=acted)
    if "notify-control-plane" in steps:
        # 2. best effort: control plane revokes the token, snapshots evidence, records the alert for users
        cp_result = await post_to_control_plane(http, "/internal/alerts",
                                                {**new_alert, "contain": "quarantine" in steps})
        log.write_sync("control_plane_notified", alert_id=new_alert["alert_id"], session_id=sid,
                       result={k: (cp_result or {}).get(k) for k in ("seq", "error", "status")})
    emit(alert=new_alert["rule"], severity=new_alert["severity"], session=sid, summary=new_alert["summary"],
         response=decision["response"], quarantined=bool(acted and "policy" in acted))
    if acted and "policy" in acted and "verify" in steps:
        asyncio.create_task(verify(http, new_alert["alert_id"], sid, acted["at"]))


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
    await post_to_control_plane(http, "/internal/alerts/verification",
                                {"alert_id": alert_id, "session_id": sid, "verified": ok, "sources": sources})
    emit(verification=sid, verified=ok, **sources)


# ------------------------------------------------------------------------------- ingest (evidence)
async def ingest_position(request: web.Request) -> web.Response:
    """GET /ingest/position: last verified seq per file, so the shipper resumes from there."""
    if request.headers.get("X-Sbx-Ingest") != INGEST_KEY or not INGEST_KEY:
        raise web.HTTPUnauthorized()
    return web.json_response(positions)


async def ingest(request: web.Request) -> web.Response:
    """POST /ingest {file, events}: verify each new record (sequence continuity, hash chain), keep a
    copy, then run detection on it. The first gap or break per file raises one EV alert."""
    if request.headers.get("X-Sbx-Ingest") != INGEST_KEY or not INGEST_KEY:
        raise web.HTTPUnauthorized()
    body = await request.json()
    name = body["file"]
    if name not in ("gateway.jsonl", "control-plane.jsonl"):
        raise web.HTTPBadRequest()
    http = request.app["http"]
    with open(os.path.join(DATA, "copy", name), "a") as copy:
        for event in body["events"]:
            last = positions.get(name, 0)
            if event["seq"] <= last:
                continue
            if event["seq"] != last + 1 and name not in broken_files:     # a hole: something was never shipped
                broken_files.add(name)
                await respond(http, alert("EV", None, f"{name}: sequence gap {last} -> {event['seq']}",
                                          {"file": name}, [{"source": "shipper", "seq": event["seq"]}]))
            claimed = event.get("hash")
            unhashed = {k: v for k, v in event.items() if k != "hash"}
            prev = chain_head.get(name, GENESIS)
            if (unhashed.get("prev_hash") != prev or _digest(prev, unhashed) != claimed) and name not in broken_files:
                broken_files.add(name)
                await respond(http, alert("EV", None, f"{name}: hash chain broken at seq {event['seq']}",
                                          {"file": name}, [{"source": "shipper", "seq": event["seq"]}]))
            copy.write(json.dumps(event, sort_keys=True) + "\n")
            positions[name], chain_head[name] = event["seq"], claimed
            await handle_event(http, name, event)
    return web.json_response({"ok": True, "position": positions.get(name, 0)})


def grace_s() -> float:
    """S6 grace period: traffic this soon after containment is not yet a leak."""
    return float(engine.pol.param("S6", "grace_s"))


async def run_custom_rules(http: aiohttp.ClientSession, source: str, event: dict, sid: str | None) -> None:
    """Evaluate the detection policy's custom match rules for one event from `source`."""
    for match in custom_rules.evaluate(engine.pol, source, event, sid):
        await respond(http, alert(match["rule"], sid, match["summary"], match["observed"],
                                  match["evidence"], key=match["key"]))


async def handle_event(http: aiohttp.ClientSession, name: str, event: dict) -> None:
    """Detection on one verified shipped record: custom rules, containment bookkeeping (control
    plane), S1 logged-request counts and the built-in gateway rules (gateway)."""
    if event.get("ts", 0) >= started - REPLAY_GRACE_S:
        await run_custom_rules(http, name.removesuffix(".jsonl"), event, event.get("session_id"))
    if name == "control-plane.jsonl":
        if event.get("action") == "session_contain" and event.get("session_id"):
            contained.setdefault(event["session_id"], event.get("quarantined_at") or event["ts"])
        elif event.get("action") == "fleet_freeze":
            for sid in event.get("frozen_sessions", []):
                contained.setdefault(sid, event["ts"])
        return
    sid = event.get("session_id") or ip_to_sid.get(event.get("pod_ip", ""))
    if sid and event.get("ts", 0) >= started:
        if event.get("action") == "ai_request":
            logged_ai.setdefault(sid, []).append(event["ts"])
        elif event.get("action", "").startswith("egress") and event.get("action") != "egress_connect_close":
            logged_egress.setdefault(sid, []).append(event["ts"])
    sid = event.get("session_id")
    if not sid or event.get("ts", 0) < started - REPLAY_GRACE_S:
        return
    for found in engine.on_gateway(event, await session_policy(sid)):
        await respond(http, found)


# --------------------------------------------------------------------------------- Hubble streams
async def hubble_stream(http: aiohttp.ClientSession, namespace: str, handler) -> None:
    """Follow `hubble observe` for flows from `namespace` forever (reconnecting), one handler call per flow."""
    while True:
        proc = await asyncio.create_subprocess_exec(
            "hubble", "observe", "--server", HUBBLE_SERVER, "--from-namespace", namespace, "--follow", "-o", "json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        emit(hubble="connected", namespace=namespace)
        assert proc.stdout
        async for raw in proc.stdout:
            try:
                flow = json.loads(raw).get("flow", {})
            except ValueError:
                continue
            await handler(http, flow)
        emit(hubble="disconnected", namespace=namespace, rc=await proc.wait())
        await asyncio.sleep(3)


async def on_session_flow(http: aiohttp.ClientSession, flow: dict) -> None:
    """A flow from a sandbox pod: S1 counting, custom rules, D2 (drops) and S6 (traffic after containment)."""
    sid = next((l.split("=", 1)[1] for l in flow.get("source", {}).get("labels", [])
                if l.startswith("k8s:sbx/session=")), None)
    if not sid:
        return
    src_ip = flow.get("IP", {}).get("source")
    if src_ip:
        ip_to_sid[src_ip] = sid
    _count_datapath_requests(sid, flow)
    await run_custom_rules(http, "hubble-sessions", flow, sid)
    if flow.get("verdict") == "DROPPED":
        pol = await session_policy(sid)
        for found in engine.on_flow(flow, lambda s: pol):
            await respond(http, found)
    elif sid in contained:
        if flow.get("verdict") == "FORWARDED" and flow.get("traffic_direction") == "EGRESS":
            forwarded.setdefault(sid, []).append(parse_time(flow.get("time")))
        leak = leak_after_containment(flow, contained[sid], grace_s())
        if leak:
            if contained.get(sid, 0) < time.time() - grace_s():     # containment was lifted: ours takes over
                contained[sid] = time.time()
            await respond(http, leak)


def _count_datapath_requests(sid: str, flow: dict) -> None:
    """S1: independent request counts from the datapath. Hubble may report one packet at several
    observation points (source and destination node), so de-duplicate by source port."""
    ts = parse_time(flow.get("time"))
    if ts < started:
        return
    http = (flow.get("l7") or {}).get("http")
    if flow.get("l7", {}).get("type") == "REQUEST" and http:
        if "/healthz" in http.get("url", ""):
            return
        sport = (flow.get("l4", {}).get("TCP") or {}).get("source_port")
        key = ("l7", sid, sport, http.get("method"), http.get("url"), round(ts, 1))
        if key not in datapath_dedup:
            datapath_dedup[key] = ts
            seen_ai.setdefault(sid, []).append(ts)
        return
    tcp = (flow.get("l4") or {}).get("TCP") or {}
    flags = tcp.get("flags") or {}
    if (flow.get("verdict") == "FORWARDED" and tcp.get("destination_port") == 3128
            and flags.get("SYN") and not flags.get("ACK")):
        key = ("syn", sid, tcp.get("source_port"))
        if ts - datapath_dedup.get(key, 0) > 30:
            datapath_dedup[key] = ts
            seen_egress.setdefault(sid, []).append(ts)


async def reconcile(http: aiohttp.ClientSession) -> None:
    """S1: if the kernel saw materially more requests from a session than the gateway logged, the
    gateway's account of that session is incomplete (compromised, buggy or tampered): contain it.
    Only requests older than the horizon are compared, so shipping lag is not a deficit."""
    while True:
        params = engine.pol.rules["S1"]["params"]
        await asyncio.sleep(params["interval_s"])
        if not engine.pol.enabled("S1"):
            continue
        horizon = time.time() - params["horizon_s"]
        for channel, seen, logged in (("AI", seen_ai, logged_ai), ("egress", seen_egress, logged_egress)):
            for sid in list(seen):
                n_seen = sum(1 for t in seen[sid] if t <= horizon)
                n_logged = sum(1 for t in logged.get(sid, []) if t <= horizon)
                deficit = n_seen - n_logged
                if deficit >= params["min_deficit"] and deficit >= params["min_ratio"] * n_seen:
                    await respond(http, alert(
                        "S1", sid, f"gateway evidence incomplete ({channel}): the datapath saw {n_seen} "
                        f"requests, the gateway logged {n_logged}",
                        {"action": "evidence_reconciliation", "channel": channel, "seen": n_seen, "logged": n_logged},
                        [{"source": "hubble"}, {"source": "shipped-gateway-evidence"}], key=channel))
        cutoff = time.time() - 300
        for k in [k for k, v in datapath_dedup.items() if v < cutoff]:
            datapath_dedup.pop(k, None)


async def on_platform_flow(http: aiohttp.ClientSession, flow: dict) -> None:
    """A flow from a platform pod (sbx-system): S2 and custom rules on platform flows."""
    found = platform_flow_alert(flow, engine.pol.param("S2", "world_allowlist") or {})
    if found:
        await respond(http, found)
    await run_custom_rules(http, "hubble-platform", flow, None)


# ---------------------------------------------------------------------------------- detection policy
async def load_policy(http: aiohttp.ClientSession, force: bool = False) -> dict:
    """Read ConfigMap sentinel-detection; on a change validate it and swap it in atomically. A policy
    that fails validation is recorded and alerted on, and the last good one stays active."""
    global policy_resource_version
    got = await asyncio.to_thread(actions.read_policy)
    if got is None:
        return {"loaded": False, "reason": "ConfigMap sentinel-detection not found", "active": engine.pol.digest}
    rv, text = got
    if rv == policy_resource_version and not force:
        return {"loaded": False, "reason": "unchanged", "active": engine.pol.digest}
    policy_resource_version = rv
    try:
        new = detpol.load(text, source=f"configmap@{rv}")
    except detpol.PolicyError as e:
        rejected = "sha256:" + __import__("hashlib").sha256(text.encode()).hexdigest()
        log.write_sync("detection_policy_rejected", digest=rejected, errors=e.errors, kept=engine.pol.digest)
        await respond(http, alert("POL", None, f"detection policy {rejected[:19]} rejected: {e.errors[0]}",
                                  {"action": "detection_policy_rejected", "errors": e.errors[:10]}, [],
                                  key=f"{rejected}|{rv}"))    # every apply re-alerts (ids are deduped across restarts)
        return {"loaded": False, "errors": e.errors, "active": engine.pol.digest}
    if new.digest != engine.pol.digest:
        engine.pol = new
        summary = new.summary()
        every_rule = {**summary["rules"], **summary["custom"]}
        log.write_sync("detection_policy_loaded", digest=new.digest, name=new.name, version=new.version,
                       disabled=[k for k, v in every_rule.items() if not v["enabled"]],
                       monitor=[k for k, v in every_rule.items() if v["mode"] == "monitor"],
                       custom=sorted(summary["custom"]))
        emit(policy="loaded", digest=new.digest, version=new.version)
    return {"loaded": True, "active": engine.pol.digest}


def boot_policy() -> None:
    """The sentinel never runs without a detection policy, and never on values hidden in code: it
    starts on the ConfigMap if that exists and is valid, otherwise on the same policy file baked into
    the image (config/sentinel/detection.yaml). If neither loads it exits, so the failure is loud
    (CrashLoopBackOff) rather than a sentinel that is running but blind."""
    global policy_resource_version
    try:
        got = actions.read_policy()
    except Exception as e:  # noqa: BLE001 - API server not reachable yet: fall back to the image copy
        got = None
        emit(policy_error=f"boot: cannot read ConfigMap: {str(e)[:150]}")
    if got:
        rv, text = got
        try:
            engine.pol = detpol.load(text, source=f"configmap@{rv}")
            policy_resource_version = rv
        except detpol.PolicyError as e:      # policy_watch re-reads it and raises POL under the image copy
            emit(policy_error=f"boot: ConfigMap policy rejected: {e.errors[0]}")
    if engine.pol is None:
        try:
            with open(BOOT_POLICY) as f:
                engine.pol = detpol.load(f.read(), source=f"image:{BOOT_POLICY}")
        except (OSError, detpol.PolicyError) as e:
            emit(fatal=f"no valid detection policy (ConfigMap or {BOOT_POLICY}): {e}")
            raise SystemExit(1)
    log.write_sync("detection_policy_loaded", digest=engine.pol.digest, name=engine.pol.name,
                   version=engine.pol.version, source=engine.pol.source, at="boot")


async def policy_watch(http: aiohttp.ClientSession) -> None:
    """Poll the detection-policy ConfigMap every 10 s."""
    while True:
        try:
            await load_policy(http)
        except Exception as e:  # noqa: BLE001 - API server blip: keep the active policy
            emit(policy_error=str(e)[:200])
        await asyncio.sleep(10)


# ------------------------------------------------------------------------------ housekeeping, admin
async def release_stale_quarantines() -> None:
    """Remove sentinel quarantines whose session pod no longer exists."""
    while True:
        await asyncio.sleep(30)
        try:
            stale = await asyncio.to_thread(lambda: actions.quarantined_sessions() - actions.live_sessions())
            for sid in stale:
                await asyncio.to_thread(actions.release, sid)
                log.write_sync("quarantine_released", session_id=sid, reason="pod gone")
        except Exception as e:  # noqa: BLE001
            emit(gc_error=str(e)[:200])


async def admin(request: web.Request) -> web.Response:
    """POST /admin/{cmd} on 127.0.0.1 only (ctl.py): freeze, unfreeze, release, alerts, policy, reload, status.
    Reaching it needs `kubectl exec` into this pod, which is the authorisation."""
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
        return web.json_response({"positions": positions, "broken": sorted(broken_files), "contained": contained,
                                  "quarantined": sorted(await asyncio.to_thread(actions.quarantined_sessions))})
    raise web.HTTPNotFound()


def restore() -> None:
    """Rebuild positions/chain heads and known alert ids from our own files after a restart."""
    os.makedirs(os.path.join(DATA, "copy"), exist_ok=True)
    for name in ("gateway.jsonl", "control-plane.jsonl"):
        path = os.path.join(DATA, "copy", name)
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    record = json.loads(line)
                    positions[name], chain_head[name] = record["seq"], record["hash"]
    if os.path.exists(log.path):
        with open(log.path) as f:
            for line in f:
                record = json.loads(line)
                if record.get("alert_id"):
                    raised_alert_ids.add(record["alert_id"])


async def main() -> None:
    restore()
    boot_policy()
    async with aiohttp.ClientSession(headers=internal.headers()) as http:
        ingest_app = web.Application(client_max_size=64 * 1024 * 1024)
        ingest_app["http"] = http
        ingest_app.router.add_get("/ingest/position", ingest_position)
        ingest_app.router.add_post("/ingest", ingest)
        ingest_app.router.add_get("/healthz", lambda r: web.json_response({"ok": True}))
        admin_app = web.Application()
        admin_app["http"] = http
        admin_app.router.add_post("/admin/{cmd}", admin)
        for app, host, port in ((ingest_app, "0.0.0.0", 9100), (admin_app, "127.0.0.1", 9101)):
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            await web.TCPSite(runner, host, port).start()
        emit(sentinel="started", positions=positions, known_alerts=len(raised_alert_ids), policy=engine.pol.digest)
        await asyncio.gather(policy_watch(http), hubble_stream(http, "sbx-sessions", on_session_flow),
                             hubble_stream(http, "sbx-system", on_platform_flow), release_stale_quarantines(),
                             reconcile(http))


if __name__ == "__main__":
    asyncio.run(main())
