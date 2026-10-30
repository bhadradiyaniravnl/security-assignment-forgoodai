"""Control plane HTTP API (FastAPI); thin routing over sessions.py and specs.py.

Public (sbxctl, via NodePort bound to 127.0.0.1): runs, sessions, logs, messages, stop, destroy,
  diff, contain, specs, alerts, and the fleet freeze (security admins only, checked in sessions.py).
  Prototype identity is the X-User header, trusted as-is; production replaces it with OIDC.
  `system:` identities are reserved for in-process callers and refused here.
Internal (X-Sbx-Internal, per-component keys): token validation (gateway), compiled policy
(gateway, credproxy, sentinel), alerts (sentinel). Each endpoint names the components it accepts.
There is deliberately no internal way to create a session: every session goes through /runs,
i.e. the spec registry and its baseline.

Logs returned to users are pod stdout (untrusted); sbxctl escapes them before display.
"""
from __future__ import annotations

import json
import os
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from sbx.common import internal
from sbx.control_plane import k8s, sessions, specs
from sbx.control_plane.store import Store

app = FastAPI(title="sbx control plane")
store = Store()


@app.on_event("startup")
def _startup() -> None:
    """Registers the shipped specs through the baseline gate, then starts the reconciler."""
    for result in specs.bootstrap(store):
        action = "spec_rejected" if "rejected" in result else "spec_registered"
        sessions.evidence.write_sync(action, by="system:bootstrap",
                                     **{k: v for k, v in result.items() if k != "unchanged"})
    sessions.reconcile_forever(store)


def scope(*allowed: str):
    """Dependency: internal endpoint callable only by the listed components."""
    def dep(x_sbx_internal: str | None = Header(default=None)) -> str:
        caller = internal.caller(x_sbx_internal)
        if caller is None:
            raise HTTPException(401, "internal auth required")
        if caller not in allowed:
            raise HTTPException(403, f"{caller} may not call this endpoint")
        return caller
    return dep


def require_user(x_user: str | None = Header(default=None)) -> str:
    """Dependency: the calling user (prototype: the X-User header)."""
    if not x_user:
        raise HTTPException(401, "X-User required")
    if x_user.startswith("system:"):                      # reserved for in-process callers (bootstrap)
        raise HTTPException(400, "reserved identity")
    return x_user


def _call_session_op(fn, *args):
    """Calls a sessions.* operation with the store, mapping SessionError to its HTTP status."""
    try:
        return fn(store, *args)
    except sessions.SessionError as e:
        raise HTTPException(e.status, str(e)) from None


@app.post("/specs")
async def register_spec(request: Request, user: str = Depends(require_user)) -> dict:
    """Spec authors register a new version (raw YAML body). Rejected specs never reach the registry."""
    raw = await request.body()
    try:
        result = specs.register(store, raw, user)
    except PermissionError as e:
        sessions.evidence.write_sync("spec_rejected", by=user, digest=specs.digest_of(raw), reasons=[str(e)])
        raise HTTPException(403, str(e)) from None
    except specs.SpecError as e:
        sessions.evidence.write_sync("spec_rejected", by=user, digest=specs.digest_of(raw), reasons=e.details or [str(e)])
        raise HTTPException(422, {"error": str(e), "reasons": e.details or [str(e)]}) from None
    if not result.get("unchanged"):
        sessions.evidence.write_sync("spec_registered", by=user, **result)
    return result


@app.post("/specs/approvals")
async def approve_spec(request: Request, user: str = Depends(require_user)) -> dict:
    """Security approvers approve exact spec bytes; authors then register them (two-person rule)."""
    raw = await request.body()
    try:
        result = specs.approve(store, raw, user)
    except PermissionError as e:
        raise HTTPException(403, str(e)) from None
    except specs.SpecError as e:
        raise HTTPException(422, {"error": str(e), "reasons": e.details or [str(e)]}) from None
    sessions.evidence.write_sync("spec_approved", **result)
    return result


@app.get("/specs")
def list_specs(user: str = Depends(require_user)) -> list:
    return store.list_specs()


class RunIn(BaseModel):
    spec: str
    params: dict


@app.post("/runs")
def create_run(r: RunIn, user: str = Depends(require_user)) -> dict:
    return _call_session_op(sessions.run, user, r.spec, r.params)


@app.get("/sessions")
def list_sessions(user: str = Depends(require_user)) -> list:
    return [_public_view(s) for s in store.list() if s["user"] == user]


@app.get("/sessions/{sid}")
def get_session(sid: str, user: str = Depends(require_user)) -> dict:
    s = store.get(sid)
    if s is None or s["user"] != user:
        raise HTTPException(404, "no such session")
    return {**_public_view(s), "pod_status": k8s.pod_status(sid)}


@app.get("/sessions/{sid}/logs")
def session_logs(sid: str, follow: bool = False, tail: int | None = None, user: str = Depends(require_user)):
    s = store.get(sid)
    if s is None or s["user"] != user:
        raise HTTPException(404, "no such session")
    if k8s.pod_status(sid) is None:
        raise HTTPException(410, "pod is gone")
    resp = k8s.logs(sid, follow=follow, tail=tail)
    return StreamingResponse(resp.stream(1024), media_type="text/plain")


class MessageIn(BaseModel):
    text: str


@app.post("/sessions/{sid}/messages")
def send_message(sid: str, m: MessageIn, user: str = Depends(require_user)) -> dict:
    return _call_session_op(sessions.send_message, sid, user, m.text)


@app.post("/sessions/{sid}/stop")
def stop_session(sid: str, user: str = Depends(require_user)) -> dict:
    return _call_session_op(sessions.stop, sid, user)


@app.delete("/sessions/{sid}")
def destroy_session(sid: str, user: str = Depends(require_user)) -> dict:
    return _call_session_op(sessions.destroy, sid, user)


@app.post("/sessions/{sid}/contain")
def contain_session(sid: str, user: str = Depends(require_user)) -> dict:
    s = store.get(sid)
    if s is None or s["user"] != user:
        raise HTTPException(404, "no such session")
    return _call_session_op(sessions.contain, sid, f"user:{user}", None, "manual")


class FreezeIn(BaseModel):
    reason: str = "manual"


@app.post("/admin/freeze")
def freeze(f: FreezeIn, user: str = Depends(require_user)) -> dict:
    return _call_session_op(sessions.freeze, user, f.reason)


@app.post("/admin/unfreeze")
def unfreeze(user: str = Depends(require_user)) -> dict:
    return _call_session_op(sessions.unfreeze, user)


@app.get("/alerts")
def list_alerts(user: str = Depends(require_user)) -> list:
    """Alerts on the caller's sessions, with containment verifications attached."""
    rows = _read_alerts()
    verifications = {r["alert_id"]: r for r in rows if r.get("action") == "containment_verification"}
    containments = {r["alert_id"]: r["result"] for r in rows if r.get("action") == "containment"}
    out = []
    for row in rows:
        if row.get("action") == "alert" and row.get("user") == user:
            out.append({**row, "containment": containments.get(row["alert_id"]),
                        "verification": verifications.get(row["alert_id"])})
    return out


class AlertIn(BaseModel):
    alert_id: str
    rule: str
    severity: str
    session_id: str | None = None
    summary: str
    observed: dict = {}
    evidence: list = []
    contain: bool = False


@app.post("/internal/alerts", dependencies=[Depends(scope("sentinel"))])
def raise_alert(alert: AlertIn) -> dict:
    """Alert sink for the sentinel. Joins user/spec from the registry so every alert links
    initiating user -> session -> observed action. The alert is recorded at detection time,
    then (if requested) the session is contained and a linked containment record is written."""
    session = store.get(alert.session_id) if alert.session_id else None
    who = {"user": session["user"], "spec": session["spec_name"], "spec_digest": session["spec_digest"],
           "pod": session["pod_name"], "pod_ip": session["pod_ip"]} if session else {}
    rec = sessions.alerts.write_sync("alert", **alert.model_dump(), **who)
    containment = None
    if alert.contain and session and session["state"] in ("running", "creating", "stopping"):
        try:
            containment = sessions.contain(store, alert.session_id, "sentinel", alert.alert_id,
                                           f"{alert.rule}: {alert.summary}")
        except sessions.SessionError as e:
            containment = {"error": str(e)}
        sessions.alerts.write_sync("containment", alert_id=alert.alert_id, session_id=alert.session_id,
                                   result=containment)
    return {**rec, "containment": containment}


class VerificationIn(BaseModel):
    alert_id: str
    session_id: str
    verified: bool
    sources: dict


@app.post("/internal/alerts/verification", dependencies=[Depends(scope("sentinel"))])
def verify_alert(v: VerificationIn) -> dict:
    """The sentinel's independent check that a containment actually took effect."""
    return sessions.alerts.write_sync("containment_verification", **v.model_dump())


@app.get("/internal/alerts", dependencies=[Depends(scope("sentinel"))])
def internal_alerts() -> list:
    return _read_alerts()


def _read_alerts() -> list:
    path = sessions.alerts.path
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


@app.get("/sessions/{sid}/diff", response_class=PlainTextResponse)
def session_diff(sid: str, user: str = Depends(require_user)) -> str:
    return _call_session_op(sessions.diff, sid, user)


def _public_view(s: dict) -> dict:
    """Session fields users may see: never the token hash, policy or canaries."""
    return {k: s.get(k) for k in ("session_id", "user", "spec_name", "spec_digest", "params", "pod_name",
                                  "pod_ip", "state", "detail", "turns", "scan", "created_at", "last_activity", "state_changed_at", "ended_at")}


class ValidateIn(BaseModel):
    token: str
    ip: str


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.post("/internal/validate", dependencies=[Depends(scope("gateway"))])
def validate(v: ValidateIn) -> dict:
    """Gateway check on every model/egress call: token known, bound to the caller's pod IP, session running."""
    s = store.by_token(v.token)
    if s is None:
        raise HTTPException(401, "unknown token")
    if s["pod_ip"] != v.ip:
        raise HTTPException(403, "token not bound to this source ip")
    if s["state"] != "running":
        raise HTTPException(403, f"session {s['state']}")
    now = time.time()
    if now - (s.get("last_activity") or 0) > 10:      # every model/egress call is activity (idle reaper)
        store.update(s["session_id"], last_activity=now)
    return _session_context(s)


@app.get("/internal/policy/{session_id}", dependencies=[Depends(scope("gateway", "credproxy", "sentinel"))])
def policy(session_id: str) -> dict:
    """Compiled policy and canaries for one session (enforcement points and the sentinel only)."""
    s = store.get(session_id)
    if s is None:
        raise HTTPException(404, "no such session")
    return {**_session_context(s), "policy": s["policy"], "canaries": s["canaries"]}


def _session_context(s: dict) -> dict:
    return {k: s[k] for k in ("session_id", "user", "spec_name", "spec_digest", "pod_name", "pod_ip", "state")}
