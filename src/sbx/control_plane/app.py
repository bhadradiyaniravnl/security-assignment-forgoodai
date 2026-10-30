"""Control plane API.

Public (sbxctl, via NodePort bound to 127.0.0.1): runs, sessions, logs, stop, destroy, diff.
  Prototype identity is the X-User header; production replaces it with OIDC.
Internal (X-Sbx-Internal, per-component keys): token validation (gateway), compiled policy
(gateway, credproxy, detector), alerts (detector). There is deliberately no internal way to create
a session: every session goes through /runs, i.e. the spec registry and its baseline.
"""
from __future__ import annotations

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
    for r in specs.bootstrap(store):
        action = "spec_rejected" if "rejected" in r else "spec_registered"
        sessions.evidence.write_sync(action, by="system:bootstrap", **{k: v for k, v in r.items() if k != "unchanged"})
    sessions.reconcile_forever(store)


def scope(*allowed: str):
    """Dependency: internal endpoint callable only by the listed components."""
    def dep(x_sbx_internal: str | None = Header(default=None)) -> str:
        who = internal.caller(x_sbx_internal)
        if who is None:
            raise HTTPException(401, "internal auth required")
        if who not in allowed:
            raise HTTPException(403, f"{who} may not call this endpoint")
        return who
    return dep


def require_user(x_user: str | None = Header(default=None)) -> str:
    if not x_user:
        raise HTTPException(401, "X-User required")
    if x_user.startswith("system:"):                      # reserved for in-process callers (bootstrap)
        raise HTTPException(400, "reserved identity")
    return x_user


def _call(fn, *args):
    try:
        return fn(store, *args)
    except sessions.SessionError as e:
        raise HTTPException(e.status, str(e)) from None


@app.post("/specs")
async def register_spec(request: Request, user: str = Depends(require_user)) -> dict:
    """Spec authors register a new version (raw YAML body). Rejected specs never reach the registry."""
    raw = await request.body()
    try:
        r = specs.register(store, raw, user)
    except PermissionError as e:
        sessions.evidence.write_sync("spec_rejected", by=user, digest=specs.digest_of(raw), reasons=[str(e)])
        raise HTTPException(403, str(e)) from None
    except specs.SpecError as e:
        sessions.evidence.write_sync("spec_rejected", by=user, digest=specs.digest_of(raw), reasons=e.details or [str(e)])
        raise HTTPException(422, {"error": str(e), "reasons": e.details or [str(e)]}) from None
    if not r.get("unchanged"):
        sessions.evidence.write_sync("spec_registered", by=user, **r)
    return r


@app.post("/specs/approvals")
async def approve_spec(request: Request, user: str = Depends(require_user)) -> dict:
    """Security approvers approve exact spec bytes; authors then register them (two-person rule)."""
    raw = await request.body()
    try:
        r = specs.approve(store, raw, user)
    except PermissionError as e:
        raise HTTPException(403, str(e)) from None
    except specs.SpecError as e:
        raise HTTPException(422, {"error": str(e), "reasons": e.details or [str(e)]}) from None
    sessions.evidence.write_sync("spec_approved", **r)
    return r


@app.get("/specs")
def list_specs(user: str = Depends(require_user)) -> list:
    return store.list_specs()


class RunIn(BaseModel):
    spec: str
    params: dict


@app.post("/runs")
def create_run(r: RunIn, user: str = Depends(require_user)) -> dict:
    return _call(sessions.run, user, r.spec, r.params)


@app.get("/sessions")
def list_sessions(user: str = Depends(require_user)) -> list:
    return [_public(s) for s in store.list() if s["user"] == user]


@app.get("/sessions/{sid}")
def get_session(sid: str, user: str = Depends(require_user)) -> dict:
    s = store.get(sid)
    if s is None or s["user"] != user:
        raise HTTPException(404, "no such session")
    return {**_public(s), "pod_status": k8s.pod_status(sid)}


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
    return _call(sessions.send_message, sid, user, m.text)


@app.post("/sessions/{sid}/stop")
def stop_session(sid: str, user: str = Depends(require_user)) -> dict:
    return _call(sessions.stop, sid, user)


@app.delete("/sessions/{sid}")
def destroy_session(sid: str, user: str = Depends(require_user)) -> dict:
    return _call(sessions.destroy, sid, user)


@app.post("/sessions/{sid}/contain")
def contain_session(sid: str, user: str = Depends(require_user)) -> dict:
    s = store.get(sid)
    if s is None or s["user"] != user:
        raise HTTPException(404, "no such session")
    return _call(sessions.contain, sid, f"user:{user}", None, "manual")


@app.get("/alerts")
def list_alerts(user: str = Depends(require_user)) -> list:
    """Alerts on the caller's sessions, with containment verifications attached."""
    rows = _read_alerts()
    verif = {r["alert_id"]: r for r in rows if r.get("action") == "containment_verification"}
    cont = {r["alert_id"]: r["result"] for r in rows if r.get("action") == "containment"}
    out = []
    for a in rows:
        if a.get("action") == "alert" and a.get("user") == user:
            out.append({**a, "containment": cont.get(a["alert_id"]), "verification": verif.get(a["alert_id"])})
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


@app.post("/internal/alerts", dependencies=[Depends(scope("detector"))])
def raise_alert(a: AlertIn) -> dict:
    """Alert sink for the detector. Joins user/spec from the registry so every alert links
    initiating user -> session -> observed action. The alert is recorded at detection time,
    then (if requested) the session is contained and a linked containment record is written."""
    s = store.get(a.session_id) if a.session_id else None
    who = {"user": s["user"], "spec": s["spec_name"], "spec_digest": s["spec_digest"], "pod": s["pod_name"],
           "pod_ip": s["pod_ip"]} if s else {}
    rec = sessions.alerts.write_sync("alert", **a.model_dump(), **who)
    containment = None
    if a.contain and s and s["state"] in ("running", "creating", "stopping"):
        try:
            containment = sessions.contain(store, a.session_id, "detector", a.alert_id, f"{a.rule}: {a.summary}")
        except sessions.SessionError as e:
            containment = {"error": str(e)}
        sessions.alerts.write_sync("containment", alert_id=a.alert_id, session_id=a.session_id, result=containment)
    return {**rec, "containment": containment}


class VerificationIn(BaseModel):
    alert_id: str
    session_id: str
    verified: bool
    sources: dict


@app.post("/internal/alerts/verification", dependencies=[Depends(scope("detector"))])
def verify_alert(v: VerificationIn) -> dict:
    return sessions.alerts.write_sync("containment_verification", **v.model_dump())


@app.get("/internal/alerts", dependencies=[Depends(scope("detector"))])
def internal_alerts() -> list:
    return _read_alerts()


def _read_alerts() -> list:
    import json
    import os
    path = sessions.alerts.path
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


@app.get("/sessions/{sid}/diff", response_class=PlainTextResponse)
def session_diff(sid: str, user: str = Depends(require_user)) -> str:
    return _call(sessions.diff, sid, user)


def _public(s: dict) -> dict:
    return {k: s.get(k) for k in ("session_id", "user", "spec_name", "spec_digest", "params", "pod_name",
                                  "pod_ip", "state", "detail", "turns", "created_at", "ended_at")}


class ValidateIn(BaseModel):
    token: str
    ip: str


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.post("/internal/validate", dependencies=[Depends(scope("gateway"))])
def validate(v: ValidateIn) -> dict:
    s = store.by_token(v.token)
    if s is None:
        raise HTTPException(401, "unknown token")
    if s["pod_ip"] != v.ip:
        raise HTTPException(403, "token not bound to this source ip")
    if s["state"] != "running":
        raise HTTPException(403, f"session {s['state']}")
    return _context(s)


@app.get("/internal/policy/{session_id}", dependencies=[Depends(scope("gateway", "credproxy", "detector"))])
def policy(session_id: str) -> dict:
    s = store.get(session_id)
    if s is None:
        raise HTTPException(404, "no such session")
    return {**_context(s), "policy": s["policy"], "canaries": s["canaries"]}


def _context(s: dict) -> dict:
    return {k: s[k] for k in ("session_id", "user", "spec_name", "spec_digest", "pod_name", "pod_ip", "state")}
