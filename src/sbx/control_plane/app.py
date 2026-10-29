"""Control plane API.

Public (sbxctl, via NodePort bound to 127.0.0.1): runs, sessions, logs, stop, destroy, diff.
  Prototype identity is the X-User header; production replaces it with OIDC.
Internal (X-Sbx-Internal): token validation, compiled policy, revocation, registration.
"""
from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from sbx.common import internal
from sbx.control_plane import k8s, sessions
from sbx.control_plane.store import Store

app = FastAPI(title="sbx control plane")
store = Store()


@app.on_event("startup")
def _start_reconciler() -> None:
    sessions.reconcile_forever(store)


def require_user(x_user: str | None = Header(default=None)) -> str:
    if not x_user:
        raise HTTPException(401, "X-User required")
    return x_user


def _call(fn, *args):
    try:
        return fn(store, *args)
    except sessions.SessionError as e:
        raise HTTPException(e.status, str(e)) from None


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


@app.post("/sessions/{sid}/stop")
def stop_session(sid: str, user: str = Depends(require_user)) -> dict:
    return _call(sessions.stop, sid, user)


@app.delete("/sessions/{sid}")
def destroy_session(sid: str, user: str = Depends(require_user)) -> dict:
    return _call(sessions.destroy, sid, user)


@app.get("/sessions/{sid}/diff", response_class=PlainTextResponse)
def session_diff(sid: str, user: str = Depends(require_user)) -> str:
    return _call(sessions.diff, sid, user)


def _public(s: dict) -> dict:
    return {k: s.get(k) for k in ("session_id", "user", "spec_name", "spec_digest", "params", "pod_name",
                                  "pod_ip", "state", "detail", "created_at", "ended_at")}


def require_internal(x_sbx_internal: str | None = Header(default=None)) -> None:
    if not internal.check(x_sbx_internal):
        raise HTTPException(401, "internal auth required")


class SessionIn(BaseModel):
    session_id: str
    user: str
    spec_name: str
    spec_digest: str
    token: str
    pod_ip: str
    pod_name: str | None = None
    policy: dict
    canaries: list = []
    params: dict = {}


class ValidateIn(BaseModel):
    token: str
    ip: str


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.post("/internal/sessions", dependencies=[Depends(require_internal)])
def register(s: SessionIn) -> dict:
    store.create(**s.model_dump(exclude={"pod_ip", "pod_name"}), pod_ip=s.pod_ip, pod_name=s.pod_name, state="running")
    return {"session_id": s.session_id}


@app.post("/internal/validate", dependencies=[Depends(require_internal)])
def validate(v: ValidateIn) -> dict:
    s = store.by_token(v.token)
    if s is None:
        raise HTTPException(401, "unknown token")
    if s["pod_ip"] != v.ip:
        raise HTTPException(403, "token not bound to this source ip")
    if s["state"] != "running":
        raise HTTPException(403, f"session {s['state']}")
    return _context(s)


@app.get("/internal/policy/{session_id}", dependencies=[Depends(require_internal)])
def policy(session_id: str) -> dict:
    s = store.get(session_id)
    if s is None:
        raise HTTPException(404, "no such session")
    return {**_context(s), "policy": s["policy"], "canaries": s["canaries"]}


@app.post("/internal/revoke/{session_id}", dependencies=[Depends(require_internal)])
def revoke(session_id: str) -> dict:
    if store.get(session_id) is None:
        raise HTTPException(404, "no such session")
    store.update(session_id, state="revoked")
    return {"session_id": session_id, "state": "revoked"}


def _context(s: dict) -> dict:
    return {k: s[k] for k in ("session_id", "user", "spec_name", "spec_digest", "pod_name", "pod_ip", "state")}
