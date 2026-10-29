"""Control plane API.

M2 scope: the internal endpoints the gateway and credproxy depend on (token validation,
compiled policy, revocation) plus internal session registration. Lifecycle endpoints
(runs, stop, contain) arrive in M3/M4.
"""
from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from sbx.common import internal
from sbx.control_plane.store import Store

app = FastAPI(title="sbx control plane")
store = Store()


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
