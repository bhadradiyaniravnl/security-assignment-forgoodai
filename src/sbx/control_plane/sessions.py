"""Session lifecycle: run -> (agent works) -> stop -> destroy.

The control plane does everything that needs trust (cloning, canary planting, result
collection); the sandbox only ever receives a copy of the repo and a placeholder token.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import secrets
import shutil
import subprocess
import tarfile
import threading
import time

from sbx.common.evidence import EvidenceLog
from sbx.control_plane import k8s, specs
from sbx.control_plane.store import Store

GIT_LAB = os.environ.get("GIT_LAB_URL", "git://git-lab.sbx-system.svc:8080")
WORK = os.environ.get("CP_WORK", "/data/work")
RESULTS = os.environ.get("CP_RESULTS", "/data/results")
CHUNK = 60_000

evidence = EvidenceLog("control-plane")


class SessionError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status = status


def run(store: Store, user: str, spec_name: str, params: dict) -> dict:
    try:
        spec, digest = specs.load(spec_name)
        specs.authorize(spec, user)
        specs.validate_params(spec, params)
        policy = specs.compile_policy(spec)
    except PermissionError as e:
        evidence.write_sync("run_rejected", user=user, spec=spec_name, reason=str(e))
        raise SessionError(403, str(e)) from None
    except specs.SpecError as e:
        evidence.write_sync("run_rejected", user=user, spec=spec_name, params=list(params), reason=str(e))
        raise SessionError(400, str(e)) from None

    sid = "s" + secrets.token_hex(4)
    token = f"sbx_{sid}_{secrets.token_hex(32)}"
    canary = {"id": "c1", "value": f"FGCANARY-{sid}-{secrets.token_hex(6)}"}
    spec_ref = f"{spec['metadata']['name']}@{spec['metadata']['version']}"
    who = {"session_id": sid, "user": user, "spec": spec_ref, "spec_digest": digest, "pod": k8s.pod_name(sid)}

    workdir = os.path.join(WORK, sid)
    commit = _clone(params["repo"], os.path.join(workdir, "repo"))
    with open(os.path.join(workdir, "repo", ".env"), "w") as f:      # the canary: a "leaked" secret
        f.write(f"PAYMENTS_API_KEY={canary['value']}\n")

    store.create(session_id=sid, user=user, spec_name=spec_ref, spec_digest=digest, token=token, policy=policy,
                 canaries=[canary], params=params, pod_name=k8s.pod_name(sid), state="creating")
    evidence.write_sync("session_create", **who, repo=params["repo"], commit=commit, canary_ids=[canary["id"]],
                        policy_sha256=hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest())
    try:
        k8s.create_pod(k8s.sandbox_pod(sid, token, policy))
        pod = k8s.wait_ready(sid)
        store.update(sid, pod_ip=pod["ip"], state="running")          # token becomes valid only now
        evidence.write_sync("session_running", **who, pod_ip=pod["ip"], pod_uid=pod["uid"], node=pod["node"])
        _deliver(sid, workdir, {"task": params["task"], "allowed_tools": policy["agent_tools"]})
        evidence.write_sync("workspace_delivered", **who, commit=commit)
    except Exception as e:
        store.update(sid, state="failed", detail=str(e)[:500], ended=True)
        k8s.delete_pod(sid)
        evidence.write_sync("session_failed", **who, error=str(e)[:500])
        raise SessionError(500, f"session start failed: {e}") from None
    return {"session_id": sid, "pod": k8s.pod_name(sid), "spec": spec_ref, "spec_digest": digest}


def stop(store: Store, sid: str, user: str) -> dict:
    s = _owned(store, sid, user)
    if s["state"] not in ("running", "creating"):
        raise SessionError(409, f"session is {s['state']}")
    store.update(sid, state="stopping")                                 # gateway rejects from here on
    diff, rc = "", None
    if k8s.pod_status(sid):
        rc, diff, _ = k8s.exec_(sid, ["sh", "-c", "cd /workspace/repo && git add -A >/dev/null 2>&1; "
                                                  "git -c core.pager=cat diff --cached"], timeout=30)
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, f"{sid}.diff"), "w") as f:
        f.write(diff)
    k8s.delete_pod(sid)
    store.update(sid, state="stopped", detail="stopped by user", ended=True)
    evidence.write_sync("session_stop", session_id=sid, user=user, spec=s["spec_name"], spec_digest=s["spec_digest"],
                        diff_bytes=len(diff), diff_sha256=hashlib.sha256(diff.encode()).hexdigest(), exec_rc=rc)
    return {"session_id": sid, "state": "stopped", "diff_bytes": len(diff)}


def destroy(store: Store, sid: str, user: str) -> dict:
    s = _owned(store, sid, user)
    if s["state"] in ("running", "creating", "stopping"):
        store.update(sid, state="stopping")
    k8s.delete_pod(sid)
    shutil.rmtree(os.path.join(WORK, sid), ignore_errors=True)
    store.update(sid, state="destroyed", ended=True)
    evidence.write_sync("session_destroy", session_id=sid, user=user, spec=s["spec_name"])
    return {"session_id": sid, "state": "destroyed"}


def diff(store: Store, sid: str, user: str) -> str:
    _owned(store, sid, user)
    path = os.path.join(RESULTS, f"{sid}.diff")
    if not os.path.exists(path):
        raise SessionError(404, "no result yet (stop the session first)")
    return open(path).read()


def reconcile_forever(store: Store, interval: float = 5.0) -> None:
    """Revokes sessions whose pod is gone or finished (TTL via activeDeadlineSeconds, crash, eviction)."""
    def loop() -> None:
        while True:
            for s in store.list():
                if s["state"] != "running":
                    continue
                st = k8s.pod_status(s["session_id"])
                if st is None or st["phase"] in ("Failed", "Succeeded"):
                    reason = "pod missing" if st is None else f"{st['phase']}:{st['reason']}"
                    store.update(s["session_id"], state="ended", detail=reason, ended=True)
                    evidence.write_sync("session_ended", session_id=s["session_id"], user=s["user"],
                                        spec=s["spec_name"], reason=reason)
            time.sleep(interval)
    threading.Thread(target=loop, daemon=True, name="reconciler").start()


def _owned(store: Store, sid: str, user: str) -> dict:
    s = store.get(sid)
    if s is None:
        raise SessionError(404, "no such session")
    if s["user"] != user:
        raise SessionError(403, "not your session")
    return s


def _clone(repo: str, dest: str) -> str:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    env = {**os.environ, "HOME": "/tmp", "GIT_TERMINAL_PROMPT": "0"}
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"{GIT_LAB}/{repo}.git", dest], env=env, check=True,
                   capture_output=True, timeout=60)
    return subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"], env=env, check=True, capture_output=True,
                          text=True).stdout.strip()


def _deliver(sid: str, workdir: str, task: dict) -> None:
    """Streams the workspace into the pod as base64 chunks (exec args; no stdin needed), then the task.
    task.json is written last and atomically: the entrypoint starts the agent when it appears."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(os.path.join(workdir, "repo"), arcname="repo")
    b64 = base64.b64encode(buf.getvalue()).decode()
    _must(sid, ["sh", "-c", "rm -f /tmp/ws.b64"])
    for i in range(0, len(b64), CHUNK):
        _must(sid, ["sh", "-c", 'printf %s "$1" >> /tmp/ws.b64', "_", b64[i:i + CHUNK]])
    _must(sid, ["sh", "-c", "base64 -d /tmp/ws.b64 | tar -xz -C /workspace && rm /tmp/ws.b64"])
    t64 = base64.b64encode(json.dumps(task).encode()).decode()
    _must(sid, ["sh", "-c", 'mkdir -p /workspace/.sbx && printf %s "$1" | base64 -d > /workspace/.sbx/task.tmp '
                            '&& mv /workspace/.sbx/task.tmp /workspace/.sbx/task.json', "_", t64])


def _must(sid: str, cmd: list[str]) -> None:
    rc, _, err = k8s.exec_(sid, cmd)
    if rc != 0:
        raise RuntimeError(f"exec failed rc={rc}: {err[:200]}")
