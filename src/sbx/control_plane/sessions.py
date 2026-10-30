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
import tempfile
import threading
import time
import urllib.error
import urllib.request

from sbx.common.canary import scan
from sbx.common.evidence import EvidenceLog
from sbx.control_plane import content_scan, k8s, specs
from sbx.control_plane.store import Store

GIT_LAB = os.environ.get("GIT_LAB_URL", "git://git-lab.sbx-system.svc:8080")
CREDPROXY = os.environ.get("CREDPROXY_URL", "http://credproxy.sbx-system.svc:9000")
CP_KEY = os.environ.get("SBX_CP_KEY", "")
WORK = os.environ.get("CP_WORK", "/data/work")
RESULTS = os.environ.get("CP_RESULTS", "/data/results")
CHUNK = 60_000
MAX_SUMMARY = 4000
MAX_PR_DIFF = 1_000_000

EVIDENCE_DIR = os.environ.get("EVIDENCE_DIR", "/evidence")
evidence = EvidenceLog("control-plane")
alerts = EvidenceLog("alerts")


class SessionError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status = status


def run(store: Store, user: str, spec_name: str, params: dict) -> dict:
    if store.get_meta("frozen"):
        raise SessionError(503, f"platform is frozen ({store.get_meta('frozen')}); no new sessions")
    try:
        spec, digest = specs.load(store, spec_name)
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
    policy["repo"] = params["repo"]                                    # credproxy re-checks GitHub ops against this
    store.create(session_id=sid, user=user, spec_name=spec_ref, spec_digest=digest, token=token, policy=policy,
                 canaries=[canary], params=params, pod_name=k8s.pod_name(sid), state="creating")
    try:
        commit = _clone(sid, params["repo"], os.path.join(workdir, "repo"), who)
    except Exception as e:
        store.transition(sid, ("creating",), "failed", detail=f"clone failed: {e}"[:500], ended=True)
        evidence.write_sync("session_failed", **who, error=f"clone: {e}"[:500])
        raise SessionError(502, f"clone failed: {e}") from None
    findings = content_scan.scan(os.path.join(workdir, "repo"))      # before we add anything ourselves
    store.update(sid, scan=json.dumps(findings))
    _plant(os.path.join(workdir, "repo", ".env"), f"PAYMENTS_API_KEY={canary['value']}\n")   # the canary
    os.makedirs(os.path.join(workdir, "repo", ".git", "info"), exist_ok=True)
    with open(os.path.join(workdir, "repo", ".git", "info", "exclude"), "a") as f:
        f.write("\n.env\n")                                          # local-only ignore; never committed
    if findings:
        evidence.write_sync("untrusted_content_scan", **who, count=len(findings), findings=findings[:20])
        alerts.write_sync("alert", alert_id=f"al_inj_{sid}", rule="INJ", severity="low", **who,
                          summary=f"{len(findings)} instruction-like passage(s) in repo content "
                                  f"({', '.join(sorted({f['rule'] for f in findings}))})",
                          observed={"findings": findings[:5]}, evidence=[{"source": "control-plane"}])
    evidence.write_sync("session_create", **who, repo=params["repo"], commit=commit, canary_ids=[canary["id"]],
                        policy_sha256=hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest())
    try:
        k8s.create_pod(k8s.sandbox_pod(sid, token, policy))
        pod = k8s.wait_ready(sid)
        if not store.transition(sid, ("creating",), "running", pod_ip=pod["ip"],   # token becomes valid only now
                                last_activity=time.time()):
            raise RuntimeError(f"session left 'creating' during start ({store.get(sid)['state']})")
        evidence.write_sync("session_running", **who, pod_ip=pod["ip"], pod_uid=pod["uid"], node=pod["node"])
        _deliver(sid, workdir, {"task": params["task"], "allowed_tools": policy["agent_tools"]})
        evidence.write_sync("workspace_delivered", **who, commit=commit)
    except Exception as e:
        if store.transition(sid, ("creating", "running"), "failed", detail=str(e)[:500], ended=True):
            k8s.delete_pod(sid)                                         # a contained pod is kept for forensics
        evidence.write_sync("session_failed", **who, error=str(e)[:500])
        raise SessionError(500, f"session start failed: {e}") from None
    return {"session_id": sid, "pod": k8s.pod_name(sid), "spec": spec_ref, "spec_digest": digest}


def stop(store: Store, sid: str, user: str, reason: str = "stopped by user", system: bool = False) -> dict:
    """Revoke -> trusted diff -> (draft PR) -> transcript -> delete pod. `system` is the idle/lifetime
    reaper acting on any owner's session; users can only stop their own."""
    s = store.get(sid) if system else _owned(store, sid, user)
    if s is None:
        raise SessionError(404, "no such session")
    if s["state"] not in ("running", "creating", "contained"):
        raise SessionError(409, f"session is {s['state']}")
    was_contained = s["state"] == "contained"
    if not was_contained and not store.transition(sid, ("running", "creating"), "stopping"):
        raise SessionError(409, f"session is {store.get(sid)['state']}")   # gateway rejects from here on
    diff, rc = "", None
    if k8s.pod_status(sid):
        diff, rc = collect_diff(sid)
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, f"{sid}.diff"), "w") as f:
        f.write(diff)
    pr = None
    if (not was_contained and store.get(sid)["state"] == "stopping"
            and s["policy"].get("output", {}).get("type") == "pull_request" and diff.strip()):
        pr = _publish(sid, s, diff)                                     # credproxy re-checks 'stopping' itself
    if was_contained:                                                   # keep the frozen pod for forensics
        evidence.write_sync("session_stop", session_id=sid, user=user, spec=s["spec_name"],
                            spec_digest=s["spec_digest"], diff_bytes=len(diff),
                            diff_sha256=hashlib.sha256(diff.encode()).hexdigest(), exec_rc=rc, pod_kept=True)
        return {"session_id": sid, "state": "contained", "diff_bytes": len(diff)}
    if not store.transition(sid, ("stopping",), "stopped", detail=reason, ended=True):
        # Contained while we were stopping: keep the pod and the 'contained' state for forensics.
        evidence.write_sync("session_stop", session_id=sid, user=user, spec=s["spec_name"],
                            spec_digest=s["spec_digest"], diff_bytes=len(diff), contained_during_stop=True,
                            diff_sha256=hashlib.sha256(diff.encode()).hexdigest(), exec_rc=rc, pod_kept=True)
        return {"session_id": sid, "state": store.get(sid)["state"], "diff_bytes": len(diff), "pr": pr}
    transcript = save_transcript(sid, "stop")
    k8s.delete_pod(sid)
    shutil.rmtree(os.path.join(WORK, sid), ignore_errors=True)        # repo copy + canary: not kept past stop
    evidence.write_sync("session_stop", session_id=sid, user=user, spec=s["spec_name"], spec_digest=s["spec_digest"],
                        diff_bytes=len(diff), diff_sha256=hashlib.sha256(diff.encode()).hexdigest(), exec_rc=rc,
                        transcript=bool(transcript), workdir_removed=True, reason=reason)
    if pr:
        store.update(sid, detail=f"PR {pr.get('pr_url') or pr.get('error')}"[:500])
    return {"session_id": sid, "state": "stopped", "diff_bytes": len(diff), "pr": pr}


MAX_MESSAGE = 4000


def send_message(store: Store, sid: str, user: str, text: str) -> dict:
    """Follow-up instruction from the session owner. The agent resumes the same conversation in the
    same pod. Evidence records who sent what (hash + length), not the text itself."""
    s = _owned(store, sid, user)
    if s["state"] != "running":
        raise SessionError(409, f"session is {s['state']}")
    text = text.strip()
    if not text or len(text) > MAX_MESSAGE:
        raise SessionError(400, f"message must be 1..{MAX_MESSAGE} characters")
    n = int(s.get("turns") or 0) + 1
    b64 = base64.b64encode(json.dumps({"text": text}).encode()).decode()
    _must(sid, ["sh", "-c", 'mkdir -p /workspace/.sbx/inbox && printf %s "$1" | base64 -d > /workspace/.sbx/inbox/.tmp '
                            '&& mv /workspace/.sbx/inbox/.tmp "/workspace/.sbx/inbox/$2.json"', "_", b64, str(n)])
    store.update(sid, turns=n, last_activity=time.time())
    evidence.write_sync("message_sent", session_id=sid, user=user, spec=s["spec_name"], turn=n, length=len(text),
                        sha256=hashlib.sha256(text.encode()).hexdigest())
    return {"session_id": sid, "turn": n}


def freeze(store: Store, actor: str, reason: str) -> dict:
    """Fleet kill switch. 1) revoke every live session (CAS, so nothing is revived), 2) one
    namespace-wide deny policy, 3) refuse new runs until unfrozen. Pods are kept for forensics."""
    if actor not in SECURITY_ADMINS:
        raise SessionError(403, "only security admins can freeze the platform")
    t0 = time.time()
    store.set_meta("frozen", f"by {actor} at {int(t0)}: {reason}"[:300])
    frozen = [s["session_id"] for s in store.list()
              if store.transition(s["session_id"], ("running", "creating", "stopping"), "contained",
                                  detail=f"fleet freeze by {actor}: {reason}"[:500])]
    revoked_at = time.time()
    k8s.freeze_all()
    result = {"frozen_sessions": frozen, "revoked_in_s": round(revoked_at - t0, 3),
              "network_deny_in_s": round(time.time() - t0, 3)}
    evidence.write_sync("fleet_freeze", actor=actor, reason=reason, **result)
    return result


def unfreeze(store: Store, actor: str) -> dict:
    """Lifts the namespace deny and allows new runs. Frozen sessions stay contained (admin release)."""
    if actor not in SECURITY_ADMINS:
        raise SessionError(403, "only security admins can unfreeze the platform")
    k8s.unfreeze_all()
    store.set_meta("frozen", None)
    evidence.write_sync("fleet_unfreeze", actor=actor)
    return {"frozen": False}


def contain(store: Store, sid: str, actor: str, alert_id: str | None = None, reason: str = "") -> dict:
    """Revoke -> network quarantine -> preserve evidence -> probe. The pod is kept (frozen off the
    network) for forensics until destroy. Order matters: the token dies before anything else."""
    s = store.get(sid)
    if s is None:
        raise SessionError(404, "no such session")
    if s["state"] == "contained":
        return {"session_id": sid, "state": "contained", "already": True}
    if s["state"] not in ("running", "creating", "stopping"):
        raise SessionError(409, f"session is {s['state']}")
    t0 = time.time()
    if not store.transition(sid, ("running", "creating", "stopping"), "contained",                  # 1. revoke
                            detail=f"contained by {actor}: {reason}"[:500]):
        return {"session_id": sid, "state": store.get(sid)["state"], "already": True}
    revoked_at = time.time()
    k8s.quarantine(sid)                                                                         # 2. isolate
    quarantined_at = time.time()
    snap = _snapshot(sid, s)                                                                    # 3. preserve
    time.sleep(2)
    probe = _probe(sid)                                                                         # 4. probe
    result = {"session_id": sid, "state": "contained", "actor": actor, "alert_id": alert_id,
              "revoked_at": revoked_at, "quarantined_at": quarantined_at, "snapshot": snap, "probe": probe,
              "probe_blocked": all(v == "000" for v in probe.values()), "elapsed_s": round(time.time() - t0, 2)}
    evidence.write_sync("session_contain", user=s["user"], spec=s["spec_name"], spec_digest=s["spec_digest"],
                        **{k: v for k, v in result.items() if k != "state"})
    return result


MAX_TRANSCRIPT_B64 = 48 * 1024 * 1024


def save_transcript(sid: str, label: str) -> str | None:
    """Copies Claude Code's own transcript (~/.claude) into evidence so the reasoning chain survives the
    pod. Provenance: written by the agent's process, so it is context for investigators, not proof;
    ground truth stays the gateway's tool_use and prompt/response records."""
    try:
        rc, b64, _ = k8s.exec_(sid, ["sh", "-c", "tar -cz -C /home/agent .claude 2>/dev/null | base64 -w0"],
                               timeout=60)
    except Exception:  # noqa: BLE001 - pod may already be gone
        return None
    if not b64 or len(b64) > MAX_TRANSCRIPT_B64:
        return None
    d = os.path.join(EVIDENCE_DIR, "sessions", sid)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"transcript-{label}.tgz")
    with open(path, "wb") as f:
        f.write(base64.b64decode(b64))
    return path


def _snapshot(sid: str, s: dict) -> str:
    """Copies what an investigator needs out of reach of the sandbox, before anything is destroyed."""
    d = os.path.join(EVIDENCE_DIR, "sessions", sid)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "session.json"), "w") as f:
        json.dump(s, f, indent=2, default=str)
    try:
        with open(os.path.join(d, "pod.json"), "w") as f:
            json.dump(k8s.pod_snapshot(sid), f, indent=2, default=str)
        with open(os.path.join(d, "agent-stdout.log"), "wb") as f:     # untrusted, kept for context only
            f.write(k8s.logs(sid, follow=False).data)
    except Exception as e:  # noqa: BLE001 - snapshot is best effort; containment must not fail on it
        with open(os.path.join(d, "snapshot-errors.txt"), "a") as f:
            f.write(f"{e}\n")
    save_transcript(sid, "containment")
    gw = os.path.join(EVIDENCE_DIR, "gateway.jsonl")
    if os.path.exists(gw):
        with open(gw) as src, open(os.path.join(d, "gateway-events.jsonl"), "w") as dst:
            dst.writelines(line for line in src if f'"session_id": "{sid}"' in line)
    return d


def _probe(sid: str) -> dict:
    """Generates traffic from inside the contained pod; every path must fail (000 = no connection)."""
    cmds = {
        "egress_via_proxy": 'curl -s -o /dev/null -m 4 -w "%{http_code}" http://paste-mock.lab-ext/probe',
        "ai_gateway": 'curl -s -o /dev/null -m 4 -w "%{http_code}" http://gateway:8080/v1/messages',
        "direct_gateway_bypassing_proxy": 'curl -s -o /dev/null -m 4 -w "%{http_code}" --noproxy "*" http://10.96.100.10:3128/',
    }
    out = {}
    for name, cmd in cmds.items():
        try:
            _, stdout, _ = k8s.exec_(sid, ["sh", "-c", cmd], timeout=15)
            out[name] = stdout.strip() or "000"
        except Exception as e:  # noqa: BLE001
            out[name] = f"exec-error: {e}"[:100]
    return out


SECURITY_ADMINS = set(filter(None, os.environ.get("SBX_SECURITY_ADMINS", "secops").split(",")))


def destroy(store: Store, sid: str, user: str, system: bool = False) -> dict:
    """Owners destroy their own sessions, except contained ones: those hold forensic state and the
    owner is the person the alert names, so only security admins (or the retention reaper, after the
    snapshot and transcript are in evidence) may release them."""
    s = store.get(sid)
    if s is None:
        raise SessionError(404, "no such session")
    if s["state"] == "contained":
        if user not in SECURITY_ADMINS and not system:
            raise SessionError(403, "contained sessions can only be destroyed by security admins")
    elif not system:
        s = _owned(store, sid, user)
    store.transition(sid, ("running", "creating", "stopping"), "stopping")
    k8s.delete_pod(sid)
    k8s.unquarantine(sid)
    shutil.rmtree(os.path.join(WORK, sid), ignore_errors=True)
    store.update(sid, state="destroyed", ended=True)
    evidence.write_sync("session_destroy", session_id=sid, user=user, spec=s["spec_name"],
                        released_from_containment=s["state"] == "contained")
    return {"session_id": sid, "state": "destroyed"}


MAX_WORKSPACE_B64 = 64 * 1024 * 1024
GIT_ISOLATED = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
                "PATH": os.environ.get("PATH", "/usr/bin:/bin")}


def collect_diff(sid: str) -> tuple[str, int]:
    """The diff is computed HERE, not by git in the pod: the agent controls the pod's git binary,
    config (diff.external, textconv, aliases) and output. We copy out the working-tree files only,
    lay them over our own pristine .git from clone time, and diff with an isolated git config."""
    rc, b64, err = k8s.exec_(sid, ["sh", "-c", "tar -cz -C /workspace/repo --exclude=./.git . | base64 -w0"],
                             timeout=120)
    if rc != 0 or len(b64) > MAX_WORKSPACE_B64:
        raise SessionError(502, f"workspace export failed (rc={rc}, {len(b64)} bytes): {err[:200]}")
    pristine = os.path.join(WORK, sid, "repo", ".git")
    with tempfile.TemporaryDirectory() as d:
        shutil.copytree(pristine, os.path.join(d, ".git"), symlinks=True)
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(b64)), mode="r:gz") as tar:
            tar.extractall(d, filter="data")          # rejects absolute paths, traversal, device files
        env = {**GIT_ISOLATED, "HOME": d}
        cfg = ["-c", "core.quotepath=off", "-c", "core.hooksPath=/dev/null", "-c", "diff.external="]
        subprocess.run(["git", *cfg, "add", "-A"], cwd=d, env=env, check=True, capture_output=True, timeout=60)
        out = subprocess.run(["git", *cfg, "diff", "--cached", "--no-ext-diff", "--no-textconv", "--binary"],
                             cwd=d, env=env, check=True, capture_output=True, text=True, timeout=60).stdout
    return out, rc


def _scan_section(s: dict) -> str:
    """Tells the reviewer about instruction-like content the agent was exposed to (agents rarely do)."""
    findings = s.get("scan") or []
    if not findings:
        return "Pre-run content scan: no instruction-like content found.\n\n"
    rows = "\n".join(f"{f['path']}:{f['line']}  [{f['rule']}]  {f['excerpt']}".replace("`", "\u02cb")
                      for f in findings[:15])
    return (f"### ⚠ Untrusted instructions in the repository ({len(findings)} finding(s))\n\n"
            "The agent read repository content that addresses AI agents. Review the diff with that in mind.\n\n"
            f"```text\n{rows}\n```\n\n")


def _publish(sid: str, s: dict, diff: str) -> dict:
    """Draft PR via credproxy. The agent's own summary is quoted as untrusted text."""
    summary = ""
    try:
        logs = k8s.logs(sid, follow=False).data.decode(errors="replace")
        line = next((l for l in reversed(logs.splitlines()) if '"type":"result"' in l.replace(" ", "")), "")
        summary = json.loads(line).get("result", "") if line else ""
    except Exception:  # noqa: BLE001
        pass
    out_cfg = s["policy"].get("output", {})
    who0 = {"session_id": sid, "user": s["user"], "spec": s["spec_name"], "spec_digest": s["spec_digest"]}
    hit = scan(diff.encode(), s["canaries"])
    where = "diff"
    if not hit:
        hit, where = scan(summary.encode(), s["canaries"]), "agent summary"
    if hit or len(diff) > MAX_PR_DIFF:
        reason = f"canary {hit['id']} ({hit['encoding']}) in {where}" if hit else f"diff too large ({len(diff)} bytes)"
        evidence.write_sync("pr_refused", **who0, error=reason)
        if hit:   # the PR is an egress channel too: same rule as D1, raised by the control plane
            alerts.write_sync("alert", alert_id=f"al_pr_{sid}", rule="D1", severity="high", **who0,
                              summary=f"{reason}: PR publication refused", observed={"channel": "pull_request"},
                              evidence=[{"source": "control-plane", "diff_sha256": hashlib.sha256(diff.encode()).hexdigest()}],
                              pod=s["pod_name"], pod_ip=s["pod_ip"])
        return {"error": reason}
    # Untrusted text rendered inert: inside a code fence nothing renders (no images, links, HTML,
    # mentions), so GitHub never fetches agent-chosen URLs. Fence-breaking backticks are neutralised.
    inert = (summary or "(no summary)").replace("`", "\u02cb")[:MAX_SUMMARY]
    quoted = "```text\n" + inert + "\n```"
    task_txt = s["params"].get("task", "")[:300].replace("`", "'").replace("|", "/").replace("\n", " ")
    body = (f"Opened by the sandboxed agent platform. **Requires human review.**\n\n"
            f"| | |\n|---|---|\n| Requested by | `{s['user']}` |\n| Session | `{sid}` |\n"
            f"| Spec | `{s['spec_name']}` |\n| Spec digest | `{s['spec_digest']}` |\n"
            f"| Task | `{task_txt}` |\n\n"
            f"{_scan_section(s)}"
            f"### Agent summary (untrusted, written by the agent)\n\n{quoted}\n")
    title = f"agent: {s['params'].get('task', 'changes')[:60]} ({sid})"
    who = {"session_id": sid, "user": s["user"], "spec": s["spec_name"], "spec_digest": s["spec_digest"]}
    try:
        resp = _credproxy("/github/publish", {"session_id": sid, "repo": s["params"]["repo"][len("github:"):],
                                              "branch": f"{out_cfg.get('branch_prefix', 'agent/')}{sid}",
                                              "diff": diff, "title": title, "body": body})
        pr = json.loads(resp.read())
        evidence.write_sync("pr_opened", **who, pr_url=pr["pr_url"], branch=pr["branch"], commit=pr["commit"],
                            paths=pr["paths"], token=pr.get("token"))
        return pr
    except RuntimeError as e:
        evidence.write_sync("pr_refused", **who, error=str(e)[:500])
        return {"error": str(e)[:300]}


def diff(store: Store, sid: str, user: str) -> str:
    _owned(store, sid, user)
    path = os.path.join(RESULTS, f"{sid}.diff")
    if not os.path.exists(path):
        raise SessionError(404, "no result yet (stop the session first)")
    return open(path).read()


RESULTS_TTL_S = int(os.environ.get("SBX_RESULTS_TTL_DAYS", "7")) * 86400


def _sweep_results() -> None:
    """Diffs are kept for review, then expire (they can contain anything the agent wrote)."""
    if not os.path.isdir(RESULTS):
        return
    cutoff = time.time() - RESULTS_TTL_S
    for f in os.listdir(RESULTS):
        path = os.path.join(RESULTS, f)
        if os.path.getmtime(path) < cutoff:
            os.remove(path)


CONTAINED_RETENTION_S = int(float(os.environ.get("SBX_CONTAINED_RETENTION_HOURS", "2")) * 3600)   # snapshot is taken at containment
LIFETIME_MARGIN_S = 60


def _reap(store: Store) -> None:
    """Frees resources nobody is using. Activity = gateway token validations (every model/egress call)
    and follow-up messages, i.e. signals the agent can't fake from inside the pod.
      running, idle > spec idleTimeout          -> normal stop (diff, PR if configured, transcript, pod deleted)
      running, within 60 s of the hard TTL       -> normal stop before the kubelet kills the pod
      contained, longer than the retention period -> released (snapshot + transcript already in evidence)"""
    now = time.time()
    for s in store.list():
        rt = s["policy"].get("runtime", {})
        try:
            if s["state"] == "running":
                idle = now - (s.get("last_activity") or s["created_at"])
                if idle > rt.get("idle_s", 600):
                    stop(store, s["session_id"], "system:reaper", f"idle {int(idle)}s (limit {rt.get('idle_s', 600)}s)",
                         system=True)
                elif now - s["created_at"] > rt.get("ttl_s", 1800) - LIFETIME_MARGIN_S:
                    stop(store, s["session_id"], "system:reaper", "max lifetime reached", system=True)
            elif s["state"] == "contained" and now - (s.get("state_changed_at") or s["created_at"]) > CONTAINED_RETENTION_S:
                destroy(store, s["session_id"], "system:retention", system=True)
        except Exception as e:  # noqa: BLE001 - one bad session must not stop the reaper
            evidence.write_sync("reaper_error", session_id=s["session_id"], error=str(e)[:300])


def reconcile_forever(store: Store, interval: float = 5.0) -> None:
    """Revokes sessions whose pod is gone or finished (TTL via activeDeadlineSeconds, crash, eviction)."""
    def sweep_orphans() -> None:
        """After a restart: any session pod the registry doesn't know as live is removed (fail closed).
        Contained sessions keep their pod for forensics."""
        for sid, pod in k8s.session_pods():
            s = store.get(sid)
            if s is None or s["state"] in ("stopped", "destroyed", "failed", "ended"):
                k8s.delete_pod(sid)
                k8s.unquarantine(sid)
                evidence.write_sync("orphan_removed", session_id=sid, pod=pod,
                                    known_state=s["state"] if s else None)

    def loop() -> None:
        try:
            sweep_orphans()
        except Exception as e:  # noqa: BLE001 - never block startup on the sweep
            evidence.write_sync("orphan_sweep_failed", error=str(e)[:300])
        while True:
            _sweep_results()
            _reap(store)
            for s in store.list():
                if s["state"] != "running":
                    continue
                st = k8s.pod_status(s["session_id"])
                if st is None or st["phase"] in ("Failed", "Succeeded"):
                    reason = "pod missing" if st is None else f"{st['phase']}:{st['reason']}"
                    if not store.transition(s["session_id"], ("running",), "ended", detail=reason, ended=True):
                        continue
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


def _plant(path: str, content: str) -> None:
    """Writes the canary without following anything the repo put there (a committed `.env` symlink
    pointing at /evidence/... or /data/cp.db would otherwise make us overwrite our own files)."""
    if os.path.lexists(path):
        os.unlink(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)


def _credproxy(path: str, body: dict, timeout: int = 180):
    req = urllib.request.Request(CREDPROXY + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-Sbx-CP": CP_KEY})
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"credproxy {path}: {e.code} {e.read().decode(errors='replace')[:300]}") from None


def _clone(sid: str, repo: str, dest: str, who: dict) -> str:
    """git-lab repos are cloned directly; GitHub repos only through credproxy, which mints and
    revokes a repo-scoped read token and returns a tarball (the token never leaves credproxy)."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if repo.startswith("github:"):
        resp = _credproxy("/github/clone", {"session_id": sid, "repo": repo[len("github:"):]})
        meta = json.loads(resp.headers.get("X-Sbx-Token-Meta", "{}"))
        with tarfile.open(fileobj=io.BytesIO(resp.read()), mode="r:gz") as tar:
            tar.extractall(os.path.dirname(dest), filter="data")
        evidence.write_sync("github_token_used", **who, operation="clone", **meta)
        return meta.get("commit", "")
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
