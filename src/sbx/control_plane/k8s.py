"""Kubernetes driver: session pods only, in sbx-sessions (the Role allows nothing else)."""
from __future__ import annotations

import time

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

NS = "sbx-sessions"
GATEWAY_IP = "10.96.100.10"   # fixed ClusterIP, injected via hostAliases (sandboxes have no DNS)

_core: client.CoreV1Api | None = None


def core() -> client.CoreV1Api:
    global _core
    if _core is None:
        config.load_incluster_config()
        _core = client.CoreV1Api()
    return _core


def pod_name(sid: str) -> str:
    return f"sandbox-{sid}"


def sandbox_pod(sid: str, token: str, policy: dict) -> dict:
    rt = policy["runtime"]
    proxy = f"http://{sid}:{token}@gateway:3128"
    env = {
        "HOME": "/home/agent",
        "ANTHROPIC_BASE_URL": "http://gateway:8080",
        "ANTHROPIC_API_KEY": token,                       # placeholder; useless outside this pod
        "ANTHROPIC_MODEL": policy["model_default"],
        "ANTHROPIC_SMALL_FAST_MODEL": policy["model_small"],
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": policy["model_small"],
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_AUTOUPDATER": "1",
        "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "NO_PROXY": "gateway",
        "http_proxy": proxy, "https_proxy": proxy, "no_proxy": "gateway",   # curl ignores HTTP_PROXY
    }
    hardened = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name(sid), "namespace": NS,
                     "labels": {"sbx/session": sid, "sbx/state": "running"}},
        "spec": {
            "runtimeClassName": rt["runtime_class"],
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "restartPolicy": "Never",
            "activeDeadlineSeconds": rt["ttl_s"],
            "dnsPolicy": "None",
            "dnsConfig": {"nameservers": ["127.0.0.1"]},
            "hostAliases": [{"ip": GATEWAY_IP, "hostnames": ["gateway"]}],
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "agent",
                "image": rt["image"],
                "imagePullPolicy": "Never",
                "env": [{"name": k, "value": v} for k, v in env.items()],
                "resources": {"limits": {"cpu": rt["cpu"], "memory": rt["memory"], "ephemeral-storage": "2Gi"},
                              "requests": {"cpu": "100m", "memory": "256Mi"}},
                "securityContext": hardened,
                "volumeMounts": [{"name": n, "mountPath": p} for n, p in
                                 (("workspace", "/workspace"), ("home", "/home/agent"), ("tmp", "/tmp"))],
            }],
            "volumes": [{"name": n, "emptyDir": {"sizeLimit": "1Gi"}} for n in ("workspace", "home", "tmp")],
        },
    }


def create_pod(manifest: dict) -> None:
    core().create_namespaced_pod(NS, manifest)


def wait_ready(sid: str, timeout: float = 120) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        p = core().read_namespaced_pod(pod_name(sid), NS)
        ready = any(c.type == "Ready" and c.status == "True" for c in (p.status.conditions or []))
        if ready and p.status.pod_ip:
            return {"ip": p.status.pod_ip, "uid": p.metadata.uid, "node": p.spec.node_name}
        if p.status.phase in ("Failed", "Succeeded"):
            raise RuntimeError(f"pod ended during start: {p.status.phase} {p.status.reason}")
        time.sleep(1)
    raise TimeoutError("pod not ready")


def pod_status(sid: str) -> dict | None:
    try:
        p = core().read_namespaced_pod(pod_name(sid), NS)
    except ApiException as e:
        if e.status == 404:
            return None
        raise
    return {"phase": p.status.phase, "reason": p.status.reason, "ip": p.status.pod_ip}


def delete_pod(sid: str) -> None:
    try:
        core().delete_namespaced_pod(pod_name(sid), NS, grace_period_seconds=0)
    except ApiException as e:
        if e.status != 404:
            raise


def exec_(sid: str, cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    """Runs a command in the sandbox. Output is untrusted data from a possibly compromised pod."""
    resp = stream(core().connect_get_namespaced_pod_exec, pod_name(sid), NS, command=cmd, container="agent",
                  stderr=True, stdin=False, stdout=True, tty=False, _preload_content=False)
    resp.run_forever(timeout=timeout)
    out, err = resp.read_stdout() or "", resp.read_stderr() or ""
    rc = resp.returncode
    resp.close()
    return (rc if rc is not None else -1), out, err


def logs(sid: str, follow: bool, tail: int | None = None):
    return core().read_namespaced_pod_log(pod_name(sid), NS, container="agent", follow=follow,
                                          tail_lines=tail, _preload_content=False)
