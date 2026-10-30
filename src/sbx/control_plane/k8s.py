"""Kubernetes driver: session pods and their Cilium policies, in sbx-sessions only (the control
plane's Role allows nothing else).

Builds the hardened sandbox pod manifest from a compiled policy, execs into it, reads its logs,
and applies per-session quarantine and the fleet-wide freeze as CiliumNetworkPolicies. Anything
read back from a pod (exec output, logs) is untrusted: the pod may be fully compromised.
"""
from __future__ import annotations

import time

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

NS = "sbx-sessions"
GATEWAY_IP = "10.96.100.10"   # fixed ClusterIP, injected via hostAliases (sandboxes have no DNS)

_core: client.CoreV1Api | None = None


def core() -> client.CoreV1Api:
    """Lazily loads the in-cluster config (so importing this module needs no cluster)."""
    global _core
    if _core is None:
        config.load_incluster_config()
        _core = client.CoreV1Api()
    return _core


def pod_name(sid: str) -> str:
    return f"sandbox-{sid}"


def sandbox_pod(sid: str, token: str, policy: dict) -> dict:
    """Pod manifest for one session. The token is the session's placeholder credential: it only
    works through the gateway, from this pod's IP, while the session is running."""
    runtime = policy["runtime"]
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
        "http_proxy": proxy, "https_proxy": proxy, "no_proxy": "gateway",   # curl ignores upper-case HTTP_PROXY
    }
    hardened = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name(sid), "namespace": NS,
                     "labels": {"sbx/session": sid, "sbx/state": "running"}},
        "spec": {
            "runtimeClassName": runtime["runtime_class"],
            "nodeSelector": {"sbx/pool": "sandbox"},        # never on the node that holds credproxy
            "tolerations": [{"key": "sbx/sandbox", "operator": "Equal", "value": "true", "effect": "NoSchedule"}],
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "restartPolicy": "Never",
            "activeDeadlineSeconds": runtime["ttl_s"],
            "dnsPolicy": "None",
            "dnsConfig": {"nameservers": ["127.0.0.1"]},
            "hostAliases": [{"ip": GATEWAY_IP, "hostnames": ["gateway"]}],
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "agent",
                "image": runtime["image"],
                "imagePullPolicy": "Never",
                "env": [{"name": k, "value": v} for k, v in env.items()],
                "resources": {"limits": {"cpu": runtime["cpu"], "memory": runtime["memory"], "ephemeral-storage": "2Gi"},
                              "requests": {"cpu": "100m", "memory": "256Mi"}},
                "securityContext": hardened,
                "volumeMounts": [{"name": n, "mountPath": p} for n, p in
                                 (("workspace", "/workspace"), ("home", "/home/agent"), ("tmp", "/tmp"))],
            }],
            "volumes": [{"name": n, "emptyDir": {"sizeLimit": "1Gi"}} for n in ("workspace", "home", "tmp")],
        },
    }


def create_pod(manifest: dict) -> None:
    """Creates the pod; admission policy in the cluster re-checks the manifest."""
    core().create_namespaced_pod(NS, manifest)


def wait_ready(sid: str, timeout: float = 120) -> dict:
    """Polls until the pod is Ready with an IP; returns {ip, uid, node}."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        pod = core().read_namespaced_pod(pod_name(sid), NS)
        ready = any(c.type == "Ready" and c.status == "True" for c in (pod.status.conditions or []))
        if ready and pod.status.pod_ip:
            return {"ip": pod.status.pod_ip, "uid": pod.metadata.uid, "node": pod.spec.node_name}
        if pod.status.phase in ("Failed", "Succeeded"):
            raise RuntimeError(f"pod ended during start: {pod.status.phase} {pod.status.reason}")
        time.sleep(1)
    raise TimeoutError("pod not ready")


def pod_status(sid: str) -> dict | None:
    """{phase, reason, ip}, or None if the pod does not exist."""
    try:
        pod = core().read_namespaced_pod(pod_name(sid), NS)
    except ApiException as e:
        if e.status == 404:
            return None
        raise
    return {"phase": pod.status.phase, "reason": pod.status.reason, "ip": pod.status.pod_ip}


def delete_pod(sid: str) -> None:
    """Immediate delete (no grace period); a missing pod is not an error."""
    try:
        core().delete_namespaced_pod(pod_name(sid), NS, grace_period_seconds=0)
    except ApiException as e:
        if e.status != 404:
            raise


def exec_(sid: str, cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    """Runs a command in the sandbox. Output is untrusted data from a possibly compromised pod.

    Uses its own ApiClient: kubernetes.stream.stream() works by swapping the client's `request` method
    for a websocket one while it runs. On the shared client that would send other threads' ordinary
    calls (reconciler, other requests) down the websocket path, and a failed exec could leave the
    shared client swapped for good."""
    core()                                                      # ensure the in-cluster config is loaded
    resp = stream(client.CoreV1Api(client.ApiClient()).connect_get_namespaced_pod_exec, pod_name(sid), NS,
                  command=cmd, container="agent",
                  stderr=True, stdin=False, stdout=True, tty=False, _preload_content=False)
    resp.run_forever(timeout=timeout)
    out, err = resp.read_stdout() or "", resp.read_stderr() or ""
    rc = resp.returncode
    resp.close()
    return (rc if rc is not None else -1), out, err


def logs(sid: str, follow: bool, tail: int | None = None):
    """Raw (unpreloaded) log response for the agent container: untrusted pod stdout."""
    return core().read_namespaced_pod_log(pod_name(sid), NS, container="agent", follow=follow,
                                          tail_lines=tail, _preload_content=False)


def quarantine(sid: str) -> None:
    """Per-session Cilium deny policy. Deny rules override allows; measured <=1s to take
    effect (vs ~45s for relabelling, which forces a new security identity)."""
    core()   # ensure in-cluster config is loaded before using other API groups
    body = {
        "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
        "metadata": {"name": f"quarantine-{sid}", "namespace": NS, "labels": {"sbx/session": sid}},
        "spec": {"endpointSelector": {"matchLabels": {"sbx/session": sid}},
                 "egressDeny": [{"toEntities": ["all"]}], "ingressDeny": [{"fromEntities": ["all"]}]},
    }
    try:
        client.CustomObjectsApi().create_namespaced_custom_object("cilium.io", "v2", NS, "ciliumnetworkpolicies", body)
    except ApiException as e:
        if e.status != 409:
            raise
    try:
        core().patch_namespaced_pod(pod_name(sid), NS, {"metadata": {"labels": {"sbx/state": "contained"}}})
    except ApiException as e:
        if e.status != 404:
            raise


FREEZE_POLICY = "freeze-all-sessions"


def freeze_all() -> None:
    """Fleet kill switch: one deny policy selecting every endpoint in sbx-sessions."""
    core()   # ensure in-cluster config is loaded
    body = {"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
            "metadata": {"name": FREEZE_POLICY, "namespace": NS},
            "spec": {"endpointSelector": {}, "egressDeny": [{"toEntities": ["all"]}],
                     "ingressDeny": [{"fromEntities": ["all"]}]}}
    try:
        client.CustomObjectsApi().create_namespaced_custom_object("cilium.io", "v2", NS, "ciliumnetworkpolicies", body)
    except ApiException as e:
        if e.status != 409:
            raise


def unfreeze_all() -> None:
    """Removes the fleet deny policy; per-session quarantines stay in place."""
    core()
    try:
        client.CustomObjectsApi().delete_namespaced_custom_object("cilium.io", "v2", NS, "ciliumnetworkpolicies", FREEZE_POLICY)
    except ApiException as e:
        if e.status != 404:
            raise


def unquarantine(sid: str) -> None:
    """Removes a session's quarantine policy (on destroy, or for an orphan pod)."""
    core()
    try:
        client.CustomObjectsApi().delete_namespaced_custom_object("cilium.io", "v2", NS, "ciliumnetworkpolicies",
                                                                  f"quarantine-{sid}")
    except ApiException as e:
        if e.status != 404:
            raise


def session_pods() -> list[tuple[str, str]]:
    """(session id, pod name) for every pod in sbx-sessions carrying a session label."""
    pods = core().list_namespaced_pod(NS, label_selector="sbx/session").items
    return [(p.metadata.labels["sbx/session"], p.metadata.name) for p in pods]


def pod_snapshot(sid: str) -> dict:
    """The full pod object as JSON-serialisable data, for forensics."""
    pod = core().read_namespaced_pod(pod_name(sid), NS)
    return client.ApiClient().sanitize_for_serialization(pod)
