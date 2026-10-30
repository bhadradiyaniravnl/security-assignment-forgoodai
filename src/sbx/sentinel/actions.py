"""Sentinel response actions and Kubernetes reads.

Uses the sentinel's OWN service account (Cilium policies in sbx-sessions, pod list, its own ConfigMap;
no exec, no Secrets), so containment works even if the control plane is down or compromised.
  quarantine / release   per-session deny-all CiliumNetworkPolicy sentinel-q-<sid>
  freeze / unfreeze      fleet-wide deny-all CiliumNetworkPolicy sentinel-freeze
  read_policy            the detection-policy ConfigMap sentinel-detection
Deny rules override any allow the platform adds, and an admission policy stops anyone else deleting
them. All calls are blocking; main.py runs them in a thread."""
from __future__ import annotations

from kubernetes import client, config
from kubernetes.client.rest import ApiException

SESSIONS = "sbx-sessions"
SECURITY = "sbx-security"
POLICY_CM, POLICY_KEY = "sentinel-detection", "detection.yaml"
MANAGED = {"app.kubernetes.io/managed-by": "sentinel"}
FREEZE = "sentinel-freeze"
_api: client.CustomObjectsApi | None = None
_core: client.CoreV1Api | None = None


def _crd() -> client.CustomObjectsApi:
    """Lazily load the in-cluster config and both API clients; returns the custom-objects client."""
    global _api, _core
    if _api is None:
        config.load_incluster_config()
        _api, _core = client.CustomObjectsApi(), client.CoreV1Api()
    return _api


def _deny(name: str, selector: dict, labels: dict) -> dict:
    """A deny-all (egress and ingress) CiliumNetworkPolicy for the pods `selector` matches (all if empty)."""
    return {"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
            "metadata": {"name": name, "namespace": SESSIONS, "labels": {**MANAGED, **labels}},
            "spec": {"endpointSelector": {"matchLabels": selector} if selector else {},
                     "egressDeny": [{"toEntities": ["all"]}], "ingressDeny": [{"fromEntities": ["all"]}]}}


def _create(body: dict) -> bool:
    """Create the policy; False if it already exists."""
    try:
        _crd().create_namespaced_custom_object("cilium.io", "v2", SESSIONS, "ciliumnetworkpolicies", body)
        return True
    except ApiException as e:
        if e.status == 409:
            return False
        raise


def _delete(name: str) -> bool:
    """Delete the policy; False if it was already gone."""
    try:
        _crd().delete_namespaced_custom_object("cilium.io", "v2", SESSIONS, "ciliumnetworkpolicies", name)
        return True
    except ApiException as e:
        if e.status == 404:
            return False
        raise


def quarantine(sid: str) -> bool:
    return _create(_deny(f"sentinel-q-{sid}", {"sbx/session": sid}, {"sbx/session": sid}))


def release(sid: str) -> bool:
    return _delete(f"sentinel-q-{sid}")


def freeze() -> bool:
    return _create(_deny(FREEZE, {}, {}))


def unfreeze() -> bool:
    return _delete(FREEZE)


def quarantined_sessions() -> set[str]:
    """Session ids that currently have a sentinel quarantine policy."""
    items = _crd().list_namespaced_custom_object("cilium.io", "v2", SESSIONS, "ciliumnetworkpolicies",
                                                 label_selector="app.kubernetes.io/managed-by=sentinel")["items"]
    return {i["metadata"]["labels"]["sbx/session"] for i in items if "sbx/session" in i["metadata"].get("labels", {})}


def live_sessions() -> set[str]:
    """Session ids that still have a sandbox pod."""
    _crd()                                                       # ensures _core is initialised
    pods = _core.list_namespaced_pod(SESSIONS, label_selector="sbx/session").items
    return {p.metadata.labels["sbx/session"] for p in pods}


def read_policy() -> tuple[str, str] | None:
    """(resourceVersion, policy YAML) from the sentinel's own ConfigMap, or None if it doesn't exist."""
    _crd()
    try:
        cm = _core.read_namespaced_config_map(POLICY_CM, SECURITY)
    except ApiException as e:
        if e.status == 404:
            return None
        raise
    return cm.metadata.resource_version, (cm.data or {}).get(POLICY_KEY, "")
