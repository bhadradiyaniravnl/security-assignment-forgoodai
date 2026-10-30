"""Service-to-service auth inside sbx-system (prototype: one key per component; production: mTLS/SPIFFE).

Each component sends its OWN key (SBX_INTERNAL_KEY). Receivers know the keys of the callers they
accept (SBX_KEY_<COMPONENT>) and authorise per endpoint, so a compromised gateway cannot use
sentinel-only endpoints, and the sentinel cannot validate tokens or reach credproxy."""
from __future__ import annotations

import hmac
import os

HEADER = "X-Sbx-Internal"
CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://control-plane.sbx-system.svc:8000")
CREDPROXY_URL = os.environ.get("CREDPROXY_URL", "http://credproxy.sbx-system.svc:9000")
CREDPROXY_TUNNEL = (os.environ.get("CREDPROXY_TUNNEL_HOST", "credproxy.sbx-system.svc"),
                    int(os.environ.get("CREDPROXY_TUNNEL_PORT", "9001")))


def key() -> str:
    k = os.environ.get("SBX_INTERNAL_KEY", "")
    if len(k) < 32:
        raise RuntimeError("SBX_INTERNAL_KEY missing or too short")
    return k


def headers() -> dict:
    return {HEADER: key()}


COMPONENTS = ("gateway", "credproxy", "sentinel")


def caller(value: str | None) -> str | None:
    """Which component presented this key (None if unknown)."""
    if not value:
        return None
    for name in COMPONENTS:
        k = os.environ.get(f"SBX_KEY_{name.upper()}", "")
        if len(k) >= 32 and hmac.compare_digest(value, k):
            return name
    return None
