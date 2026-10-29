"""Service-to-service auth inside sbx-system (prototype: shared key; production: mTLS/SPIFFE)."""
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


def check(value: str | None) -> bool:
    return bool(value) and hmac.compare_digest(value, key())
