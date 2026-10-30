"""Session policy lookups shared by the gateway, credproxy and sentinel.

- normalize_host / host_allowed: the one allowlist comparison used by every enforcement point, so
  the gateway and credproxy cannot disagree about whether a destination is in the spec.
- ControlPlane: client for the control plane's internal API (token validation, compiled session
  policy). The control plane is the source of truth; answers are cached for `ttl` seconds, which
  bounds how long a revoked session can keep working. Any failure to reach it is answered as 503,
  so callers fail closed.
"""
from __future__ import annotations

import time

import aiohttp

from sbx.common import internal

_SUFFIXES = (".svc.cluster.local", ".svc")


def normalize_host(host: str) -> str:
    """Lower-case, drop the trailing dot and the in-cluster service suffix (svc / svc.cluster.local)."""
    host = host.lower().rstrip(".")
    for suffix in _SUFFIXES:
        if host.endswith(suffix):
            return host[: -len(suffix)]
    return host


def host_allowed(host: str, allow: list[str]) -> bool:
    """Exact match after normalization. No wildcards (the spec baseline forbids them)."""
    return normalize_host(host) in {normalize_host(a) for a in allow}


class ControlPlane:
    """Validation and policy lookups with a short cache (TTL bounds revocation latency)."""

    def __init__(self, ttl: float = 1.0):
        self.ttl = ttl
        self._cache: dict[tuple, tuple[float, int, dict]] = {}
        self._http: aiohttp.ClientSession | None = None

    async def _get_http(self) -> aiohttp.ClientSession:
        if self._http is None:
            self._http = aiohttp.ClientSession(headers=internal.headers(), timeout=aiohttp.ClientTimeout(total=5))
        return self._http

    async def _cached(self, key: tuple, method: str, path: str, json_body: dict | None = None,
                      fresh: bool = False) -> tuple[int, dict]:
        hit = self._cache.get(key)
        if hit and not fresh and time.monotonic() - hit[0] < self.ttl:
            return hit[1], hit[2]
        http = await self._get_http()
        try:
            async with http.request(method, internal.CONTROL_PLANE_URL + path, json=json_body) as r:
                status, body = r.status, await r.json()
        except (aiohttp.ClientError, TimeoutError, ValueError):
            return 503, {"detail": "control plane unavailable"}       # fail closed, never cached
        self._cache[key] = (time.monotonic(), status, body)
        return status, body

    async def validate(self, token: str, ip: str) -> tuple[int, dict]:
        """Check a session token presented from `ip` (tokens are bound to the pod IP)."""
        return await self._cached(("v", token, ip), "POST", "/internal/validate", {"token": token, "ip": ip})

    async def policy(self, session_id: str, fresh: bool = False) -> tuple[int, dict]:
        """Compiled policy, state and canaries for a session.

        fresh=True skips the cache: used for rare, high-impact operations (GitHub clone/publish)."""
        return await self._cached(("p", session_id), "GET", f"/internal/policy/{session_id}", fresh=fresh)
