"""Policy helpers shared by the gateway and credproxy, plus a cached control-plane client."""
from __future__ import annotations

import time

import aiohttp

from sbx.common import internal

_SUFFIXES = (".svc.cluster.local", ".svc")


def normalize_host(host: str) -> str:
    host = host.lower().rstrip(".")
    for s in _SUFFIXES:
        if host.endswith(s):
            return host[: -len(s)]
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

    async def _cached(self, key: tuple, method: str, path: str, json_body: dict | None = None) -> tuple[int, dict]:
        hit = self._cache.get(key)
        if hit and time.monotonic() - hit[0] < self.ttl:
            return hit[1], hit[2]
        http = await self._get_http()
        async with http.request(method, internal.CONTROL_PLANE_URL + path, json=json_body) as r:
            status, body = r.status, await r.json()
        self._cache[key] = (time.monotonic(), status, body)
        return status, body

    async def validate(self, token: str, ip: str) -> tuple[int, dict]:
        return await self._cached(("v", token, ip), "POST", "/internal/validate", {"token": token, "ip": ip})

    async def policy(self, session_id: str) -> tuple[int, dict]:
        return await self._cached(("p", session_id), "GET", f"/internal/policy/{session_id}")
