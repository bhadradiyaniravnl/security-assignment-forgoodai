"""State and helpers shared by the gateway's two listeners (ai.py on :8080, egress.py on :3128).

- cp: the cached control-plane client both listeners authenticate sessions and fetch policy with.
- evidence: the gateway's hash-chained evidence log (one writer per process).
- usage: per-session token counts, the input to the token budget check in ai.py.
- session_fields / referenced_hosts / sha256: shared shapes for evidence records.

Everything here describes untrusted sandbox traffic; nothing in this module grants anything.
"""
from __future__ import annotations

import hashlib
import os
import re
import time

from sbx.common.evidence import EvidenceLog
from sbx.common.session_policy import ControlPlane

cp = ControlPlane(ttl=1.0)   # 1 s cache: a revoked session stops working within about a second


class _Evidence:
    """The gateway's evidence log. With SBX_FAULT_INJECTION=1 (test deployments only) it silently drops
    records for sessions listed in /tmp/sbx-fault/drop-sessions: exactly what a compromised gateway could
    do anyway, so the switch adds no capability. It exists to prove that the sentinel's gateway
    completeness rule (S1: Hubble saw more requests than the gateway logged) catches it."""

    def __init__(self, log: EvidenceLog):
        self.log, self._drop_list_read_at, self._drop_sessions = log, 0.0, set()
        self.enabled = os.environ.get("SBX_FAULT_INJECTION") == "1"

    def _should_drop(self, sid) -> bool:
        if not self.enabled or not sid:
            return False
        if time.monotonic() - self._drop_list_read_at > 1:     # re-read the drop list at most once a second
            try:
                with open("/tmp/sbx-fault/drop-sessions") as f:
                    self._drop_sessions = {line.strip() for line in f if line.strip()}
            except OSError:
                self._drop_sessions = set()
            self._drop_list_read_at = time.monotonic()
        return sid in self._drop_sessions

    async def write(self, action: str, **fields) -> dict:
        """Append an evidence event (returns {"seq": -1, "dropped": True} when fault injection drops it)."""
        if self._should_drop(fields.get("session_id")):
            return {"seq": -1, "dropped": True}
        return await self.log.write(action, **fields)


evidence = _Evidence(EvidenceLog("gateway"))
usage: dict[str, int] = {}          # session_id -> tokens consumed (single replica in the prototype)

# Hostnames inside tool input (URLs or bare host.domain). Labels may contain hyphens, e.g. paste-mock.lab-ext.
_URL_HOST = re.compile(r"(?:https?://)?\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+)(?=[:/\s'\"]|$)")


def sha256(data: bytes) -> str:
    """Hex digest; evidence records body hashes, not bodies."""
    return hashlib.sha256(data).hexdigest()


def session_fields(ctx: dict) -> dict:
    """Identity fields (session, user, spec, pod) every per-session evidence event carries."""
    return {"session_id": ctx.get("session_id"), "user": ctx.get("user"), "spec": ctx.get("spec_name"),
            "spec_digest": ctx.get("spec_digest"), "pod": ctx.get("pod_name"), "pod_ip": ctx.get("pod_ip")}


def referenced_hosts(text: str) -> set[str]:
    """Hostnames mentioned in free text (tool_use input), lower-cased.

    Plausible hostnames only: ignore file names like slug.py / test_slug.py and dotted numbers.
    Heuristic by design: the result only annotates evidence, it never allows or blocks anything."""
    out = set()
    for host in _URL_HOST.findall(text):
        host = host.lower()
        tld = host.rsplit(".", 1)[-1]
        if tld in {"py", "md", "txt", "json", "yaml", "yml", "toml", "cfg", "ini", "lock", "sh", "env"} or tld.isdigit():
            continue
        out.add(host)
    return out
