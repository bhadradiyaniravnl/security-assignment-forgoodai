"""State shared by the gateway listeners."""
from __future__ import annotations

import hashlib
import os
import re
import time

from sbx.common.evidence import EvidenceLog
from sbx.common.policy import ControlPlane

cp = ControlPlane(ttl=1.0)
class _Evidence:
    """The gateway's evidence log. With SBX_FAULT_INJECTION=1 (test deployments only) it silently drops
    records for sessions listed in /tmp/sbx-fault/drop-sessions: exactly what a compromised gateway could
    do anyway, so the switch adds no capability. It exists to prove the sentinel's S1 rule catches it."""

    def __init__(self, log: EvidenceLog):
        self.log, self._at, self._drop = log, 0.0, set()
        self.enabled = os.environ.get("SBX_FAULT_INJECTION") == "1"

    def _dropped(self, sid) -> bool:
        if not self.enabled or not sid:
            return False
        if time.monotonic() - self._at > 1:
            try:
                with open("/tmp/sbx-fault/drop-sessions") as f:
                    self._drop = {line.strip() for line in f if line.strip()}
            except OSError:
                self._drop = set()
            self._at = time.monotonic()
        return sid in self._drop

    async def write(self, action: str, **fields) -> dict:
        if self._dropped(fields.get("session_id")):
            return {"seq": -1, "dropped": True}
        return await self.log.write(action, **fields)


evidence = _Evidence(EvidenceLog("gateway"))
usage: dict[str, int] = {}          # session_id -> tokens consumed (single replica in the prototype)

# Hostnames inside tool input (URLs or bare host.domain). Labels may contain hyphens, e.g. paste-mock.lab-ext.
_URL_HOST = re.compile(r"(?:https?://)?\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+)(?=[:/\s'\"]|$)")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def session_fields(ctx: dict) -> dict:
    return {"session_id": ctx.get("session_id"), "user": ctx.get("user"), "spec": ctx.get("spec_name"),
            "spec_digest": ctx.get("spec_digest"), "pod": ctx.get("pod_name"), "pod_ip": ctx.get("pod_ip")}


def referenced_hosts(text: str) -> set[str]:
    """Plausible hostnames only: ignore file names like slug.py / test_slug.py and dotted numbers."""
    out = set()
    for h in _URL_HOST.findall(text):
        h = h.lower()
        tld = h.rsplit(".", 1)[-1]
        if tld in {"py", "md", "txt", "json", "yaml", "yml", "toml", "cfg", "ini", "lock", "sh", "env"} or tld.isdigit():
            continue
        out.add(h)
    return out
