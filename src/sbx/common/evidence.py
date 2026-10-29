"""Append-only, hash-chained evidence log.

Each component writes its own file (<dir>/<component>.jsonl). Every event carries
seq, prev_hash and hash = sha256(prev_hash + canonical event), so truncation or
edits are detectable by re-walking the chain. Sandboxes never mount this volume.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time

GENESIS = "0" * 64


def _digest(prev_hash: str, event: dict) -> str:
    body = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


class EvidenceLog:
    def __init__(self, component: str, directory: str | None = None):
        self.component = component
        self.path = os.path.join(directory or os.environ.get("EVIDENCE_DIR", "/evidence"), f"{component}.jsonl")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._lock = threading.Lock()   # writes are short; safe from both threads and the event loop
        self.seq, self.prev_hash = self._tail()

    def _tail(self) -> tuple[int, str]:
        seq, prev = 0, GENESIS
        if os.path.exists(self.path):
            with open(self.path) as f:
                for line in f:
                    if line.strip():
                        e = json.loads(line)
                        seq, prev = e["seq"], e["hash"]
        return seq, prev

    def write_sync(self, action: str, **fields) -> dict:
        with self._lock:
            event = {"ts": time.time(), "seq": self.seq + 1, "component": self.component,
                     "action": action, **fields, "prev_hash": self.prev_hash}
            event["hash"] = _digest(self.prev_hash, event)
            with open(self.path, "a") as f:
                f.write(json.dumps(event, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self.seq, self.prev_hash = event["seq"], event["hash"]
            return event

    async def write(self, action: str, **fields) -> dict:
        return self.write_sync(action, **fields)


def verify_chain(path: str) -> tuple[bool, int, str]:
    """Returns (ok, events_checked, error)."""
    prev, n = GENESIS, 0
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            claimed = e.pop("hash")
            if e.get("prev_hash") != prev or _digest(prev, e) != claimed or e.get("seq") != n + 1:
                return False, n, f"chain broken at seq {e.get('seq')}"
            prev, n = claimed, n + 1
    return True, n, ""
