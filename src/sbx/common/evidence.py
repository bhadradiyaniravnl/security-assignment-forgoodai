"""Append-only, hash-chained evidence log.

Each component writes its own file (<dir>/<component>.jsonl, dir from EVIDENCE_DIR). Every
event carries seq, prev_hash and hash = sha256(prev_hash + canonical event), so truncation or
edits are detectable by re-walking the chain (verify_chain here, and the sentinel's EV rule).

Trust: the chain detects tampering after the fact; it does not stop a compromised writer from
omitting events. Omission is caught elsewhere (the sentinel's S1 rule compares the gateway's
log against Hubble flows). Sandboxes never mount this volume.
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
    """One component's hash-chained log. Resumes the chain from the existing file on start."""

    def __init__(self, component: str, directory: str | None = None):
        self.component = component
        self.path = os.path.join(directory or os.environ.get("EVIDENCE_DIR", "/evidence"), f"{component}.jsonl")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._lock = threading.Lock()   # writes are short; safe from both threads and the event loop
        self.seq, self.prev_hash = self._read_chain_head()

    def _read_chain_head(self) -> tuple[int, str]:
        """(seq, hash) of the last event on disk, or (0, GENESIS) for a new log."""
        seq, prev = 0, GENESIS
        if os.path.exists(self.path):
            with open(self.path) as f:
                for line in f:
                    if line.strip():
                        event = json.loads(line)
                        seq, prev = event["seq"], event["hash"]
        return seq, prev

    def write_sync(self, action: str, **fields) -> dict:
        """Append one event (fsynced before returning) and return it with seq and hash."""
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
        """Async wrapper for callers on the event loop; the write itself is synchronous."""
        return self.write_sync(action, **fields)


def verify_chain(path: str) -> tuple[bool, int, str]:
    """Re-walk a log file's hash chain. Returns (ok, events_checked, error)."""
    prev, checked = GENESIS, 0
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            event = json.loads(line)
            claimed = event.pop("hash")
            if event.get("prev_hash") != prev or _digest(prev, event) != claimed or event.get("seq") != checked + 1:
                return False, checked, f"chain broken at seq {event.get('seq')}"
            prev, checked = claimed, checked + 1
    return True, checked, ""
