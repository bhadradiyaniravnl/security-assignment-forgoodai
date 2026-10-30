"""Control-plane state in SQLite: sessions, the spec registry, spec approvals, and a small meta
table (the fleet-freeze flag).

Tokens are stored only as sha256 hashes and never returned. Session state changes that race
(stop, containment, freeze, the reconciler) go through `transition`, a compare-and-set, so an
actor that loses the race sees False instead of overwriting, e.g., 'contained'. One connection is
shared by the API threadpool and the reconciler thread, guarded by a lock.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time

DB_PATH = os.environ.get("CP_DB", "/data/cp.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  session_id   TEXT PRIMARY KEY,
  user         TEXT NOT NULL,
  spec_name    TEXT NOT NULL,
  spec_digest  TEXT NOT NULL,
  params       TEXT NOT NULL DEFAULT '{}',
  pod_name     TEXT,
  pod_ip       TEXT,
  token_hash   TEXT NOT NULL,
  policy       TEXT NOT NULL,
  canaries     TEXT NOT NULL DEFAULT '[]',
  state        TEXT NOT NULL,
  detail       TEXT,
  created_at   REAL NOT NULL,
  ended_at     REAL
);
CREATE TABLE IF NOT EXISTS specs (
  name          TEXT NOT NULL,
  version       INTEGER NOT NULL,
  digest        TEXT NOT NULL,
  body          BLOB NOT NULL,
  registered_by TEXT NOT NULL,
  warnings      TEXT NOT NULL DEFAULT '[]',
  registered_at REAL NOT NULL,
  PRIMARY KEY (name, version)
);
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
  digest      TEXT NOT NULL,
  name        TEXT NOT NULL,
  version     INTEGER NOT NULL,
  approver    TEXT NOT NULL,
  approved_at REAL NOT NULL,
  PRIMARY KEY (digest, approver)
);
"""


def token_hash(token: str) -> str:
    """The stored form of a session token (lookups hash the presented token the same way)."""
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    def __init__(self, path: str = DB_PATH):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.lock = threading.RLock()          # FastAPI threadpool + reconciler share one connection
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        for ddl in ("ALTER TABLE sessions ADD COLUMN turns INTEGER NOT NULL DEFAULT 0",   # lightweight migrations
                    "ALTER TABLE sessions ADD COLUMN scan TEXT NOT NULL DEFAULT '[]'",
                    "ALTER TABLE sessions ADD COLUMN last_activity REAL",
                    "ALTER TABLE sessions ADD COLUMN state_changed_at REAL"):
            try:
                self.db.execute(ddl)
            except sqlite3.OperationalError:
                pass

    def create(self, *, session_id: str, user: str, spec_name: str, spec_digest: str, token: str,
               policy: dict, canaries: list, params: dict | None = None, pod_name: str | None = None,
               pod_ip: str | None = None, state: str = "creating") -> None:
        with self.lock:
            self.db.execute(
            "INSERT INTO sessions (session_id,user,spec_name,spec_digest,params,pod_name,pod_ip,token_hash,"
            "policy,canaries,state,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (session_id, user, spec_name, spec_digest, json.dumps(params or {}), pod_name, pod_ip,
             token_hash(token), json.dumps(policy), json.dumps(canaries), state, time.time()))

    def update(self, session_id: str, **fields) -> None:
        """Unconditional field update; `ended=True` sets ended_at. Use `transition` to change state."""
        if "ended" in fields:
            fields.pop("ended")
            fields["ended_at"] = time.time()
        cols = ", ".join(f"{k}=?" for k in fields)
        with self.lock:
            self.db.execute(f"UPDATE sessions SET {cols} WHERE session_id=?", (*fields.values(), session_id))

    def transition(self, session_id: str, from_states: tuple, to_state: str, **fields) -> bool:
        """Compare-and-set: moves to `to_state` only if the current state is in `from_states`.
        Returns False if another actor (containment, reconciler, stop) got there first."""
        if "ended" in fields:
            fields.pop("ended")
            fields["ended_at"] = time.time()
        fields["state"] = to_state
        fields["state_changed_at"] = time.time()
        cols = ", ".join(f"{k}=?" for k in fields)
        marks = ",".join("?" * len(from_states))
        with self.lock:
            cur = self.db.execute(f"UPDATE sessions SET {cols} WHERE session_id=? AND state IN ({marks})",
                                  (*fields.values(), session_id, *from_states))
            return cur.rowcount == 1

    def get(self, session_id: str) -> dict | None:
        """The session row with JSON columns decoded, or None."""
        with self.lock:
            row = self.db.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        return _decode_row(row)

    def by_token(self, token: str) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash(token),)).fetchone()
        return _decode_row(row)

    def add_spec(self, name: str, version: int, digest: str, body: bytes, by: str, warnings: list) -> None:
        self.db.execute("INSERT INTO specs VALUES (?,?,?,?,?,?,?)",
                        (name, version, digest, body, by, json.dumps(warnings), time.time()))

    def get_meta(self, key: str) -> str | None:
        with self.lock:
            row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str | None) -> None:
        with self.lock:
            if value is None:
                self.db.execute("DELETE FROM meta WHERE key=?", (key,))
            else:
                self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, value))

    def add_approval(self, digest: str, name: str, version: int, approver: str) -> None:
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO approvals VALUES (?,?,?,?,?)",
                            (digest, name, version, approver, time.time()))

    def approvers_of(self, digest: str) -> list[str]:
        with self.lock:
            return [r[0] for r in self.db.execute("SELECT approver FROM approvals WHERE digest=?", (digest,))]

    def latest_spec(self, name: str) -> dict | None:
        """The highest registered version of a spec (raw body and digest), or None."""
        row = self.db.execute("SELECT * FROM specs WHERE name=? ORDER BY version DESC LIMIT 1", (name,)).fetchone()
        return dict(row) if row else None

    def list_specs(self) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT name, version, digest, registered_by, warnings, registered_at FROM specs ORDER BY name, version")]

    def list(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT * FROM sessions ORDER BY created_at DESC").fetchall()
        return [_decode_row(r) for r in rows]


def _decode_row(row) -> dict | None:
    """sqlite Row -> dict with JSON columns decoded and the token hash dropped."""
    if row is None:
        return None
    d = dict(row)
    for k in ("params", "policy", "canaries", "scan"):
        d[k] = json.loads(d[k])
    d.pop("token_hash", None)
    return d
