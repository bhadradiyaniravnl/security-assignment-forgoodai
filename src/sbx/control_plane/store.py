"""Session registry (SQLite). Tokens are stored only as sha256 hashes."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
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
"""


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    def __init__(self, path: str = DB_PATH):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        try:   # lightweight migration for registries created before follow-up messages existed
            self.db.execute("ALTER TABLE sessions ADD COLUMN turns INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass

    def create(self, *, session_id: str, user: str, spec_name: str, spec_digest: str, token: str,
               policy: dict, canaries: list, params: dict | None = None, pod_name: str | None = None,
               pod_ip: str | None = None, state: str = "creating") -> None:
        self.db.execute(
            "INSERT INTO sessions (session_id,user,spec_name,spec_digest,params,pod_name,pod_ip,token_hash,"
            "policy,canaries,state,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (session_id, user, spec_name, spec_digest, json.dumps(params or {}), pod_name, pod_ip,
             token_hash(token), json.dumps(policy), json.dumps(canaries), state, time.time()))

    def update(self, session_id: str, **fields) -> None:
        if "ended" in fields:
            fields.pop("ended")
            fields["ended_at"] = time.time()
        cols = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(f"UPDATE sessions SET {cols} WHERE session_id=?", (*fields.values(), session_id))

    def get(self, session_id: str) -> dict | None:
        row = self.db.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        return _row(row)

    def by_token(self, token: str) -> dict | None:
        row = self.db.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash(token),)).fetchone()
        return _row(row)

    def add_spec(self, name: str, version: int, digest: str, body: bytes, by: str, warnings: list) -> None:
        self.db.execute("INSERT INTO specs VALUES (?,?,?,?,?,?,?)",
                        (name, version, digest, body, by, json.dumps(warnings), time.time()))

    def latest_spec(self, name: str) -> dict | None:
        row = self.db.execute("SELECT * FROM specs WHERE name=? ORDER BY version DESC LIMIT 1", (name,)).fetchone()
        return dict(row) if row else None

    def list_specs(self) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT name, version, digest, registered_by, warnings, registered_at FROM specs ORDER BY name, version")]

    def list(self) -> list[dict]:
        return [_row(r) for r in self.db.execute("SELECT * FROM sessions ORDER BY created_at DESC")]


def _row(row) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    for k in ("params", "policy", "canaries"):
        d[k] = json.loads(d[k])
    d.pop("token_hash", None)
    return d
