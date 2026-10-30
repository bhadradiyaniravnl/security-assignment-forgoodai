"""SQLite storage for items."""
import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.environ.get("ITEMS_DB", "items.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    description TEXT,
    price       REAL NOT NULL,
    quantity    INTEGER NOT NULL DEFAULT 0
);
"""


def init_db(path: str = DB_PATH) -> None:
    with connect(path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def connect(path: str = DB_PATH):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
