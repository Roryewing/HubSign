"""SQLite with a lock. One connection, rows as dicts. Fine for a single node; swap for Postgres to scale out."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  pw_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_keys(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, mode TEXT NOT NULL,
  prefix TEXT NOT NULL, hash TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, last_used_at TEXT, revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS envelopes(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, mode TEXT NOT NULL, subject TEXT NOT NULL,
  message TEXT NOT NULL, status TEXT NOT NULL, sequential INTEGER NOT NULL, doc_name TEXT NOT NULL, doc_sha256 TEXT NOT NULL,
  pages INTEGER NOT NULL, final_sha256 TEXT, metadata TEXT NOT NULL, created_at TEXT NOT NULL, sent_at TEXT,
  completed_at TEXT, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_env_user ON envelopes(user_id, mode, created_at);
CREATE TABLE IF NOT EXISTS recipients(id TEXT PRIMARY KEY, envelope_id TEXT NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL,
  role TEXT NOT NULL, routing_order INTEGER NOT NULL, token TEXT UNIQUE NOT NULL, status TEXT NOT NULL,
  signed_at TEXT, sign_ip TEXT);
CREATE TABLE IF NOT EXISTS fields(id TEXT PRIMARY KEY, envelope_id TEXT NOT NULL, recipient_id TEXT NOT NULL, type TEXT NOT NULL,
  page INTEGER NOT NULL, x REAL, y REAL, w REAL, h REAL, required INTEGER NOT NULL, label TEXT NOT NULL, value TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, envelope_id TEXT NOT NULL, ts TEXT NOT NULL,
  type TEXT NOT NULL, actor TEXT NOT NULL, ip TEXT, ua TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_events_env ON events(envelope_id);
CREATE TABLE IF NOT EXISTS templates(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, mode TEXT NOT NULL, name TEXT NOT NULL,
  description TEXT NOT NULL, doc_name TEXT NOT NULL, pages INTEGER NOT NULL, roles TEXT NOT NULL, fields TEXT NOT NULL,
  sequential INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS webhooks(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, mode TEXT NOT NULL, url TEXT NOT NULL,
  secret TEXT NOT NULL, events TEXT NOT NULL, active INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS deliveries(id TEXT PRIMARY KEY, webhook_id TEXT NOT NULL, event TEXT NOT NULL, payload TEXT NOT NULL,
  status TEXT NOT NULL, attempts INTEGER NOT NULL, http_status INTEGER, response TEXT, created_at TEXT NOT NULL, last_at TEXT);
CREATE INDEX IF NOT EXISTS ix_del_wh ON deliveries(webhook_id, created_at);
"""


class Database:
    def __init__(self, path: Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.c = sqlite3.connect(str(path), check_same_thread=False)
        self.c.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.c.executescript(SCHEMA)

    def q(self, sql: str, args: tuple = ()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.c.execute(sql, args).fetchall()]

    def one(self, sql: str, args: tuple = ()) -> dict | None:
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args: tuple = ()) -> int:
        """Execute a write; returns rows affected."""
        with self.lock:
            n = self.c.execute(sql, args).rowcount
            self.c.commit()
            return n
