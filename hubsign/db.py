"""One interface over SQLite (single node) and PostgreSQL (several nodes). Rows come back as dicts.

Autocommit everywhere: each statement is its own transaction, so correctness relies on conditional UPDATEs
(`... WHERE status='sent'` and checking the affected row count), never on read-then-write.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  pw_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS orgs(id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memberships(org_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY(org_id, user_id));
CREATE TABLE IF NOT EXISTS invites(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL,
  token_hash TEXT UNIQUE NOT NULL, invited_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, accepted_at TEXT);
CREATE TABLE IF NOT EXISTS api_keys(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, created_by TEXT NOT NULL, name TEXT NOT NULL,
  mode TEXT NOT NULL, role TEXT NOT NULL, prefix TEXT NOT NULL, hash TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL,
  last_used_at TEXT, revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS envelopes(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, created_by TEXT NOT NULL, mode TEXT NOT NULL,
  subject TEXT NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL, sequential INTEGER NOT NULL, doc_name TEXT NOT NULL,
  doc_sha256 TEXT NOT NULL, pages INTEGER NOT NULL, final_sha256 TEXT, metadata TEXT NOT NULL, created_at TEXT NOT NULL,
  sent_at TEXT, completed_at TEXT, updated_at TEXT NOT NULL, parts TEXT NOT NULL DEFAULT '[]',
  allow_reassign INTEGER NOT NULL DEFAULT 0, reply_to TEXT, sender_name TEXT);
CREATE INDEX IF NOT EXISTS ix_env_org ON envelopes(org_id, mode, updated_at);
CREATE TABLE IF NOT EXISTS recipients(id TEXT PRIMARY KEY, envelope_id TEXT NOT NULL, idx INTEGER NOT NULL, name TEXT NOT NULL,
  email TEXT NOT NULL, phone TEXT, role TEXT NOT NULL, routing_order INTEGER NOT NULL, token TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL, signed_at TEXT, sign_ip TEXT, auth_method TEXT NOT NULL, auth_secret TEXT, verified_at TEXT,
  session_hash TEXT, session_expires TEXT, embedded INTEGER NOT NULL DEFAULT 0, return_url TEXT);
CREATE INDEX IF NOT EXISTS ix_rcp_env ON recipients(envelope_id);
CREATE TABLE IF NOT EXISTS otps(recipient_id TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires_at TEXT NOT NULL,
  attempts INTEGER NOT NULL, sent_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS fields(id TEXT PRIMARY KEY, envelope_id TEXT NOT NULL, recipient_id TEXT NOT NULL, type TEXT NOT NULL,
  page INTEGER NOT NULL, x DOUBLE PRECISION, y DOUBLE PRECISION, w DOUBLE PRECISION, h DOUBLE PRECISION,
  required INTEGER NOT NULL, label TEXT NOT NULL, value TEXT, locked INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_fld_env ON fields(envelope_id);
CREATE TABLE IF NOT EXISTS events(id {AUTOID}, envelope_id TEXT NOT NULL, ts TEXT NOT NULL,
  type TEXT NOT NULL, actor TEXT NOT NULL, ip TEXT, ua TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_events_env ON events(envelope_id);
CREATE TABLE IF NOT EXISTS templates(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, created_by TEXT NOT NULL, mode TEXT NOT NULL,
  name TEXT NOT NULL, description TEXT NOT NULL, doc_name TEXT NOT NULL, pages INTEGER NOT NULL, roles TEXT NOT NULL,
  fields TEXT NOT NULL, sequential INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS webhooks(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, created_by TEXT NOT NULL, mode TEXT NOT NULL,
  url TEXT NOT NULL, secret TEXT NOT NULL, events TEXT NOT NULL, active INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS deliveries(id TEXT PRIMARY KEY, webhook_id TEXT NOT NULL, event TEXT NOT NULL, payload TEXT NOT NULL,
  status TEXT NOT NULL, attempts INTEGER NOT NULL, http_status INTEGER, response TEXT, created_at TEXT NOT NULL,
  last_at TEXT, next_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_del_wh ON deliveries(webhook_id, created_at);
CREATE INDEX IF NOT EXISTS ix_del_due ON deliveries(status, next_at);
CREATE TABLE IF NOT EXISTS batches(id TEXT PRIMARY KEY, org_id TEXT NOT NULL, created_by TEXT NOT NULL, mode TEXT NOT NULL,
  template_id TEXT NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL, send INTEGER NOT NULL, total INTEGER NOT NULL,
  done INTEGER NOT NULL, failed INTEGER NOT NULL, status TEXT NOT NULL, rows TEXT NOT NULL, errors TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS blobs(k TEXT PRIMARY KEY, data {BLOB} NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rate_limits(k TEXT NOT NULL, w BIGINT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY(k, w));
"""


class Database:
    def __init__(self, target: str | Path, schema: str | None = None):
        """`target` is a postgresql:// URL or a SQLite file path. `schema` isolates a Postgres tenant (tests)."""
        self.pg = str(target).startswith(("postgres://", "postgresql://"))
        if self.pg:
            import psycopg
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool

            if schema:
                with psycopg.connect(str(target), autocommit=True) as c:
                    c.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
            opts = {"autocommit": True, "row_factory": dict_row}
            if schema:
                opts["options"] = f'-c search_path="{schema}"'
            # a serverless Postgres (Neon) drops idle connections: test one before handing it out, and recycle old ones
            self.pool = ConnectionPool(str(target), kwargs=opts, min_size=1, max_size=10, open=True,
                                       check=ConnectionPool.check_connection, max_lifetime=1800, reconnect_timeout=30)  # fmt: skip
            auto, blob = "BIGSERIAL PRIMARY KEY", "BYTEA"
        else:
            Path(target).parent.mkdir(parents=True, exist_ok=True)
            self.c = sqlite3.connect(str(target), check_same_thread=False, isolation_level=None)
            self.c.row_factory = sqlite3.Row
            self.c.execute("PRAGMA journal_mode=WAL")
            self.c.execute("PRAGMA busy_timeout=5000")
            self.lock = threading.RLock()
            auto, blob = "INTEGER PRIMARY KEY AUTOINCREMENT", "BLOB"
        for stmt in SCHEMA.replace("{AUTOID}", auto).replace("{BLOB}", blob).split(";"):
            if stmt.strip():
                self.x(stmt)

    def _run(self, sql: str, args: tuple):
        if self.pg:
            with self.pool.connection() as conn:
                cur = conn.execute(sql.replace("?", "%s"), args)
                return (cur.fetchall() if cur.description else []), cur.rowcount
        with self.lock:
            cur = self.c.execute(sql, args)
            rows = [dict(r) for r in cur.fetchall()] if cur.description else []
            return rows, cur.rowcount

    def q(self, sql: str, args: tuple = ()) -> list[dict]:
        return self._run(sql, args)[0]

    def one(self, sql: str, args: tuple = ()) -> dict | None:
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args: tuple = ()) -> int:
        """Execute a write; returns rows affected. Check it: 0 means a conditional UPDATE lost the race."""
        return self._run(sql, args)[1]

    def hit(self, key: str, limit: int, window_s: int) -> tuple[bool, int, int]:
        """Fixed-window counter shared by every node. -> (allowed, remaining, seconds until reset)."""
        now = time.time()
        w = int(now // window_s)
        rows = self.q(
            "INSERT INTO rate_limits(k,w,n) VALUES(?,?,1) ON CONFLICT(k,w) DO UPDATE SET n=rate_limits.n+1 RETURNING n",
            (key, w),
        )
        n = rows[0]["n"]
        if n == 1 and int(now) % 7 == 0:  # opportunistic cleanup of expired windows
            self.x("DELETE FROM rate_limits WHERE w < ?", (w - 2,))
        return n <= limit, max(limit - n, 0), int((w + 1) * window_s - now) + 1

    def reset_hits(self, key: str) -> None:
        self.x("DELETE FROM rate_limits WHERE k=?", (key,))

    def close(self) -> None:
        if self.pg:
            self.pool.close()
        else:
            self.c.close()
