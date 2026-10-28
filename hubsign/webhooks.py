"""Signed webhook delivery. Deliveries are rows in the database, drained by a worker with retries, so they
survive restarts and work with several nodes (each attempt is claimed with a conditional UPDATE)."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta

import httpx

from . import security
from .config import Settings
from .db import Database

EVENTS = [
    "envelope.sent",
    "envelope.completed",
    "envelope.declined",
    "envelope.voided",
    "recipient.sent",
    "recipient.viewed",
    "recipient.signed",
    "recipient.declined",
    "recipient.reassigned",
    "recipient.auth_failed",
]


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def http_send(url: str, headers: dict, body: bytes) -> tuple[int, str]:
    r = httpx.post(url, content=body, headers=headers, timeout=10, follow_redirects=False)
    return r.status_code, r.text[:500]


class Webhooks:
    def __init__(self, db: Database, settings: Settings, sender=http_send):
        self.db, self.s, self.sender = db, settings, sender

    def emit(self, org_id: str, mode: str, event: str, data: dict) -> None:
        payload = {"id": "evt_" + secrets.token_hex(8), "type": event, "created": now(), "mode": mode, "data": data}
        for wh in self.db.q("SELECT * FROM webhooks WHERE org_id=? AND mode=? AND active=1", (org_id, mode)):
            wanted = json.loads(wh["events"])
            if wanted and event not in wanted:
                continue
            self.queue(wh["id"], event, payload)

    def queue(self, webhook_id: str, event: str, payload: dict) -> str:
        did = "del_" + secrets.token_hex(8)
        t = now()
        self.db.x(
            "INSERT INTO deliveries(id,webhook_id,event,payload,status,attempts,created_at,next_at) VALUES(?,?,?,?,?,?,?,?)",
            (did, webhook_id, event, json.dumps(payload), "pending", 0, t, t),
        )
        if self.s.webhooks_inline:  # tests: run the whole retry schedule now
            while (d := self.db.one("SELECT status FROM deliveries WHERE id=?", (did,))) and d["status"] in (
                "pending",
                "retrying",
            ):
                self.attempt(did)
        return did

    def process_due(self, limit: int = 20) -> int:
        stale = (datetime.now(UTC) - timedelta(minutes=5)).isoformat(timespec="microseconds")
        self.db.x(
            "UPDATE deliveries SET status='retrying' WHERE status='sending' AND last_at < ?", (stale,)
        )  # crashed worker
        due = self.db.q(
            "SELECT id FROM deliveries WHERE status IN ('pending','retrying') AND next_at <= ? ORDER BY next_at LIMIT ?",
            (now(), limit),
        )
        return sum(self.attempt(d["id"]) for d in due)

    def attempt(self, did: str) -> bool:
        """One delivery attempt. False if another worker claimed it first."""
        if not self.db.x(
            "UPDATE deliveries SET status='sending', last_at=? WHERE id=? AND status IN ('pending','retrying')",
            (now(), did),
        ):
            return False
        d = self.db.one("SELECT * FROM deliveries WHERE id=?", (did,))
        wh = self.db.one("SELECT * FROM webhooks WHERE id=?", (d["webhook_id"],))
        if not wh:
            self.db.x("UPDATE deliveries SET status='failed', response='webhook deleted' WHERE id=?", (did,))
            return True
        body = d["payload"].encode()
        status, text = 0, ""
        bad = security.url_is_safe(wh["url"], self.s.allow_private_webhooks)
        if bad:
            text = bad
        else:
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "HubSign-Webhooks/1",
                "HubSign-Event": d["event"],
                "HubSign-Delivery": did,
                "HubSign-Signature": security.sign_webhook(wh["secret"], body),
            }
            try:
                status, text = self.sender(wh["url"], headers, body)
            except Exception as e:  # network errors are a normal failure, not a crash
                text = f"{type(e).__name__}: {e}"[:500]
        tries = d["attempts"] + 1
        delays = self.s.webhook_retry_delays
        if 200 <= status < 300:
            new, nxt = "delivered", d["next_at"]
        elif bad or tries > len(delays):
            new, nxt = "failed", d["next_at"]
        else:
            new = "retrying"
            nxt = (datetime.now(UTC) + timedelta(seconds=delays[tries - 1])).isoformat(timespec="microseconds")
        self.db.x(
            "UPDATE deliveries SET status=?, attempts=?, http_status=?, response=?, last_at=?, next_at=? WHERE id=?",
            (new, tries, status, text, now(), nxt, did),
        )
        return True
