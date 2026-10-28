"""Signed webhook delivery with retries and a delivery log."""

from __future__ import annotations

import json
import secrets
import threading
import time
from datetime import UTC, datetime

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
]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def http_send(url: str, headers: dict, body: bytes) -> tuple[int, str]:
    r = httpx.post(url, content=body, headers=headers, timeout=10, follow_redirects=False)
    return r.status_code, r.text[:500]


class Webhooks:
    def __init__(self, db: Database, settings: Settings, sender=http_send):
        self.db, self.s, self.sender = db, settings, sender

    def emit(self, user_id: str, mode: str, event: str, data: dict) -> None:
        payload = {"id": "evt_" + secrets.token_hex(8), "type": event, "created": _now(), "mode": mode, "data": data}
        for wh in self.db.q("SELECT * FROM webhooks WHERE user_id=? AND mode=? AND active=1", (user_id, mode)):
            wanted = json.loads(wh["events"])
            if wanted and event not in wanted:
                continue
            self.queue(wh["id"], event, payload)

    def queue(self, webhook_id: str, event: str, payload: dict) -> str:
        did = "del_" + secrets.token_hex(8)
        self.db.x(
            "INSERT INTO deliveries(id,webhook_id,event,payload,status,attempts,created_at) VALUES(?,?,?,?,?,?,?)",
            (did, webhook_id, event, json.dumps(payload), "pending", 0, _now()),
        )
        if self.s.webhooks_inline:
            self.deliver(did)
        else:
            threading.Thread(target=self.deliver, args=(did,), daemon=True).start()
        return did

    def deliver(self, did: str) -> None:
        d = self.db.one("SELECT * FROM deliveries WHERE id=?", (did,))
        wh = d and self.db.one("SELECT * FROM webhooks WHERE id=?", (d["webhook_id"],))
        if not wh:
            return
        body = d["payload"].encode()
        delays = [0.0, *self.s.webhook_retry_delays]
        for attempt, delay in enumerate(delays, start=1):
            time.sleep(delay)
            status, text = 0, ""
            bad = security.url_is_safe(wh["url"], self.s.allow_private_webhooks)
            if bad:
                status, text = 0, bad
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
            ok = 200 <= status < 300
            self.db.x(
                "UPDATE deliveries SET status=?, attempts=?, http_status=?, response=?, last_at=? WHERE id=?",
                (
                    "delivered" if ok else ("failed" if bad or attempt == len(delays) else "retrying"),
                    attempt,
                    status,
                    text,
                    _now(),
                    did,
                ),
            )
            if ok or bad:
                return
