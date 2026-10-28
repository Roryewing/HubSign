"""Small Python client for the HubSign API, plus webhook signature verification."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from pathlib import Path

import httpx


def verify_signature(secret: str, header: str, body: bytes, tolerance: int = 300) -> None:
    """Raise ValueError unless `header` is a valid, recent HubSign-Signature for the raw request body."""
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        ts, sig = int(parts["t"]), parts["v1"]
    except (KeyError, ValueError):
        raise ValueError("malformed signature header") from None
    good = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(good, sig):
        raise ValueError("signature mismatch")
    if abs(time.time() - ts) > tolerance:
        raise ValueError("timestamp outside tolerance (replay?)")


class HubSign:
    def __init__(self, api_key: str, base_url: str = "http://localhost:8000", client: httpx.Client | None = None):
        self.http = client or httpx.Client(base_url=base_url, timeout=30)
        self.http.headers["Authorization"] = f"Bearer {api_key}"

    def _ok(self, r: httpx.Response):
        if r.status_code >= 400:
            raise RuntimeError(f"HubSign {r.status_code}: {r.text}")
        return r.json() if r.content and r.headers.get("content-type", "").startswith("application/json") else r.content

    def create_envelope(
        self, pdf: str | Path | bytes, *, subject: str, recipients: list[dict], fields: list[dict] | None = None, **kw
    ) -> dict:
        data = pdf if isinstance(pdf, bytes) else Path(pdf).read_bytes()
        name = "document.pdf" if isinstance(pdf, bytes) else Path(pdf).name
        body = {"subject": subject, "document_base64": base64.b64encode(data).decode(), "document_name": name,
                "recipients": recipients, "fields": fields or [], **kw}  # fmt: skip
        return self._ok(self.http.post("/v1/envelopes", json=body))

    def get_envelope(self, envelope_id: str) -> dict:
        return self._ok(self.http.get(f"/v1/envelopes/{envelope_id}"))

    def list_envelopes(self, status: str | None = None) -> list[dict]:
        return self._ok(self.http.get("/v1/envelopes", params={"status": status} if status else {}))["envelopes"]

    def send(self, envelope_id: str) -> dict:
        return self._ok(self.http.post(f"/v1/envelopes/{envelope_id}/send"))

    def void(self, envelope_id: str, reason: str = "") -> dict:
        return self._ok(self.http.post(f"/v1/envelopes/{envelope_id}/void", json={"reason": reason}))

    def download_signed(self, envelope_id: str, path: str | Path) -> Path:
        Path(path).write_bytes(self._ok(self.http.get(f"/v1/envelopes/{envelope_id}/signed")))
        return Path(path)

    def create_webhook(self, url: str, events: list[str] | None = None) -> dict:
        return self._ok(self.http.post("/v1/webhooks", json={"url": url, "events": events or []}))
