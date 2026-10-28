import base64
import io

import pytest
from fastapi.testclient import TestClient
from reportlab.pdfgen import canvas

from hubsign.api import create_app
from hubsign.config import Settings

PNG = (
    "data:image/png;base64,"
    + base64.b64encode(
        base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
        )
    ).decode()
)


def make_pdf(pages: int = 2) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    for i in range(pages):
        c.drawString(100, 700, f"Agreement page {i + 1}")
        c.showPage()
    c.save()
    return buf.getvalue()


class Env:
    def __init__(self, tmp_path):
        self.sent: list[tuple[str, dict, bytes]] = []
        self.status = 200
        settings = Settings(
            data_dir=tmp_path, webhooks_inline=True, webhook_retry_delays=[0, 0], allow_private_webhooks=True
        )

        def sender(url, headers, body):
            self.sent.append((url, headers, body))
            return self.status, "ok"

        self.client = TestClient(create_app(settings, sender=sender))
        self.client.post(
            "/auth/signup", json={"email": "owner@example.com", "password": "correct horse", "name": "Owner"}
        )
        self.key = self.client.post("/v1/api-keys", json={"name": "ci", "mode": "test"}).json()["key"]
        self.h = {"Authorization": f"Bearer {self.key}"}
        self.client.cookies.clear()  # from here on, act as an API client

    def envelope(self, **kw):
        body = {
            "subject": "Equipment lease",
            "document_base64": base64.b64encode(make_pdf()).decode(),
            "recipients": [
                {"name": "Ann", "email": "ann@example.com", "routing_order": 1},
                {"name": "Bob", "email": "bob@example.com", "routing_order": 2},
                {"name": "Cc", "email": "cc@example.com", "role": "cc", "routing_order": 3},
            ],
            "fields": [
                {"recipient": 0, "type": "signature", "page": 1, "x": 0.1, "y": 0.8},
                {"recipient": 0, "type": "date", "page": 1, "x": 0.5, "y": 0.8},
                {"recipient": 1, "type": "signature", "page": 2, "x": 0.1, "y": 0.8},
                {"recipient": 1, "type": "text", "page": 2, "x": 0.1, "y": 0.7, "label": "Title"},
            ],
            "send": True,
            "metadata": {"deal": "D-1"},
        } | kw
        return self.client.post("/v1/envelopes", json=body, headers=self.h)


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)
