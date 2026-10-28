import base64
import io
import os
import uuid

import pytest
from fastapi.testclient import TestClient
from reportlab.pdfgen import canvas

from hubsign.api import create_app
from hubsign.config import Settings


def pytest_configure(config):
    """HUBSIGN_TEST_PG=embedded runs the whole suite against a throwaway local PostgreSQL (pgserver)."""
    if os.environ.get("HUBSIGN_TEST_PG") == "embedded":
        import tempfile

        import pgserver

        srv = pgserver.get_server(tempfile.mkdtemp(prefix="hs-pg-"))
        os.environ["HUBSIGN_TEST_DATABASE_URL"] = srv.get_uri()
        config._hs_pg = srv


def pytest_unconfigure(config):
    if getattr(config, "_hs_pg", None):
        config._hs_pg.cleanup()


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
    def __init__(self, tmp_path, **overrides):
        self.sent: list[tuple[str, dict, bytes]] = []
        self.status = 200
        pg = os.environ.get("HUBSIGN_TEST_DATABASE_URL", "")
        base = {
            "data_dir": tmp_path, "webhooks_inline": True, "webhook_retry_delays": [0, 0],
            "allow_private_webhooks": True, "database_url": pg,
        }  # fmt: skip
        settings = Settings(**(base | overrides))
        self.settings = settings

        def sender(url, headers, body):
            self.sent.append((url, headers, body))
            return self.status, "ok"

        self.sms: list[tuple[str, str]] = []
        self.schema = ("t" + uuid.uuid4().hex[:12]) if pg else None
        self.sender = sender
        self.app = create_app(
            settings,
            sender=sender,
            sms_sender=lambda _s, to, body: self.sms.append((to, body)),
            db_schema=self.schema,
        )
        self.client = TestClient(self.app)
        self.client.post(
            "/auth/signup", json={"email": "owner@example.com", "password": "correct horse", "name": "Owner"}
        )
        self.key = self.client.post("/v1/api-keys", json={"name": "ci", "mode": "test", "role": "admin"}).json()["key"]
        self.h = {"Authorization": f"Bearer {self.key}"}
        self.client.cookies.clear()  # from here on, act as an API client

    def second_node(self):
        """Another app instance on the same database and storage, as a second server would be."""
        from fastapi.testclient import TestClient as TC

        return TC(create_app(self.settings, sender=self.sender, db_schema=self.schema))

    def login(self, email="owner@example.com", password="correct horse"):
        self.client.cookies.clear()
        assert self.client.post("/auth/login", json={"email": email, "password": password}).status_code == 200

    def make_key(self, role="sender", mode="test"):
        self.login()
        k = self.client.post("/v1/api-keys", json={"name": role, "mode": mode, "role": role}).json()["key"]
        self.client.cookies.clear()
        return {"Authorization": f"Bearer {k}"}

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


@pytest.fixture
def make_env(tmp_path):
    n = 0

    def make(**overrides):
        nonlocal n
        n += 1
        d = tmp_path / f"n{n}"
        d.mkdir()
        return Env(d, **overrides)

    return make
