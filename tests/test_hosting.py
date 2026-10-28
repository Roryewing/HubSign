from fastapi.testclient import TestClient

from hubsign.api import create_app
from hubsign.config import Settings


def test_first_account_can_be_reserved_for_the_administrator(tmp_path):
    s = Settings(data_dir=tmp_path, first_user_email="Boss@Example.com", allow_signup=False)
    with TestClient(create_app(s)) as c:
        body = {"password": "correct horse battery", "name": "X"}
        assert c.post("/auth/signup", json={"email": "stranger@example.com", **body}).status_code == 403
        assert c.post("/auth/signup", json={"email": "boss@example.com", **body}).status_code == 200  # case-insensitive
        assert (
            c.post("/auth/signup", json={"email": "stranger@example.com", **body}).status_code == 403
        )  # registration now closed
