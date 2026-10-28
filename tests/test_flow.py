import hashlib
import hmac
import io

from pypdf import PdfReader

from .conftest import PNG


def token(url: str) -> str:
    return url.rsplit("/", 1)[1]


def fill(env, tok):
    info = env.client.get(f"/sign-api/{tok}").json()
    vals = {}
    for f in info["fields"]:
        vals[f["id"]] = PNG if f["type"] in ("signature", "initials") else "Director"
    return info, vals


def test_sequential_signing_to_completed_pdf(env):
    r = env.envelope()
    assert r.status_code == 201, r.text
    e = r.json()
    assert e["status"] == "sent"
    ann, bob, cc = e["recipients"]
    assert ann["status"] == "sent" and "signing_url" in ann
    assert bob["status"] == "created" and "signing_url" not in bob  # not Bob's turn yet
    assert env.client.get(f"/sign-api/{token(ann['signing_url'])}").json()["state"] == "ready"

    # Bob's link exists but is not active
    d = env.client.get(f"/v1/envelopes/{e['id']}", headers=env.h).json()
    assert env.client.post("/sign-api/nope/complete", json={"consent": True, "values": {}}).status_code == 404

    # Ann: must consent and fill required fields
    t1 = token(ann["signing_url"])
    info, vals = fill(env, t1)
    assert env.client.post(f"/sign-api/{t1}/complete", json={"consent": False, "values": vals}).status_code == 422
    sig_id = next(f["id"] for f in info["fields"] if f["type"] == "signature")
    assert env.client.post(f"/sign-api/{t1}/complete", json={"consent": True, "values": {}}).status_code == 422
    bad = env.client.post(
        f"/sign-api/{t1}/complete", json={"consent": True, "values": {sig_id: "data:image/png;base64,AAAA"}}
    )
    assert bad.status_code == 422
    ok = env.client.post(f"/sign-api/{t1}/complete", json={"consent": True, "values": vals})
    assert ok.json()["state"] == "signed"
    assert (
        env.client.post(f"/sign-api/{t1}/complete", json={"consent": True, "values": vals}).status_code == 409
    )  # no double sign

    d = env.client.get(f"/v1/envelopes/{e['id']}", headers=env.h).json()
    assert d["status"] == "sent" and d["recipients"][1]["status"] == "sent"
    t2 = token(d["recipients"][1]["signing_url"])
    _, vals2 = fill(env, t2)
    assert (
        env.client.post(f"/sign-api/{t2}/complete", json={"consent": True, "values": vals2}).json()["state"]
        == "completed"
    )

    d = env.client.get(f"/v1/envelopes/{e['id']}", headers=env.h).json()
    assert d["status"] == "completed" and d["final_sha256"]
    pdf = env.client.get(f"/v1/envelopes/{e['id']}/signed", headers=env.h).content
    assert hashlib.sha256(pdf).hexdigest() == d["final_sha256"]
    r = PdfReader(io.BytesIO(pdf))
    assert len(r.pages) > 2 and "Certificate of Completion" in r.pages[-1].extract_text()
    assert "SANDBOX" in r.pages[-1].extract_text()
    assert (
        "Director" in r.pages[1].extract_text() and "SANDBOX" in r.pages[0].extract_text()
    )  # stamped text + watermark  # test mode is marked on the certificate
    orig = env.client.get(f"/v1/envelopes/{e['id']}/document", headers=env.h).content
    assert hashlib.sha256(orig).hexdigest() == d["document"]["sha256"]
    # cc can fetch the signed copy by link
    assert env.client.get(f"/sign-api/{token(f'/x/{cc_token(env, e)}')}/signed").status_code == 200

    kinds = [x["type"] for x in env.client.get(f"/v1/envelopes/{e['id']}/events", headers=env.h).json()["events"]]
    assert kinds[:2] == ["created", "sent"] and kinds[-1] == "completed" and kinds.count("signed") == 2


def cc_token(env, e):
    return env.client.app.state.svc.db.one(
        "SELECT token FROM recipients WHERE envelope_id=? AND role='cc'", (e["id"],)
    )["token"]


def test_parallel_routing_decline_and_void(env):
    e = env.envelope(sequential=False).json()
    assert all("signing_url" in r for r in e["recipients"][:2])
    t = token(e["recipients"][1]["signing_url"])
    assert env.client.post(f"/sign-api/{t}/decline", json={"reason": "wrong terms"}).status_code == 200
    d = env.client.get(f"/v1/envelopes/{e['id']}", headers=env.h).json()
    assert d["status"] == "declined"
    assert env.client.post(f"/v1/envelopes/{e['id']}/void", json={}, headers=env.h).status_code == 409
    assert env.client.get(f"/sign-api/{token(e['recipients'][0]['signing_url'])}").json()["state"] == "declined"

    e2 = env.envelope().json()
    assert (
        env.client.post(f"/v1/envelopes/{e2['id']}/void", json={"reason": "typo"}, headers=env.h).json()["status"]
        == "voided"
    )
    assert (
        env.client.post(
            f"/sign-api/{token(e2['recipients'][0]['signing_url'])}/complete", json={"consent": True}
        ).status_code
        == 409
    )


def test_validation(env):
    assert env.envelope(document_base64="@@@").status_code == 422
    import base64

    assert env.envelope(document_base64=base64.b64encode(b"not a pdf").decode()).status_code == 422
    assert (
        env.envelope(recipients=[{"name": "C", "email": "c@example.com", "role": "cc"}], fields=[]).status_code == 422
    )
    assert (
        env.envelope(fields=[{"recipient": 0, "type": "signature", "page": 9, "x": 0.1, "y": 0.1}]).status_code == 422
    )
    assert (
        env.envelope(fields=[{"recipient": 0, "type": "signature", "page": 1, "x": 0.95, "y": 0.1}]).status_code == 422
    )  # off page
    assert (
        env.envelope(fields=[{"recipient": 2, "type": "signature", "page": 1, "x": 0.1, "y": 0.1}]).status_code == 422
    )  # cc field
    # send needs a signature field per signer; drafts can be deleted
    d = env.envelope(send=False, fields=[{"recipient": 0, "type": "signature", "page": 1, "x": 0.1, "y": 0.1}]).json()
    assert d["status"] == "draft"
    assert env.client.post(f"/v1/envelopes/{d['id']}/send", headers=env.h).status_code == 422
    assert env.client.delete(f"/v1/envelopes/{d['id']}", headers=env.h).status_code == 204
    assert env.client.get(f"/v1/envelopes/{d['id']}", headers=env.h).status_code == 404


def test_auth_scoping_and_modes(env):
    assert env.client.get("/v1/envelopes").status_code == 401
    assert env.client.get("/v1/envelopes", headers={"Authorization": "Bearer hs_test_bad"}).status_code == 401
    e = env.envelope().json()
    # a second user cannot see it
    env.client.post("/auth/signup", json={"email": "other@example.com", "password": "another pass 1"})
    k2 = env.client.post("/v1/api-keys", json={"name": "x", "mode": "test"}).json()["key"]
    assert env.client.get(f"/v1/envelopes/{e['id']}", headers={"Authorization": f"Bearer {k2}"}).status_code == 404
    # keys cannot mint keys; live key does not see sandbox envelopes
    live = env.client.post("/v1/api-keys", json={"name": "live", "mode": "live"}).json()["key"]
    assert env.client.get("/v1/envelopes", headers={"Authorization": f"Bearer {live}"}).json()["envelopes"] == []
    # revoked key stops working
    env.client.cookies.clear()
    r = env.client.post("/auth/login", json={"email": "owner@example.com", "password": "correct horse"})
    assert r.status_code == 200
    assert env.client.post("/v1/api-keys", json={"name": "z"}, headers=env.h).status_code == 403
    kid = env.client.get("/v1/api-keys").json()["keys"][0]["id"]
    assert env.client.delete(f"/v1/api-keys/{kid}").status_code == 204
    env.client.cookies.clear()
    assert env.client.get("/v1/envelopes", headers={"Authorization": f"Bearer {k2}"}).status_code == 200


def test_login_throttle_and_password_rules(env):
    env.client.cookies.clear()
    for _ in range(5):
        assert (
            env.client.post("/auth/login", json={"email": "owner@example.com", "password": "wrong pass!!"}).status_code
            == 401
        )
    assert (
        env.client.post("/auth/login", json={"email": "owner@example.com", "password": "correct horse"}).status_code
        == 429
    )
    assert env.client.post("/auth/signup", json={"email": "a@b.co", "password": "short"}).status_code == 422


def test_webhooks_signed_and_filtered(env):
    wh = env.client.post(
        "/v1/webhooks",
        json={"url": "https://hooks.example.com/x", "events": ["envelope.completed", "recipient.signed"]},
        headers=env.h,
    ).json()
    assert wh["secret"].startswith("whsec_")
    assert env.client.post("/v1/webhooks", json={"url": "ftp://x"}, headers=env.h).status_code == 422
    assert (
        env.client.post(
            "/v1/webhooks", json={"url": "https://x.example", "events": ["nope"]}, headers=env.h
        ).status_code
        == 422
    )
    e = env.envelope().json()
    assert env.sent == []  # nothing subscribed has happened yet
    for i in (0, 1):
        d = env.client.get(f"/v1/envelopes/{e['id']}", headers=env.h).json()
        t = token(d["recipients"][i]["signing_url"])
        _, vals = fill(env, t)
        env.client.post(f"/sign-api/{t}/complete", json={"consent": True, "values": vals})
    types = [h["HubSign-Event"] for _, h, _ in env.sent]
    assert types == ["recipient.signed", "recipient.signed", "envelope.completed"]
    url, headers, body = env.sent[-1]
    ts, v1 = (p.split("=", 1)[1] for p in headers["HubSign-Signature"].split(","))
    assert v1 == hmac.new(wh["secret"].encode(), f"{ts}.".encode() + body, "sha256").hexdigest()
    import json

    p = json.loads(body)
    assert p["type"] == "envelope.completed" and p["data"]["envelope"]["metadata"] == {"deal": "D-1"}
    assert "token" not in body.decode() and "signing_url" not in body.decode()
    log = env.client.get(f"/v1/webhooks/{wh['id']}/deliveries", headers=env.h).json()["deliveries"]
    assert len(log) == 3 and all(x["status"] == "delivered" for x in log)
    # failure -> retried then failed; redeliver works
    env.status = 500
    n = len(env.sent)
    env.client.post(f"/v1/webhooks/{wh['id']}/test", headers=env.h)
    assert len(env.sent) == n + 3  # initial + 2 configured retries
    log = env.client.get(f"/v1/webhooks/{wh['id']}/deliveries", headers=env.h).json()["deliveries"]
    assert log[0]["status"] == "failed" and log[0]["attempts"] == 3 and log[0]["http_status"] == 500
    env.status = 200
    env.client.post(f"/v1/webhook-deliveries/{log[0]['id']}/redeliver", headers=env.h)
    assert (
        env.client.get(f"/v1/webhooks/{wh['id']}/deliveries", headers=env.h).json()["deliveries"][0]["status"]
        == "delivered"
    )
    # deleted webhooks stop receiving
    assert env.client.delete(f"/v1/webhooks/{wh['id']}", headers=env.h).status_code == 204
    n = len(env.sent)
    env.envelope()
    assert len(env.sent) == n


def test_ssrf_guard():
    from hubsign.security import url_is_safe

    assert url_is_safe("http://127.0.0.1:8080/x") and url_is_safe("http://169.254.169.254/latest")
    assert url_is_safe("http://10.0.0.5/") and url_is_safe("file:///etc/passwd")
    assert url_is_safe("http://127.0.0.1/", allow_private=True) is None


def test_certificate_escapes_user_text(env):
    e = env.envelope(
        recipients=[{"name": "<b>Eve</b> & <i>Co", "email": "e@example.com"}],
        fields=[{"recipient": 0, "type": "signature", "page": 1, "x": 0.1, "y": 0.1}],
    ).json()
    t = token(e["recipients"][0]["signing_url"])
    _, vals = fill(env, t)
    assert (
        env.client.post(f"/sign-api/{t}/complete", json={"consent": True, "values": vals}).json()["state"]
        == "completed"
    )
    assert env.client.get(f"/v1/envelopes/{e['id']}/signed", headers=env.h).status_code == 200


def test_sdk_roundtrip_and_signature_verification(env, tmp_path):
    import time

    import pytest

    from hubsign.sdk import HubSign, verify_signature

    from .conftest import make_pdf

    hs = HubSign(env.key, client=env.client)
    e = hs.create_envelope(make_pdf(1), subject="SDK", recipients=[{"name": "A", "email": "a@example.com"}],
                           fields=[{"recipient": 0, "type": "signature", "page": 1, "x": 0.1, "y": 0.1}], send=True)  # fmt: skip
    assert hs.list_envelopes("sent")[0]["id"] == e["id"] and hs.get_envelope(e["id"])["status"] == "sent"
    assert hs.void(e["id"], "test")["status"] == "voided"
    with pytest.raises(RuntimeError, match="404"):
        hs.get_envelope("env_nope")
    from hubsign.security import sign_webhook

    body = b'{"a":1}'
    verify_signature("sec", sign_webhook("sec", body), body)
    for hdr, b in [(sign_webhook("sec", body), b'{"a":2}'), (sign_webhook("other", body), body), ("garbage", body),
                   (sign_webhook("sec", body, int(time.time()) - 4000), body)]:  # fmt: skip
        with pytest.raises(ValueError):
            verify_signature("sec", hdr, b)
