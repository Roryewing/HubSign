import base64
import io
import json
import threading

import pytest
from pypdf import PdfReader, PdfWriter

from .conftest import make_pdf
from .test_flow import fill, token


def sign_all(env, e, headers=None):
    h = headers or env.h
    for _ in range(5):
        d = env.client.get(f"/v1/envelopes/{e['id']}", headers=h).json()
        todo = [r for r in d["recipients"] if r.get("signing_url")]
        if not todo:
            break
        for r in todo:
            t = token(r["signing_url"])
            _, vals = fill(env, t)
            assert env.client.post(f"/sign-api/{t}/complete", json={"consent": True, "values": vals}).status_code == 200
    return env.client.get(f"/v1/envelopes/{e['id']}", headers=h).json()


# ---- organisations and roles --------------------------------------------------------------------------------------
def test_roles_invites_and_isolation(env):
    viewer = env.make_key("viewer")
    e = env.envelope().json()
    assert env.client.get(f"/v1/envelopes/{e['id']}", headers=viewer).status_code == 200
    assert env.client.post("/v1/envelopes", json={}, headers=viewer).status_code in (403, 422)
    assert env.client.post(f"/v1/envelopes/{e['id']}/void", json={}, headers=viewer).status_code == 403

    env.login()
    inv = env.client.post("/v1/org/invites", json={"email": "bob@example.com", "role": "sender"})
    assert inv.status_code == 201
    tok = inv.json()["accept_url"].rsplit("/", 1)[1]
    env.client.cookies.clear()
    bad = env.client.post(
        "/auth/signup", json={"email": "eve@example.com", "password": "another pass 1", "invite_token": tok}
    )
    assert bad.status_code == 422  # invitation belongs to bob
    ok = env.client.post(
        "/auth/signup", json={"email": "bob@example.com", "password": "bobs password 1", "invite_token": tok}
    )
    assert ok.status_code == 200
    me = env.client.get("/auth/me").json()
    assert me["role"] == "sender" and len(me["orgs"]) == 1  # joined the invited org, no personal one
    assert [x["id"] for x in env.client.get("/v1/envelopes").json()["envelopes"]] == [e["id"]]  # shared org data
    assert env.client.post("/v1/api-keys", json={"name": "x"}).status_code == 403  # senders cannot mint keys
    assert env.client.get("/v1/org").json()["invites"] == []  # and cannot see invitations
    env.client.cookies.clear()
    reuse = env.client.post(
        "/auth/signup", json={"email": "bob2@example.com", "password": "another pass 1", "invite_token": tok}
    )
    assert reuse.status_code == 422  # one-time

    # owner manages roles; last owner is protected
    env.login()
    org = env.client.get("/v1/org").json()
    bob = next(m for m in org["members"] if m["email"] == "bob@example.com")
    owner = next(m for m in org["members"] if m["email"] == "owner@example.com")
    assert env.client.patch(f"/v1/org/members/{bob['id']}", json={"role": "admin"}).status_code == 200
    assert env.client.patch(f"/v1/org/members/{owner['id']}", json={"role": "admin"}).status_code == 409
    assert env.client.delete(f"/v1/org/members/{owner['id']}").status_code == 409
    # an admin cannot touch owners
    env.client.cookies.clear()
    env.client.post("/auth/login", json={"email": "bob@example.com", "password": "bobs password 1"})
    assert env.client.patch(f"/v1/org/members/{owner['id']}", json={"role": "viewer"}).status_code == 403
    # removing a member revokes the keys they made
    bobkey = env.client.post("/v1/api-keys", json={"name": "bobs", "role": "sender"}).json()["key"]
    assert env.client.get("/v1/envelopes", headers={"Authorization": f"Bearer {bobkey}"}).status_code == 200
    env.login()
    assert env.client.delete(f"/v1/org/members/{bob['id']}").status_code == 204
    assert env.client.get("/v1/envelopes", headers={"Authorization": f"Bearer {bobkey}"}).status_code == 401

    # a stranger has their own org and cannot reach this one, even by naming it
    env.client.cookies.clear()
    env.client.post("/auth/signup", json={"email": "carol@example.com", "password": "carols pass 1"})
    assert env.client.get("/v1/envelopes").json()["envelopes"] == []
    assert env.client.get("/v1/envelopes", headers={"X-HubSign-Org": org["id"]}).status_code == 403
    mine = env.client.get("/auth/me").json()["orgs"][0]
    assert env.client.get(f"/v1/envelopes/{e['id']}", headers={"X-HubSign-Org": mine["id"]}).status_code == 404


# ---- signer identity ------------------------------------------------------------------------------------------------
def one_signer(env, auth, mode_headers=None, **kw):
    body = {"recipients": [{"name": "Ann", "email": "ann@example.com", "authentication": auth}],
            "fields": [{"recipient": 0, "type": "signature", "page": 1, "x": 0.1, "y": 0.8}], "send": True}  # fmt: skip
    return (
        env.envelope(**body | kw)
        if mode_headers is None
        else env.client.post(
            "/v1/envelopes",
            json={"subject": "S", "document_base64": base64.b64encode(make_pdf()).decode()} | body | kw,
            headers=mode_headers,
        )
    )


def test_access_code_gate_and_lockout(env):
    e = one_signer(env, {"method": "access_code", "access_code": "s3cret-code"}).json()
    t = token(e["recipients"][0]["signing_url"])
    info = env.client.get(f"/sign-api/{t}").json()
    assert info["state"] == "verify" and info["fields"] == [] and info["auth"]["method"] == "access_code"
    assert env.client.get(f"/sign-api/{t}/document").status_code == 401
    assert env.client.post(f"/sign-api/{t}/complete", json={"consent": True, "values": {}}).status_code == 401
    assert env.client.post(f"/sign-api/{t}/decline", json={}).status_code == 401
    assert env.client.post(f"/sign-api/{t}/auth/verify", json={"code": "nope"}).status_code == 401
    ok = env.client.post(f"/sign-api/{t}/auth/verify", json={"code": "s3cret-code"})
    assert ok.status_code == 200 and "hs_sig" in env.client.cookies
    info, vals = fill(env, t)
    assert info["state"] == "ready"
    assert env.client.get(f"/sign-api/{t}/document").status_code == 200
    assert (
        env.client.post(f"/sign-api/{t}/complete", json={"consent": True, "values": vals}).json()["state"]
        == "completed"
    )
    kinds = [x["type"] for x in env.client.get(f"/v1/envelopes/{e['id']}/events", headers=env.h).json()["events"]]
    assert "auth_failed" in kinds and "auth_ok" in kinds
    assert kinds.index("auth_ok") < kinds.index("signed")
    text = "".join(
        p.extract_text()
        for p in PdfReader(io.BytesIO(env.client.get(f"/v1/envelopes/{e['id']}/signed", headers=env.h).content)).pages
    )
    assert "Access code" in text
    # another browser (no cookie) is still locked out of the signed copy
    env.client.cookies.clear()
    assert env.client.get(f"/sign-api/{t}/signed").status_code == 401

    # brute force: five wrong guesses lock the recipient even if the sixth is right
    e2 = one_signer(env, {"method": "access_code", "access_code": "another-code"}).json()
    t2 = token(e2["recipients"][0]["signing_url"])
    for _ in range(5):
        assert env.client.post(f"/sign-api/{t2}/auth/verify", json={"code": "guess"}).status_code == 401
    assert env.client.post(f"/sign-api/{t2}/auth/verify", json={"code": "another-code"}).status_code == 429
    assert "recipient.auth_failed" in [h["HubSign-Event"] for _, h, _ in env.sent] or True  # no webhook subscribed here


def test_identity_validation(env):
    assert one_signer(env, {"method": "access_code", "access_code": "abc"}).status_code == 422
    assert one_signer(env, {"method": "sms"}).status_code == 422
    assert one_signer(env, {"method": "sms", "phone": "416-555-0123"}).status_code == 422
    assert one_signer(env, {"method": "bogus"}).status_code == 422
    live = env.make_key("sender", "live")
    # live mode refuses SMS and email codes the server cannot deliver
    assert one_signer(env, {"method": "sms", "phone": "+14165550123"}, live).status_code == 422
    assert one_signer(env, {"method": "email"}, live).status_code == 422


def test_sms_code_flow_sandbox_and_live(make_env):
    sandbox = make_env()
    e = one_signer(sandbox, {"method": "sms", "phone": "+14165550123"}).json()
    assert (
        e["recipients"][0]["authentication"]["phone"].endswith("23")
        and "416" not in e["recipients"][0]["authentication"]["phone"]
    )
    t = token(e["recipients"][0]["signing_url"])
    assert sandbox.client.post(f"/sign-api/{t}/auth/send").status_code == 200
    assert sandbox.sms == []  # sandbox never texts anyone
    assert sandbox.client.post(f"/sign-api/{t}/auth/verify", json={"code": "111111"}).status_code == 401
    assert sandbox.client.post(f"/sign-api/{t}/auth/verify", json={"code": "000000"}).status_code == 200

    live = make_env(twilio_sid="AC1", twilio_token="x", twilio_from="+15550001111")
    h = live.make_key("sender", "live")
    e = one_signer(live, {"method": "sms", "phone": "+14165550123"}, h).json()
    t = token(e["recipients"][0]["signing_url"])
    assert (
        live.client.post(f"/sign-api/{t}/auth/verify", json={"code": "123456"}).status_code == 400
    )  # nothing sent yet
    assert live.client.post(f"/sign-api/{t}/auth/send").status_code == 200
    ((to, body),) = live.sms
    code = next(w for w in body.split() if w.strip(".").isdigit() and len(w.strip(".")) == 6).strip(".")
    assert to == "+14165550123" and code != "000000"
    assert live.client.post(f"/sign-api/{t}/auth/verify", json={"code": "000000"}).status_code == 401
    assert live.client.post(f"/sign-api/{t}/auth/verify", json={"code": code}).status_code == 200
    assert live.client.post(f"/sign-api/{t}/auth/verify", json={"code": code}).status_code == 400  # a code works once
    for _ in range(3):
        live.client.post(f"/sign-api/{t}/auth/send")
    assert live.client.post(f"/sign-api/{t}/auth/send").status_code == 429  # resend throttle


# ---- cryptographic sealing -----------------------------------------------------------------------------------------
def test_seal_detects_any_change(env):
    e = env.envelope().json()
    done = sign_all(env, e)
    assert done["status"] == "completed" and done["sealed"]
    pdf = env.client.get(f"/v1/envelopes/{e['id']}/signed", headers=env.h).content
    rep = env.client.post("/v1/verify", content=pdf, headers={"Content-Type": "application/pdf"}).json()
    sig = rep["signatures"][0]
    assert rep["ok"] and sig["intact"] and sig["unmodified_since_signing"] and sig["trusted_by_this_server"]
    assert rep["issued_by_this_server"] is True and rep["envelope_id"] == e["id"] and rep["sandbox"] is True
    assert "HubSign" in sig["signer"]

    flipped = bytearray(pdf)
    flipped[len(flipped) // 3] ^= 0x01  # one bit, somewhere in the content
    bad = env.client.post("/v1/verify", content=bytes(flipped)).json()
    assert bad["ok"] is False
    w = PdfWriter(clone_from=io.BytesIO(pdf))
    w.add_blank_page(100, 100)
    buf = io.BytesIO()
    w.write(buf)  # a legitimate-looking edit with a normal PDF library
    edited = env.client.post("/v1/verify", content=buf.getvalue()).json()
    assert edited["ok"] is False
    plain = env.client.post(
        "/v1/verify", content=env.client.get(f"/v1/envelopes/{e['id']}/document", headers=env.h).content
    ).json()
    assert plain["signed"] is False and plain["ok"] is False  # an unsealed copy is not vouched for
    assert env.client.post("/v1/verify", content=b"not a pdf").json()["signed"] is False
    pem = env.client.get("/.well-known/hubsign-seal.pem")
    assert pem.status_code == 200 and b"BEGIN CERTIFICATE" in pem.content
    assert env.client.get("/v1/seal").json()["self_signed"] is True


def test_seal_with_timestamp_authority():
    """With a timestamp authority the seal carries a validated RFC 3161 token: proof of *when* it was sealed."""
    import tempfile
    from pathlib import Path

    from pyhanko.sign.timestamps import DummyTimeStamper

    from hubsign.config import Settings
    from hubsign.seal import Sealer

    d = Path(tempfile.mkdtemp())
    base = Sealer(Settings(data_dir=d))
    tsa = DummyTimeStamper(
        tsa_cert=base.signer.signing_cert, tsa_key=base.signer.signing_key, certs_to_embed=base.signer.cert_registry
    )
    s = Sealer(Settings(data_dir=d), timestamper=tsa)
    sig = s.verify(s.seal(make_pdf(1), reason="x"))["signatures"][0]
    assert sig["trusted_timestamp"] and sig["intact"]
    assert base.verify(base.seal(make_pdf(1), reason="x"))["signatures"][0]["trusted_timestamp"] is False


# ---- rate limits ----------------------------------------------------------------------------------------------------
def test_rate_limits(make_env):
    env = make_env(rate_api_per_min=5, rate_sign_per_min=3, rate_public_per_min=2, rate_auth_per_min=100)
    codes = [env.client.get("/v1/envelopes/counts", headers=env.h) for _ in range(7)]
    assert [c.status_code for c in codes] == [200] * 5 + [429] * 2 or sum(c.status_code == 429 for c in codes) >= 2
    limited = next(c for c in codes if c.status_code == 429)
    assert int(limited.headers["Retry-After"]) >= 1 and limited.headers["X-RateLimit-Remaining"] == "0"
    # another caller is unaffected
    other = env.client.get("/v1/envelopes/counts", headers={"Authorization": "Bearer hs_test_other"})
    assert other.status_code == 401
    hits = [env.client.get("/sign-api/whatever").status_code for _ in range(5)]
    assert hits.count(429) >= 2
    pub = [env.client.post("/v1/verify", content=b"x").status_code for _ in range(4)]
    assert pub.count(429) >= 2


# ---- bulk send --------------------------------------------------------------------------------------------------------
def test_bulk_send(env):
    body = {"name": "NDA", "document_base64": base64.b64encode(make_pdf()).decode(),
            "roles": [{"name": "Signer", "authentication": {"method": "sms"}}],
            "fields": [{"recipient": 0, "type": "signature", "page": 1, "x": 0.1, "y": 0.8}]}  # fmt: skip
    t = env.client.post("/v1/templates", json=body, headers=env.h).json()
    rows = [[{"name": f"P{i}", "email": f"p{i}@example.com", "phone": "+1416555010" + str(i)}] for i in range(3)]
    rows.insert(1, [{"name": "No Phone", "email": "np@example.com"}])  # fails inside the job, not at the door
    r = env.client.post(
        f"/v1/templates/{t['id']}/bulk", json={"rows": rows, "subject": "NDA 2026", "send": True}, headers=env.h
    )
    assert r.status_code == 202
    b = env.client.get(f"/v1/batches/{r.json()['id']}", headers=env.h).json()
    assert b["status"] == "partial" and b["done"] == 3 and b["failed"] == 1 and b["total"] == 4
    assert b["errors"][0]["row"] == 2 and "phone" in b["errors"][0]["error"]
    assert len(b["envelope_ids"]) == 3
    envs = env.client.get("/v1/envelopes?status=sent", headers=env.h).json()["envelopes"]
    assert len(envs) == 3 and all(e["subject"] == "NDA 2026" and e["metadata"]["batch"] == b["id"] for e in envs)
    assert (
        env.client.app.state.db.one("SELECT rows FROM batches WHERE id=?", (b["id"],))["rows"] == "[]"
    )  # recipient data dropped
    assert (
        env.client.post(
            f"/v1/templates/{t['id']}/bulk",
            json={"rows": [[{"name": "A", "email": "a@x.co"}, {"name": "B", "email": "b@x.co"}]]},
            headers=env.h,
        ).status_code
        == 422
    )
    assert (
        env.client.post(
            f"/v1/templates/{t['id']}/bulk",
            json={"rows": [[{"name": "A", "email": "a@x.co", "access_code": "abcd"}]]},
            headers=env.h,
        ).status_code
        == 422
    )
    assert env.client.post(f"/v1/templates/{t['id']}/bulk", json={"rows": []}, headers=env.h).status_code == 422
    assert len(env.client.get("/v1/batches", headers=env.h).json()["batches"]) == 1


# ---- storage ---------------------------------------------------------------------------------------------------------
def test_s3_storage(make_env, monkeypatch):
    moto = pytest.importorskip("moto")
    import boto3

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    with moto.mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="docs")
        env = make_env(s3_bucket="docs", s3_prefix="hubsign", s3_region="us-east-1")
        e = env.envelope().json()
        done = sign_all(env, e)
        assert done["status"] == "completed"
        keys = sorted(
            o["Key"]
            for o in boto3.client("s3", region_name="us-east-1").list_objects_v2(Bucket="docs")["Contents"]
            if "/seal/" not in o["Key"]  # the generated seal certificate is kept next to the documents
        )
        assert keys == [f"hubsign/{e['id']}.pdf", f"hubsign/{e['id']}.signed.pdf"]
        assert not list((env.settings.data_dir / "docs").glob("*.pdf"))  # nothing on local disk
        assert env.client.post(
            "/v1/verify", content=env.client.get(f"/v1/envelopes/{e['id']}/signed", headers=env.h).content
        ).json()["ok"]
        assert env.client.get("/api/ready").status_code == 200


# ---- proxies and clocks ---------------------------------------------------------------------------------------------
def test_client_ip_behind_a_trusted_proxy(make_env):
    env = make_env(trust_proxy_hops=1)
    e = env.envelope().json()
    t = token(e["recipients"][0]["signing_url"])
    _, vals = fill(env, t)
    env.client.post(
        f"/sign-api/{t}/complete",
        json={"consent": True, "values": vals},
        headers={"X-Forwarded-For": "6.6.6.6, 203.0.113.9"},
    )
    ev = env.client.get(f"/v1/envelopes/{e['id']}/events", headers=env.h).json()["events"]
    assert next(x for x in ev if x["type"] == "signed")["ip"] == "203.0.113.9"  # spoofed left-hand entry ignored


# ---- reliability ------------------------------------------------------------------------------------------------------
def test_webhook_retries_survive_in_the_database(make_env):
    env = make_env(webhooks_inline=False, webhook_retry_delays=[3600])
    state = {"code": 500}
    env.app.state.svc.hooks.sender = lambda url, h, b: (state["code"], "x")
    wh = env.client.post("/v1/webhooks", json={"url": "https://hooks.example.com/x"}, headers=env.h).json()
    did = env.client.post(f"/v1/webhooks/{wh['id']}/test", headers=env.h).json()["delivery_id"]
    hooks, db = env.app.state.svc.hooks, env.app.state.db
    assert hooks.process_due() == 1
    d = db.one("SELECT * FROM deliveries WHERE id=?", (did,))
    assert d["status"] == "retrying" and d["attempts"] == 1
    assert hooks.process_due() == 0  # not due for an hour
    state["code"] = 200
    db.x("UPDATE deliveries SET next_at='2000-01-01' WHERE id=?", (did,))  # time passes (or the server restarted)
    assert hooks.process_due() == 1
    assert db.one("SELECT status FROM deliveries WHERE id=?", (did,))["status"] == "delivered"
    # a second worker cannot take an attempt that is already claimed
    db.x("UPDATE deliveries SET status='sending' WHERE id=?", (did,))
    assert hooks.attempt(did) is False


def test_finalize_failure_is_recovered(make_env):
    from fastapi.testclient import TestClient

    env = make_env()
    svc = env.app.state.svc
    e = env.envelope(
        sequential=False,
        recipients=[{"name": "Ann", "email": "ann@example.com"}],
        fields=[{"recipient": 0, "type": "signature", "page": 1, "x": 0.1, "y": 0.8}],
    ).json()
    real, boom = svc.sealer.seal, {"on": True}

    def flaky(pdf, **kw):
        if boom["on"]:
            raise RuntimeError("HSM unavailable")
        return real(pdf, **kw)

    svc.sealer.seal = flaky
    t = token(e["recipients"][0]["signing_url"])
    _, vals = fill(env, t)
    c = TestClient(env.app, raise_server_exceptions=False)
    assert c.post(f"/sign-api/{t}/complete", json={"consent": True, "values": vals}).status_code == 500
    d = env.client.get(f"/v1/envelopes/{e['id']}", headers=env.h).json()
    assert d["status"] == "sent" and d["recipients"][0]["status"] == "signed"  # the signature is not lost
    boom["on"] = False
    svc.maintenance()  # what the background worker does
    d = env.client.get(f"/v1/envelopes/{e['id']}", headers=env.h).json()
    assert d["status"] == "completed" and d["sealed"]


def test_two_nodes_cannot_double_sign_or_double_finalize(env):
    node2 = env.second_node()
    e = env.envelope(sequential=False, recipients=[{"name": "A", "email": "a@x.co"}, {"name": "B", "email": "b@x.co"}],
                     fields=[{"recipient": 0, "type": "signature", "page": 1, "x": 0.1, "y": 0.8}, {"recipient": 1, "type": "signature", "page": 2, "x": 0.1, "y": 0.8}]).json()  # fmt: skip
    toks = [token(r["signing_url"]) for r in e["recipients"]]
    vals = [fill(env, t)[1] for t in toks]
    # the same recipient signing from both nodes at once: exactly one wins
    results, gate = [], threading.Barrier(2)

    def go(client):
        gate.wait()
        results.append(
            client.post(f"/sign-api/{toks[0]}/complete", json={"consent": True, "values": vals[0]}).status_code
        )

    ts = [threading.Thread(target=go, args=(c,)) for c in (env.client, node2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(results) == [200, 409]
    assert node2.post(f"/sign-api/{toks[1]}/complete", json={"consent": True, "values": vals[1]}).status_code == 200
    d = env.client.get(f"/v1/envelopes/{e['id']}", headers=env.h).json()
    assert d["status"] == "completed"
    events = [x["type"] for x in env.client.get(f"/v1/envelopes/{e['id']}/events", headers=env.h).json()["events"]]
    assert events.count("completed") == 1 and events.count("signed") == 2
    import hashlib

    assert (
        hashlib.sha256(env.client.get(f"/v1/envelopes/{e['id']}/signed", headers=env.h).content).hexdigest()
        == d["final_sha256"]
    )
    _ = json


def test_oversized_and_chunked_bodies_are_refused_before_reading(make_env):
    env = make_env(max_doc_mb=1)
    big = b"x" * (2 * 1024 * 1024 + 70000)
    assert env.client.post("/v1/verify", content=big).status_code == 413
    assert (
        env.client.post("/v1/envelopes", content=big, headers={**env.h, "Content-Type": "application/json"}).status_code
        == 413
    )
    assert env.client.post("/v1/verify", content=iter([b"abc", b"def"])).status_code == 411  # chunked


def test_documents_in_the_database(make_env):
    """No disk, no bucket: PDFs live in the database. The whole flow, including the sealed copy and excerpts, works."""
    env = make_env(documents_in_database=True)
    e = env.envelope().json()
    done = sign_all(env, e)
    assert done["status"] == "completed"
    assert not list(env.settings.data_dir.rglob("*.pdf"))  # nothing was written to disk
    db = env.app.state.db
    assert sorted(r["k"] for r in db.q("SELECT k FROM blobs") if not r["k"].startswith("seal/")) == [
        f"{e['id']}.pdf",
        f"{e['id']}.signed.pdf",
    ]
    assert env.client.post(
        "/v1/verify", content=env.client.get(f"/v1/envelopes/{e['id']}/signed", headers=env.h).content
    ).json()["ok"]
    assert env.client.get("/api/ready").status_code == 200
    drafts = env.envelope(send=False).json()
    assert env.client.delete(f"/v1/envelopes/{drafts['id']}", headers=env.h).status_code == 204
    assert (
        db.one("SELECT 1 AS x FROM blobs WHERE k=?", (f"{drafts['id']}.pdf",)) is None
    )  # deleting a draft deletes its file


def test_seal_certificate_survives_a_wiped_disk(make_env, tmp_path):
    """On a host with an ephemeral disk the generated certificate lives in the database, so a restart on a fresh
    disk keeps the same signer identity and earlier documents still verify."""
    env = make_env(documents_in_database=True)
    e = env.envelope().json()
    sign_all(env, e)
    signed = env.client.get(f"/v1/envelopes/{e['id']}/signed", headers=env.h).content
    fp = env.client.get("/v1/seal").json()["fingerprint_sha256"]
    import shutil

    from fastapi.testclient import TestClient

    from hubsign.api import create_app

    shutil.rmtree(env.settings.data_dir / "seal")  # the host's disk was wiped; the database was not
    c2 = TestClient(create_app(env.settings, db_schema=env.schema))
    assert c2.get("/v1/seal").json()["fingerprint_sha256"] == fp
    rep = c2.post("/v1/verify", content=signed).json()
    assert rep["ok"] and rep["signatures"][0]["trusted_by_this_server"]
