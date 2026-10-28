"""The features a host application needs to replace DocuSign: anchored fields, several documents, prefilled locked
fields, embedded signers with a return URL, reply-to and SendGrid mail, reassigning, form data, per-document copies."""

import base64
import io

import pytest
from pypdf import PdfReader
from reportlab.lib import colors
from reportlab.pdfgen import canvas

from .conftest import PNG
from .test_flow import token


def anchored_pdf(pages=2, anchors=(), title="Agreement") -> bytes:
    """A PDF with invisible white 2pt anchor text, like the ones jsPDF prints on ServiceHub's signature lines."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(612, 792))
    for p in range(1, pages + 1):
        c.setFillColor(colors.black)
        c.setFont("Helvetica", 12)
        c.drawString(72, 740, f"{title} page {p}")
        for pg, text, x, y in anchors:
            if pg == p:
                c.setFillColor(colors.white)
                c.setFont("Helvetica", 2)
                c.drawString(x, y, text)
        c.showPage()
    c.save()
    return buf.getvalue()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def fill_for(env, tok, **extra):
    info = env.client.get(f"/sign-api/{tok}").json()
    vals = {
        f["id"]: (PNG if f["type"] in ("signature", "initials") else "typed") for f in info["fields"] if not f["locked"]
    }
    return info, vals | extra


def test_anchor_fields_land_on_the_text(env):
    pdf = anchored_pdf(
        2,
        [
            (1, "~cus-sign~", 100, 200),
            (1, "~cus-name~", 100, 150),
            (1, "~cus-init~", 400, 60),
            (2, "~cus-init~", 400, 60),
        ],
    )
    fields = [
        {
            "recipient": 0,
            "type": "signature",
            "anchor": {"text": "~cus-sign~", "y_offset": -22, "width": 150, "height": 36},
        },
        {"recipient": 0, "type": "name", "anchor": {"text": "~cus-name~", "y_offset": -8}},
        {"recipient": 0, "type": "initials", "anchor": {"text": "~cus-init~", "y_offset": -12}},  # on every page
        {"recipient": 0, "type": "date", "anchor": {"text": "~cus-adate~", "optional": True}},  # not in this PDF
    ]
    r = env.envelope(
        document_base64=b64(pdf), recipients=[{"name": "Ann", "email": "ann@example.com"}], fields=fields, send=True
    )
    assert r.status_code == 201, r.text
    fs = r.json()["fields"]
    assert sorted(f["type"] for f in fs) == [
        "initials",
        "initials",
        "name",
        "signature",
    ]  # optional anchor skipped, init twice
    sig = next(f for f in fs if f["type"] == "signature")
    # anchor text top-left is at x=100, ~692pt from the top (792-200-2); the box starts 22pt above that
    assert abs(sig["x"] - 100 / 612) < 0.005 and abs(sig["y"] - (792 - 200 - 2 - 22) / 792) < 0.01
    assert abs(sig["w"] - 150 / 612) < 0.001 and abs(sig["h"] - 36 / 792) < 0.001
    assert {f["page"] for f in fs if f["type"] == "initials"} == {1, 2}
    # a required anchor that is missing is an error, not a silently unsigned document
    bad = env.envelope(
        document_base64=b64(pdf), fields=[{"recipient": 0, "type": "signature", "anchor": {"text": "~nope~"}}]
    )
    assert bad.status_code == 422 and "~nope~" in bad.text
    assert env.envelope(fields=[{"recipient": 0, "type": "signature"}]).status_code == 422  # neither x/y nor anchor


def test_several_documents_prefilled_fields_and_form_data(env):
    inv = anchored_pdf(1, [(1, "~ca-sign~", 100, 100)], "Invoice")
    app = anchored_pdf(
        2,
        [(1, "~ca-tax_id~", 150, 600), (2, "~ca-sign~", 100, 100), (2, "~ca-company~", 150, 500)],
        "Credit application",
    )
    sheet = anchored_pdf(1, [(1, "~ca-delivery_address~", 150, 500)], "Delivery sheet")
    docs = [{"id": "1", "name": "Invoice.pdf", "document_base64": b64(inv)}, {"id": "2", "name": "Credit app.pdf", "document_base64": b64(app)},
            {"id": "3", "name": "Delivery.pdf", "document_base64": b64(sheet)}]  # fmt: skip
    fields = [
        {
            "recipient": 0,
            "type": "text",
            "label": "tax_id",
            "anchor": {"text": "~ca-tax_id~", "y_offset": -8, "width": 160, "height": 12},
        },
        {
            "recipient": 0,
            "type": "text",
            "label": "company",
            "value": "HJV Equipment Ltd.",
            "anchor": {"text": "~ca-company~", "y_offset": -8},
        },
        {
            "recipient": 0,
            "type": "text",
            "label": "delivery_address",
            "anchor": {"text": "~ca-delivery_address~", "y_offset": -8},
        },
        {"recipient": 0, "type": "signature", "anchor": {"text": "~ca-sign~", "y_offset": -22}},  # in docs 1 and 2
    ]
    r = env.client.post(
        "/v1/envelopes",
        headers=env.h,
        json={
            "subject": "Deposit",
            "documents": docs,
            "recipients": [{"name": "Cust", "email": "c@example.com"}],
            "fields": fields,
            "send": True,
        },
    )
    assert r.status_code == 201, r.text
    e = r.json()
    assert [(d["id"], d["start"], d["pages"]) for d in e["documents"]] == [("1", 1, 1), ("2", 2, 2), ("3", 4, 1)] and e[
        "document"
    ]["pages"] == 4
    assert sorted((f["page"], f["type"]) for f in e["fields"] if f["type"] == "signature") == [
        (1, "signature"),
        (3, "signature"),
    ]
    t = token(e["recipients"][0]["signing_url"])
    info, vals = fill_for(env, t)
    company = next(f for f in info["fields"] if f["label"] == "company")
    assert company["locked"] and company["value"] == "HJV Equipment Ltd."  # shown to the signer, fixed
    tax = next(f for f in info["fields"] if f["label"] == "tax_id")
    assert tax["value"] is None and not tax["locked"]
    vals[tax["id"]] = "RT 12345"
    vals[next(f["id"] for f in info["fields"] if f["label"] == "delivery_address")] = "1 Farm Rd, Winnipeg"
    vals[company["id"]] = "SOMETHING ELSE"  # a signer cannot overwrite a prefilled value
    assert (
        env.client.post(f"/sign-api/{t}/complete", json={"consent": True, "values": vals}).json()["state"]
        == "completed"
    )
    assert env.client.get(f"/v1/envelopes/{e['id']}/form_data", headers=env.h).json()["form_data"] == {
        "tax_id": "RT 12345", "company": "HJV Equipment Ltd.", "delivery_address": "1 Farm Rd, Winnipeg",
    }  # fmt: skip
    whole = env.client.get(f"/v1/envelopes/{e['id']}/signed", headers=env.h).content
    text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(whole)).pages)
    assert "HJV Equipment Ltd." in text and "SOMETHING ELSE" not in text and "RT 12345" in text
    # one document on its own, sealed as an excerpt
    ex = env.client.get(f"/v1/envelopes/{e['id']}/documents/2", headers=env.h)
    assert ex.status_code == 200
    pages = PdfReader(io.BytesIO(ex.content)).pages
    assert (
        len(pages) == 2
        and "Credit application page 1" in pages[0].extract_text()
        and "RT 12345" in pages[0].extract_text()
    )
    assert env.client.post("/v1/verify", content=ex.content).json()["ok"] is True
    assert env.client.get(f"/v1/envelopes/{e['id']}/documents/9", headers=env.h).status_code == 404
    assert env.client.get(f"/v1/envelopes/{e['id']}/documents/2").status_code == 401


def test_prefill_is_limited_to_text_and_checkbox(env):
    r = env.envelope(fields=[{"recipient": 0, "type": "signature", "page": 1, "x": 0.1, "y": 0.8, "value": "x"}])
    assert r.status_code == 422


def test_embedded_signer_return_url_reply_to_and_mail(make_env, monkeypatch):
    sent = []
    monkeypatch.setattr("hubsign.mail._deliver", lambda *a: sent.append(a))
    env = make_env(mail_from="noreply@hjv.example", sendgrid_api_key="SG.x")
    body = {
        "recipients": [
            {"name": "Cust", "email": "cust@example.com", "routing_order": 1},
            {"name": "Dan (HJV)", "email": "dan@hjv.example", "routing_order": 2, "embedded": True, "return_url": "https://hub.example/sales/1?esign=signed"},
        ],
        "fields": [{"recipient": 0, "type": "signature", "page": 1, "x": 0.1, "y": 0.8}, {"recipient": 1, "type": "signature", "page": 1, "x": 0.5, "y": 0.8}],
        "reply_to": {"name": "Dan", "email": "dan@hjv.example"}, "sender_name": "HJV Equipment", "message": "Please sign the addendum.", "send": True,
    }  # fmt: skip
    e = env.envelope(**body).json()
    assert [a[1] for a in sent] == ["cust@example.com"]  # the customer only
    s, to, subject, text, html, reply_to, from_name = sent[0]
    assert (
        subject == "Please sign: Equipment lease"
        and reply_to == {"name": "Dan", "email": "dan@hjv.example"}
        and from_name == "HJV Equipment"
    )
    assert (
        "HJV Equipment sent you a document" in text
        and "/sign/" in html
        and "Review and sign" in html
        and "Please sign the addendum." in html
    )
    t1 = token(e["recipients"][0]["signing_url"])
    _, v = fill_for(env, t1)
    env.client.post(f"/sign-api/{t1}/complete", json={"consent": True, "values": v})
    d = env.client.get(f"/v1/envelopes/{e['id']}", headers=env.h).json()
    emb = d["recipients"][1]
    assert emb["embedded"] and emb["status"] == "sent" and "signing_url" in emb
    assert [a[1] for a in sent] == ["cust@example.com"]  # still no email to the embedded signer
    t2 = token(emb["signing_url"])
    assert env.client.get(f"/sign-api/{t2}").json()["return_url"] == "https://hub.example/sales/1?esign=signed"
    _, v = fill_for(env, t2)
    assert (
        env.client.post(f"/sign-api/{t2}/complete", json={"consent": True, "values": v}).json()["state"] == "completed"
    )
    assert sorted(a[1] for a in sent[1:]) == [
        "cust@example.com"
    ]  # completed copy: the customer, not the embedded signer
    for bad in ("javascript:alert(1)", "ftp://x.example/y", "http://evil.example/x"):
        r = env.envelope(recipients=[{"name": "A", "email": "a@example.com", "return_url": bad}])
        assert r.status_code == 422, bad


def test_sendgrid_request_shape(make_env, monkeypatch):
    calls = []

    class R:
        status_code = 202
        text = ""

    monkeypatch.setattr("hubsign.mail.httpx.post", lambda url, **kw: calls.append((url, kw)) or R())
    env = make_env(mail_from="noreply@hjv.example", sendgrid_api_key="SG.secret", mail_from_name="HJV")
    env.envelope(reply_to={"name": "Dan", "email": "dan@hjv.example"}, send=True)
    url, kw = calls[0]
    assert url == "https://api.sendgrid.com/v3/mail/send" and kw["headers"]["Authorization"] == "Bearer SG.secret"
    j = kw["json"]
    assert j["from"]["email"] == "noreply@hjv.example" and j["reply_to"] == {"email": "dan@hjv.example", "name": "Dan"}
    assert {c["type"] for c in j["content"]} == {"text/plain", "text/html"} and j["personalizations"][0]["to"] == [
        {"email": "ann@example.com"}
    ]


def test_reassign(make_env, monkeypatch):
    sent = []
    monkeypatch.setattr("hubsign.mail._deliver", lambda *a: sent.append(a))
    env = make_env(mail_from="n@hjv.example", sendgrid_api_key="SG.x")
    one = {
        "recipients": [{"name": "Ann", "email": "ann@example.com"}],
        "fields": [{"recipient": 0, "type": "signature", "page": 1, "x": 0.1, "y": 0.8}],
        "send": True,
    }
    plain = env.envelope(**one).json()
    t0 = token(plain["recipients"][0]["signing_url"])
    assert (
        env.client.post(f"/sign-api/{t0}/reassign", json={"name": "Bo", "email": "bo@example.com"}).status_code == 403
    )  # not allowed unless the sender said so
    e = env.envelope(allow_reassign=True, **one).json()
    t = token(e["recipients"][0]["signing_url"])
    assert env.client.get(f"/sign-api/{t}").json()["allow_reassign"] is True
    assert (
        env.client.post(f"/sign-api/{t}/reassign", json={"name": "Ann", "email": "ANN@example.com"}).status_code == 422
    )
    assert (
        env.client.post(
            f"/sign-api/{t}/reassign", json={"name": "Bo Accountant", "email": "bo@example.com"}
        ).status_code
        == 200
    )
    assert env.client.get(f"/sign-api/{t}").status_code == 404  # the old link is dead
    d = env.client.get(f"/v1/envelopes/{e['id']}", headers=env.h).json()
    assert d["recipients"][0]["name"] == "Bo Accountant" and d["recipients"][0]["email"] == "bo@example.com"
    t2 = token(d["recipients"][0]["signing_url"])
    assert t2 != t and sent[-1][1] == "bo@example.com"
    _, v = fill_for(env, t2)
    assert (
        env.client.post(f"/sign-api/{t2}/complete", json={"consent": True, "values": v}).json()["state"] == "completed"
    )
    kinds = [x["type"] for x in env.client.get(f"/v1/envelopes/{e['id']}/events", headers=env.h).json()["events"]]
    assert "reassigned" in kinds
    # not for signers who must pass an SMS or access-code check: the check was for the original person
    guarded = env.envelope(
        allow_reassign=True,
        **{
            **one,
            "recipients": [
                {
                    "name": "A",
                    "email": "a@example.com",
                    "authentication": {"method": "access_code", "access_code": "abcd1234"},
                }
            ],
        },
    ).json()
    tg = token(guarded["recipients"][0]["signing_url"])
    env.client.post(f"/sign-api/{tg}/auth/verify", json={"code": "abcd1234"})
    assert env.client.post(f"/sign-api/{tg}/reassign", json={"name": "X", "email": "x@example.com"}).status_code == 403


@pytest.mark.parametrize("bad", [{"x": 2, "y": 0.1}, {"x": 0.1, "y": 0.1, "w": 0.95}])
def test_positioned_fields_still_validated(env, bad):
    r = env.envelope(fields=[{"recipient": 0, "type": "signature", "page": 1, **bad}])
    assert r.status_code == 422
