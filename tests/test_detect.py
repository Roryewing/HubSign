import base64
import io

from reportlab.pdfgen import canvas

from hubsign import detect


def form_pdf() -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(612, 792))
    c.drawString(72, 700, "Agreement")
    c.acroForm.textfield(name="full_name", x=100, y=600, width=200, height=20)
    c.acroForm.textfield(name="prefilled", x=100, y=560, width=200, height=20, value="x")
    c.acroForm.checkbox(name="agree", x=100, y=520, size=14)
    # printed labels with underlines
    c.drawString(72, 300, "Signature:")
    c.line(140, 298, 340, 298)
    c.drawString(72, 250, "Date:")
    c.line(110, 248, 220, 248)
    c.drawString(72, 200, "Initials: ________")
    c.drawString(72, 150, "☐ I agree")
    c.save()
    return buf.getvalue()


def test_form_fields_are_imported_and_prefilled_ones_skipped():
    fields = [f for f in detect.acro_fields(form_pdf())]
    assert {(f["type"], f["label"]) for f in fields} == {("text", "full_name"), ("checkbox", "agree")}
    name = next(f for f in fields if f["label"] == "full_name")
    assert (round(name["x"] * 612), round((1 - name["y"] - name["h"]) * 792), round(name["w"] * 612)) == (100, 600, 200)


def test_labels_get_fields_on_the_lines():
    by_type = {}
    for f in detect.label_fields(form_pdf()):
        by_type.setdefault(f["type"], []).append(f)
    sig = by_type["signature"][0]
    assert sig["required"] and abs(sig["x"] * 612 - 140) < 3 and abs(sig["w"] * 612 - 200) < 3
    assert abs((1 - sig["y"] - sig["h"]) * 792 - 298) < 3  # sits on the line
    assert abs(by_type["date"][0]["x"] * 612 - 110) < 3
    assert by_type["initials"]  # underscores after the label count as the blank


def test_endpoint(env):
    r = env.client.post(
        "/v1/detect-fields", json={"document_base64": base64.b64encode(form_pdf()).decode()}, headers=env.h
    )
    assert r.status_code == 200, r.text
    assert {f["type"] for f in r.json()["fields"]} >= {"text", "checkbox", "signature", "date"}
    assert env.client.post("/v1/detect-fields", json={"document_base64": "AAAA"}, headers=env.h).status_code == 422


def test_invisible_anchor_text_beside_a_label_does_not_hide_it():
    """ServiceHub's PDFs print white 2pt anchors (~cus-date~) on the label's own line."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(612, 792))
    for label, y in (("Signature", 300), ("Date", 280)):
        c.setFont("Helvetica", 9)
        c.line(60, y, 250, y)
        c.drawString(40, y, label)
        c.setFont("Helvetica", 2)
        c.setFillColorRGB(1, 1, 1)
        c.drawString(62, y + 1, f"~cus-{label.lower()}~")
        c.setFillColorRGB(0, 0, 0)
    c.save()
    got = {f["type"]: f for f in detect.label_fields(buf.getvalue())}
    assert set(got) == {"signature", "date"}
    assert abs(got["date"]["x"] * 612 - 60) < 3 and abs(got["date"]["w"] * 612 - 190) < 3
