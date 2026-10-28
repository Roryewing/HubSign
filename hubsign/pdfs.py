"""PDF validation, field stamping and the certificate of completion."""

from __future__ import annotations

import base64
import io
from xml.sax.saxutils import escape

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

MAX_PAGES = 200


def inspect(data: bytes) -> int:
    """Page count of a valid, unencrypted PDF. Raises ValueError otherwise."""
    if not data.startswith(b"%PDF"):
        raise ValueError("document is not a PDF")
    try:
        r = PdfReader(io.BytesIO(data))
        if r.is_encrypted:
            raise ValueError("encrypted PDFs are not supported")
        n = len(r.pages)
    except ValueError:
        raise
    except Exception as e:
        raise ValueError("document is not a readable PDF") from e
    if not 1 <= n <= MAX_PAGES:
        raise ValueError(f"PDF must have 1 to {MAX_PAGES} pages")
    return n


def png_from_data_url(v: str) -> bytes | None:
    if not v.startswith("data:image/png;base64,") or len(v) > 400_000:
        return None
    try:
        raw = base64.b64decode(v.split(",", 1)[1], validate=True)
    except ValueError:
        return None
    return raw if raw.startswith(b"\x89PNG") else None


def _overlay(w: float, h: float, fields: list[dict], sandbox: bool) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(w, h))
    if sandbox:
        c.saveState()
        c.setFillColor(colors.grey)
        c.setFillAlpha(0.12)
        c.setFont("Helvetica-Bold", 46)
        c.translate(w / 2, h / 2)
        c.rotate(40)
        c.drawCentredString(0, 0, "SANDBOX - NOT LEGALLY BINDING")
        c.restoreState()
    for f in fields:
        bx, bw, bh = f["x"] * w, f["w"] * w, f["h"] * h
        by = h - (f["y"] + f["h"]) * h  # fractions are measured from the top-left
        v = f["value"] or ""
        if f["type"] in ("signature", "initials"):
            png = png_from_data_url(v)
            if png:
                c.drawImage(ImageReader(io.BytesIO(png)), bx, by, bw, bh, preserveAspectRatio=True, mask="auto")
        elif f["type"] == "checkbox":
            if v == "true":
                c.setFont("Helvetica-Bold", max(8, bh * 0.9))
                c.drawString(bx + bw * 0.1, by + bh * 0.1, "X")
        else:
            size = max(6, min(11, bh * 0.7))
            c.setFont("Helvetica", size)
            c.drawString(bx + 2, by + (bh - size) / 2 + size * 0.2, v[:200])
    c.save()
    return buf.getvalue()


def _auth(r: dict) -> str:
    m = r.get("auth_method", "none")
    label = {"none": "Link only", "access_code": "Access code", "sms": "SMS code", "email": "Email code"}.get(m, m)
    return f"{label}" + (f" ({r['verified_at'][:19]}Z)" if r.get("verified_at") else "")


def certificate(
    env: dict, recipients: list[dict], events: list[dict], org_name: str = "", verify_url: str = ""
) -> bytes:
    st = getSampleStyleSheet()
    small = st["BodyText"].clone("small", fontSize=8, leading=10)
    P = lambda t: Paragraph(escape(str(t if t is not None else "")), small)  # noqa: E731
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
    grid = TableStyle(
        [
            ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213d")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
    )
    head = lambda *cols: [Paragraph(f'<font color="white">{escape(c)}</font>', small) for c in cols]  # noqa: E731
    story = [
        Paragraph("Certificate of Completion", st["Title"]),
        Paragraph(
            f"Envelope <b>{escape(env['id'])}</b> &nbsp; Status <b>{escape(env['status'])}</b>"
            + (" &nbsp; <b>SANDBOX - not legally binding</b>" if env["mode"] == "test" else ""),
            st["BodyText"],
        ),
        Spacer(1, 6),
        Table(
            [
                [P("Subject"), P(env["subject"])],
                [P("Sent by"), P(org_name)],
                [P("Document"), P(f"{env['doc_name']} ({env['pages']} pages)")],
                [P("Original SHA-256"), P(env["doc_sha256"])],
                [P("Created"), P(env["created_at"])],
                [P("Completed"), P(env["completed_at"])],
            ],
            colWidths=[110, 400],
            style=TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey)]),
        ),
        Spacer(1, 12),
        Paragraph("Signers", st["Heading3"]),
        Table(
            [head("Name", "Email", "Role", "Status", "Identity check", "Signed at (UTC)", "IP")]
            + [
                [
                    P(r["name"]),
                    P(r["email"]),
                    P(r["role"]),
                    P(r["status"]),
                    P(_auth(r)),
                    P(r["signed_at"]),
                    P(r["sign_ip"]),
                ]
                for r in recipients
            ],
            colWidths=[70, 105, 38, 45, 75, 95, 60],
            style=grid,
            repeatRows=1,
        ),
        Spacer(1, 12),
        Paragraph("Audit trail", st["Heading3"]),
        Table(
            [head("Time (UTC)", "Event", "Actor", "IP", "Detail")]
            + [[P(e["ts"]), P(e["type"]), P(e["actor"]), P(e["ip"]), P(e["detail"])] for e in events],
            colWidths=[100, 70, 120, 80, 140],
            style=grid,
            repeatRows=1,
        ),
        Spacer(1, 10),
        Paragraph(
            "The SHA-256 above is of the original document as uploaded. This file carries a cryptographic seal (PAdES): "
            "any change after sealing breaks it. Check a copy at "
            + escape(verify_url or "/verify")
            + " or open it in Adobe Acrobat.",
            small,
        ),
    ]
    doc.build(story)
    return buf.getvalue()


def finalize(
    original: bytes, fields: list[dict], cert: bytes, sandbox: bool, eid: str = "", subject: str = ""
) -> bytes:
    # ponytail: page /Rotate is ignored; rotated source pages would misplace stamps
    r = PdfReader(io.BytesIO(original))
    out = PdfWriter()
    for i, page in enumerate(r.pages, start=1):
        w, h = float(page.mediabox.width), float(page.mediabox.height)
        here = [f for f in fields if f["page"] == i and f["value"]]
        added = out.add_page(page)
        if here or sandbox:
            added.merge_page(PdfReader(io.BytesIO(_overlay(w, h, here, sandbox))).pages[0])
    for page in PdfReader(io.BytesIO(cert)).pages:
        out.add_page(page)
    out.add_metadata({"/Title": subject[:200], "/Producer": "HubSign", "/HubSignEnvelope": eid})
    buf = io.BytesIO()
    out.write(buf)
    return buf.getvalue()
