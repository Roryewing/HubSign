"""Find the fields in a PDF so a template does not have to be drawn by hand.

Ported from DocuSeal (AGPL-3.0, https://github.com/docusealco/docuseal, lib/templates/find_pdfium_acro_fields.rb and
detect_fields.rb): form fields already in the PDF are imported, and printed labels ("Signature:", "Date:", an empty
checkbox) get a field placed beside them. DocuSeal's machine-learning box detector is not ported (its model file is
not in the repository). Boxes are fractions of the page from the top-left, pages are 1-based.
"""

from __future__ import annotations

import io
import re

from pdfminer.converter import PDFPageAggregator
from pdfminer.layout import LAParams, LTChar, LTCurve, LTLine, LTRect, LTTextContainer, LTTextLine
from pdfminer.pdfinterp import PDFPageInterpreter, PDFResourceManager
from pdfminer.pdfpage import PDFPage
from pypdf import PdfReader

_TAIL = r"[:_\s-]*\Z"
DATE_RE = re.compile(rf"(?:date|signed\sat|datum){_TAIL}", re.I)
SIGNATURE_RE = re.compile(rf"(?:signature|sign\shere|sign|signez\sici|unterschrift|unterschreiben){_TAIL}", re.I)
INITIALS_RE = re.compile(rf"initials?{_TAIL}", re.I)
NAME_RE = re.compile(rf"(?:print(?:ed)?\sname|full\sname){_TAIL}", re.I)
CHECKBOXES = "☐□"
DATE_JS = "AFDate_"

# (width, height) in points when the page gives no line to size the field from
DEFAULT_PT = {
    "signature": (140, 36),
    "initials": (48, 30),
    "date": (90, 14),
    "name": (150, 14),
    "text": (160, 14),
    "checkbox": (12, 12),
}


def detect(pdf: bytes) -> list[dict]:
    """Form fields in the PDF, plus label-based fields wherever a form field does not already cover the spot."""
    found = acro_fields(pdf)
    for f in label_fields(pdf):
        if not any(_overlap(f, g) for g in found):
            found.append(f)
    found.sort(key=lambda f: (f["page"], round(f["y"], 2), f["x"]))
    return found


def _overlap(a: dict, b: dict) -> bool:
    if a["page"] != b["page"]:
        return False
    return (
        a["x"] < b["x"] + b["w"] and b["x"] < a["x"] + a["w"] and a["y"] < b["y"] + b["h"] and b["y"] < a["y"] + a["h"]
    )


# ---- form fields (AcroForm) -------------------------------------------------------------------------------------


def _inherited(obj, key):
    while obj is not None:
        if key in obj:
            return obj[key]
        obj = obj.get("/Parent")
        obj = obj.get_object() if obj is not None else None
    return None


def _full_name(obj) -> str:
    parts = []
    while obj is not None:
        if "/T" in obj:
            parts.append(str(obj["/T"]))
        obj = obj.get("/Parent")
        obj = obj.get_object() if obj is not None else None
    return ".".join(reversed(parts))


def _js(obj) -> str:
    aa = _inherited(obj, "/AA")
    if aa is None:
        return ""
    out = []
    for k in ("/F", "/K"):
        action = aa.get_object().get(k)
        js = action.get_object().get("/JS") if action is not None else None
        if js is not None:
            out.append(
                str(js.get_object().get_data().decode("latin-1") if hasattr(js.get_object(), "get_data") else js)
            )
    return " ".join(out)


def _box(rect, page) -> tuple[float, float, float, float] | None:
    """Widget rectangle -> (x, y, w, h) fractions from the top-left, honouring page rotation."""
    x0, y0, x1, y1 = (float(v) for v in rect)
    x0, x1, y0, y1 = min(x0, x1), max(x0, x1), min(y0, y1), max(y0, y1)
    mb = page.mediabox
    ox, oy, pw, ph = float(mb.left), float(mb.bottom), float(mb.width), float(mb.height)
    x0, x1, y0, y1 = x0 - ox, x1 - ox, y0 - oy, y1 - oy
    rot = (page.get("/Rotate") or 0) % 360
    if rot == 90:
        (x0, y0, x1, y1), (pw, ph) = (y0, pw - x1, y1, pw - x0), (ph, pw)
    elif rot == 180:
        x0, y0, x1, y1 = pw - x1, ph - y1, pw - x0, ph - y0
    elif rot == 270:
        (x0, y0, x1, y1), (pw, ph) = (ph - y1, x0, ph - y0, x1), (ph, pw)
    w, h = (x1 - x0) / pw, (y1 - y0) / ph
    if w <= 0 or h <= 0:
        return None
    return x0 / pw, 1 - y1 / ph, w, h


def acro_fields(pdf: bytes) -> list[dict]:
    try:
        reader = PdfReader(io.BytesIO(pdf))
        pages = list(reader.pages)
    except Exception:
        return []
    out = []
    for n, page in enumerate(pages, start=1):
        for ref in page.get("/Annots") or []:
            w = ref.get_object()
            if w.get("/Subtype") != "/Widget" or "/Rect" not in w:
                continue
            ft, ff = _inherited(w, "/FT"), int(_inherited(w, "/Ff") or 0)
            name = _full_name(w)
            label = name if re.fullmatch(r"(?=.*[^\W\d_])[\w\s.-]+", name) else ""
            if ft == "/Tx":
                value = _inherited(w, "/V")
                if value not in (None, ""):
                    continue  # already filled in: not for a signer to complete
                kind = "date" if DATE_JS in _js(w) or DATE_RE.search(name) else "text"
                if INITIALS_RE.search(name):
                    kind = "initials"
            elif ft == "/Btn":
                if ff & (1 << 16):
                    continue  # push button
                kind = "checkbox"
            elif ft == "/Sig":
                kind = "initials" if "initials" in name.lower() else "signature"
            elif ft == "/Ch":
                kind = "text"
            else:
                continue
            box = _box(w["/Rect"], page)
            if box is None:
                continue
            x, y, bw, bh = box
            out.append({"type": kind, "page": n, "x": x, "y": y, "w": bw, "h": bh, "required": bool(ff & 2),
                        "label": label[:100], "source": "form"})  # fmt: skip
    return out


# ---- printed labels ---------------------------------------------------------------------------------------------


def _layout(pdf: bytes):
    rm = PDFResourceManager()
    dev = PDFPageAggregator(rm, laparams=LAParams())
    it = PDFPageInterpreter(rm, dev)
    for n, pg in enumerate(PDFPage.get_pages(io.BytesIO(pdf)), start=1):
        it.process_page(pg)
        yield n, dev.get_result()


def _walk(items):
    for o in items:
        if isinstance(o, LTTextContainer):
            yield from (t for t in o if isinstance(t, LTTextLine))
        elif isinstance(o, (LTLine, LTRect, LTCurve)):
            yield o


def _field(page, kind, x0, top, x1, bottom, n, label="") -> dict:
    pw, ph = page.width, page.height
    return {"type": kind, "page": n, "x": max(x0, 0) / pw, "y": max(top, 0) / ph, "w": (x1 - x0) / pw,
            "h": (bottom - top) / ph, "required": kind in ("signature", "initials"), "label": label, "source": "label"}  # fmt: skip


def label_fields(pdf: bytes) -> list[dict]:
    out = []
    for n, page in _layout(pdf):
        items = list(_walk(page))
        # thin horizontal strokes are underlines: (x0, x1, y), y from the bottom of the page
        rules = [(o.x0, o.x1, (o.y0 + o.y1) / 2) for o in items
                 if isinstance(o, (LTLine, LTRect, LTCurve)) and o.height < 2 and o.width > 30]  # fmt: skip
        for raw in (o for o in items if isinstance(o, LTTextLine)):
            # invisible anchor text (white or tiny, like ~cus-sign~) shares the line with the label: ignore it
            vis = [c for c in raw if isinstance(c, LTChar) and c.size >= MIN_VISIBLE_PT]
            text = "".join(c.get_text() for c in vis).strip()
            if not text:
                continue
            line = _Span(min(c.x0 for c in vis), max(c.x1 for c in vis), min(c.y0 for c in vis), max(c.y1 for c in vis))
            for ch in (c for c in raw if isinstance(c, LTChar) and c.get_text() in CHECKBOXES):
                s = max(ch.width, ch.height, 8)
                out.append(_field(page, "checkbox", ch.x0, page.height - ch.y0 - s, ch.x0 + s, page.height - ch.y0, n))
            kind = next((k for k, rx in (("signature", SIGNATURE_RE), ("initials", INITIALS_RE), ("date", DATE_RE),
                                         ("name", NAME_RE)) if rx.search(text)), None)  # fmt: skip
            if kind is None:
                continue
            dw, dh = DEFAULT_PT[kind]
            base = (line.y0 + line.y1) / 2
            # an underline to the right of the label on the same line, else just under it
            near = [r for r in rules if r[0] >= line.x0 and abs(r[2] - line.y0) <= 8 and r[1] > line.x1 - 2]
            if near:
                x0, x1, y = min(near, key=lambda r: r[0])
                x0 = max(x0, line.x1 + 2) if x0 < line.x1 else x0
                x1 = max(x1, x0 + 40)
                out.append(
                    _field(page, kind, x0, page.height - y - dh, x1, page.height - y, n, text.strip(":_ -")[:100])
                )
            else:
                # no rule: take the blank after the label (underscores count as the blank), else a default box
                blank = len(text) - len(text.rstrip(_BLANK))
                x0 = line.x1 + 4 if blank == 0 else line.x1 - line.width * blank / len(text)
                x1 = x0 + (line.x1 - x0 if blank else dw)
                out.append(_field(page, kind, x0, page.height - base - dh / 2, x1, page.height - base + dh / 2, n,
                                  text.strip(":_ -")[:100]))  # fmt: skip
    return out


_BLANK = "_ -:"
MIN_VISIBLE_PT = 4


class _Span:
    """Bounding box of a line's visible characters."""

    def __init__(self, x0, x1, y0, y1):
        self.x0, self.x1, self.y0, self.y1 = x0, x1, y0, y1
        self.width = x1 - x0
