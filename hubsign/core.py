"""Envelope lifecycle: create -> send -> sign (sequential or parallel routing) -> complete | decline | void.

Every state change is a conditional UPDATE whose row count is checked, so two requests (or two nodes) racing on the
same envelope cannot both win.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta

from . import mail, pdfs
from .config import Settings
from .db import Database
from .identity import AuthError, Identity, mask_phone
from .seal import Sealer
from .storage import LocalStorage
from .webhooks import Webhooks

FIELD_TYPES = {"signature", "initials", "date", "name", "email", "text", "checkbox"}
DEFAULT_SIZE = {
    "signature": (0.25, 0.06),
    "initials": (0.08, 0.05),
    "date": (0.15, 0.03),
    "name": (0.22, 0.03),
    "email": (0.28, 0.03),
    "text": (0.25, 0.03),
    "checkbox": (0.025, 0.02),
}
ACTIVE = ("sent", "viewed")
AUTH_LOCK = (5, 900)  # failed verification attempts per recipient, per 15 minutes


class Error(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def rid(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def pub(status: str) -> str:
    return "sent" if status == "finalizing" else status  # finalizing is an internal, transient state


class Service:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        hooks: Webhooks,
        storage=None,
        identity: Identity | None = None,
        sealer: Sealer | None = None,
    ):
        self.s, self.db, self.hooks = settings, db, hooks
        self.storage = storage or LocalStorage(settings.data_dir / "docs")
        self.identity = identity or Identity(settings, db)
        self.sealer = sealer or Sealer(settings)

    # ---- reads ---------------------------------------------------------------------------------------------------
    def env(self, eid: str, org: str | None = None, mode: str | None = None) -> dict:
        e = self.db.one("SELECT * FROM envelopes WHERE id=?", (eid,))
        if not e or (org and (e["org_id"] != org or e["mode"] != mode)):
            raise Error(404, "envelope not found")
        return e

    def recipients(self, eid: str) -> list[dict]:
        return self.db.q("SELECT * FROM recipients WHERE envelope_id=? ORDER BY routing_order, idx", (eid,))

    def org_name(self, org_id: str) -> str:
        o = self.db.one("SELECT name FROM orgs WHERE id=?", (org_id,))
        return o["name"] if o else ""

    def summary(self, eid: str) -> dict:
        e = self.env(eid)
        return {
            "id": e["id"],
            "status": pub(e["status"]),
            "subject": e["subject"],
            "mode": e["mode"],
            "metadata": json.loads(e["metadata"]),
            "created_at": e["created_at"],
            "completed_at": e["completed_at"],
            "recipients": [
                {"id": r["id"], "name": r["name"], "email": r["email"], "status": r["status"]}
                for r in self.recipients(eid)
            ],
        }

    def detail(self, eid: str, org: str, mode: str) -> dict:
        e = self.env(eid, org, mode)
        recs = []
        for r in self.recipients(eid):
            item = {k: r[k] for k in ("id", "name", "email", "role", "routing_order", "status", "signed_at")}
            item["embedded"] = bool(r["embedded"])
            item["authentication"] = {
                "method": r["auth_method"],
                "phone": mask_phone(r["phone"]) or None,
                "verified_at": r["verified_at"],
            }
            if r["status"] in ACTIVE:  # embedded signing: the owner may hand this link to the signer
                item["signing_url"] = f"{self.s.base_url.rstrip('/')}/sign/{r['token']}"
            recs.append(item)
        fields = self.db.q(
            "SELECT id,recipient_id,type,page,x,y,w,h,required,label FROM fields WHERE envelope_id=? ORDER BY page,y,x",
            (eid,),
        )
        return {
            "id": e["id"],
            "status": pub(e["status"]),
            "mode": e["mode"],
            "subject": e["subject"],
            "message": e["message"],
            "sequential": bool(e["sequential"]),
            "metadata": json.loads(e["metadata"]),
            "document": {"name": e["doc_name"], "sha256": e["doc_sha256"], "pages": e["pages"]},
            "documents": json.loads(e["parts"]),
            "allow_reassign": bool(e["allow_reassign"]),
            "final_sha256": e["final_sha256"],
            "sealed": bool(e["final_sha256"]),
            "created_at": e["created_at"],
            "sent_at": e["sent_at"],
            "completed_at": e["completed_at"],
            "recipients": recs,
            "fields": fields,
        }

    def events(self, eid: str) -> list[dict]:
        return self.db.q("SELECT ts,type,actor,ip,ua,detail FROM events WHERE envelope_id=? ORDER BY id", (eid,))

    def _event(self, eid: str, type_: str, actor: str, ip: str = "", ua: str = "", detail: str = "") -> None:
        t = now()
        self.db.x(
            "INSERT INTO events(envelope_id,ts,type,actor,ip,ua,detail) VALUES(?,?,?,?,?,?,?)",
            (eid, t, type_, actor, ip, ua[:200], detail),
        )
        self.db.x("UPDATE envelopes SET updated_at=? WHERE id=?", (t, eid))

    def _emit(self, eid: str, event: str, recipient: dict | None = None) -> None:
        e = self.env(eid)
        data = {"envelope": self.summary(eid)}
        if recipient:
            data["recipient"] = {k: recipient[k] for k in ("id", "name", "email", "status")}
        self.hooks.emit(e["org_id"], e["mode"], event, data)

    # ---- validation and field placement ---------------------------------------------------------------------------
    def _check(self, pages: int, recipients: list[dict], fields: list[dict]) -> None:
        if not any(r["role"] == "signer" for r in recipients):
            raise Error(422, "at least one signer is required")
        if len(recipients) > 20 or len(fields) > 500:
            raise Error(422, "too many recipients or fields")
        for f in fields:
            idx = f["recipient"]
            if not 0 <= idx < len(recipients) or recipients[idx]["role"] != "signer":
                raise Error(422, "every field must belong to a signer (recipient index)")
            if f["type"] not in FIELD_TYPES:
                raise Error(422, f"unknown field type {f['type']}")
            if not 1 <= f["page"] <= pages:
                raise Error(422, f"field page {f['page']} is outside the document ({pages} pages)")
            if not (
                0 <= f["x"] <= 1
                and 0 <= f["y"] <= 1
                and f["w"] > 0
                and f["h"] > 0
                and f["x"] + f["w"] <= 1.001
                and f["y"] + f["h"] <= 1.001
            ):
                raise Error(422, "field box must lie inside the page (fractions 0..1)")
            if f.get("value") is not None and f["type"] not in ("text", "checkbox"):
                raise Error(422, "only text and checkbox fields can be prefilled")

    def _load(self, documents: list[dict]) -> tuple[bytes, list[dict]]:
        """Validate each PDF and join them. -> (one PDF, [{id, name, start, pages}] with 1-based start pages)."""
        if not 1 <= len(documents) <= 10:
            raise Error(422, "an envelope holds 1 to 10 documents")
        limit = self.s.max_doc_mb * 1024 * 1024
        if sum(len(d["data"]) for d in documents) > limit * 2:
            raise Error(413, f"documents exceed {self.s.max_doc_mb * 2} MB together")
        for d in documents:
            if len(d["data"]) > limit:
                raise Error(413, f"document exceeds {self.s.max_doc_mb} MB")
            try:
                pdfs.inspect(d["data"])
            except ValueError as e:
                raise Error(422, f"{d['name']}: {e}") from e
        ids = [d["id"] for d in documents]
        if len(set(ids)) != len(ids):
            raise Error(422, "document ids must be unique")
        if len(documents) == 1:
            data, spans = documents[0]["data"], [(1, pdfs.inspect(documents[0]["data"]))]
        else:
            data, spans = pdfs.merge([d["data"] for d in documents])
        if spans[-1][0] + spans[-1][1] - 1 > pdfs.MAX_PAGES:
            raise Error(422, f"an envelope can have at most {pdfs.MAX_PAGES} pages")
        return data, [
            {"id": d["id"], "name": d["name"], "start": sp[0], "pages": sp[1]}
            for d, sp in zip(documents, spans, strict=True)
        ]

    PT = {
        "signature": (140, 36),
        "initials": (48, 30),
        "date": (90, 14),
        "name": (150, 14),
        "email": (180, 14),
        "text": (160, 14),
        "checkbox": (12, 12),
    }

    def _place(self, pdf: bytes, parts: list[dict], fields: list[dict]) -> list[dict]:
        """Turn the caller's fields into page-fraction boxes. A field is either positioned (x, y as fractions of the
        page, `document` + `page` relative to that document) or anchored to text printed in the PDF (each occurrence
        gets one field, like DocuSign's anchor tabs). Anchor offsets are points; y grows downward."""
        out: list[dict] = []
        for f in fields:
            which = f.get("document")
            if which is not None and not 0 <= which < len(parts):
                raise Error(422, f"unknown document index {which}")
            base = {k: f.get(k) for k in ("recipient", "type", "required", "label", "value")}
            base["label"] = base["label"] or ""
            anchor = f.get("anchor")
            if not anchor:
                doc = parts[which or 0]
                if f["page"] > doc["pages"]:
                    raise Error(422, f"field page {f['page']} is outside document {doc['id']} ({doc['pages']} pages)")
                out.append(
                    {**base, "page": f["page"] + doc["start"] - 1, "x": f["x"], "y": f["y"], "w": f["w"], "h": f["h"]}
                )
                continue
            first, last = (
                (parts[which]["start"], parts[which]["start"] + parts[which]["pages"] - 1)
                if which is not None
                else (1, 10**6)
            )
            hits = [h for h in pdfs.find_anchors(pdf, anchor["text"]) if first <= h["page"] <= last]
            if not hits and not anchor.get("optional"):
                raise Error(422, f"anchor text {anchor['text']!r} was not found in the document")
            dw, dh = self.PT[f["type"]]
            for h in hits:
                w, hh = anchor.get("width") or dw, anchor.get("height") or dh
                x = min(max(h["x"] + anchor.get("x_offset", 0), 0), h["page_w"] - w)
                y = min(max(h["top"] + anchor.get("y_offset", 0), 0), h["page_h"] - hh)
                out.append(
                    {
                        **base,
                        "page": h["page"],
                        "x": x / h["page_w"],
                        "y": y / h["page_h"],
                        "w": w / h["page_w"],
                        "h": hh / h["page_h"],
                    }
                )
        return out

    # ---- create / send -------------------------------------------------------------------------------------------
    def create(self, org, user, mode, *, subject, message, documents, recipients, fields, sequential, metadata,
               allow_reassign=False, reply_to=None, sender_name="") -> str:  # fmt: skip
        pdf, parts = self._load(documents)
        pages = sum(p["pages"] for p in parts)
        fields = self._place(pdf, parts, fields)
        self._check(pages, recipients, fields)
        try:
            auth = [self.identity.prepare(r.get("authentication"), mode) for r in recipients]
        except AuthError as e:
            raise Error(e.status, e.msg) from e
        eid = rid("env")
        self.storage.put(f"{eid}.pdf", pdf)
        t = now()
        names = ", ".join(p["name"] for p in parts)
        self.db.x(
            "INSERT INTO envelopes(id,org_id,created_by,mode,subject,message,status,sequential,doc_name,doc_sha256,pages,metadata,"
            "created_at,updated_at,parts,allow_reassign,reply_to,sender_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, org, user, mode, subject, message, "draft", int(sequential), names[:200], hashlib.sha256(pdf).hexdigest(), pages,
             json.dumps(metadata), t, t, json.dumps(parts), int(allow_reassign), json.dumps(reply_to) if reply_to else None, sender_name),
        )  # fmt: skip
        ids = []
        for i, (r, (method, secret, phone)) in enumerate(zip(recipients, auth, strict=True)):
            ids.append(rid("rcp"))
            self.db.x(
                "INSERT INTO recipients(id,envelope_id,idx,name,email,phone,role,routing_order,token,status,auth_method,auth_secret,embedded,return_url)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ids[-1], eid, i, r["name"], r["email"], phone, r["role"], r["routing_order"], secrets.token_urlsafe(32), "created", method, secret,
                 int(bool(r.get("embedded"))), r.get("return_url")),
            )  # fmt: skip
        for f in fields:
            locked = f.get("value") is not None
            self.db.x(
                "INSERT INTO fields(id,envelope_id,recipient_id,type,page,x,y,w,h,required,label,value,locked) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rid("fld"), eid, ids[f["recipient"]], f["type"], f["page"], f["x"], f["y"], f["w"], f["h"], int(f["required"]), f["label"] or "",
                 f["value"] if locked else None, int(locked)),
            )  # fmt: skip
        self._event(eid, "created", "api")
        return eid

    def send(self, eid: str, org: str, mode: str) -> None:
        self.env(eid, org, mode)
        for r in self.recipients(eid):
            if r["role"] == "signer" and not self.db.one(
                "SELECT 1 AS x FROM fields WHERE recipient_id=? AND type IN ('signature','initials')", (r["id"],)
            ):
                raise Error(422, f"signer {r['email']} needs at least one signature or initials field")
        if not self.db.x("UPDATE envelopes SET status='sent', sent_at=? WHERE id=? AND status='draft'", (now(), eid)):
            raise Error(409, "only drafts can be sent")
        self._event(eid, "sent", "owner")
        self._emit(eid, "envelope.sent")
        self._advance(eid)

    def void(self, eid: str, org: str, mode: str, reason: str) -> None:
        self.env(eid, org, mode)
        if not self.db.x("UPDATE envelopes SET status='voided' WHERE id=? AND status IN ('draft','sent')", (eid,)):
            raise Error(409, "this envelope can no longer be voided")
        self._event(eid, "voided", "owner", detail=reason[:300])
        self._emit(eid, "envelope.voided")

    def delete_draft(self, eid: str, org: str, mode: str) -> None:
        self.env(eid, org, mode)
        if not self.db.x("UPDATE envelopes SET status='deleting' WHERE id=? AND status='draft'", (eid,)):
            raise Error(409, "only drafts can be deleted; void a sent envelope instead")
        for t in ("fields", "recipients", "events"):
            self.db.x(f"DELETE FROM {t} WHERE envelope_id=?", (eid,))
        self.db.x("DELETE FROM envelopes WHERE id=?", (eid,))
        self.storage.delete(f"{eid}.pdf")

    def _advance(self, eid: str) -> None:
        e = self.env(eid)
        pending = [r for r in self.recipients(eid) if r["role"] == "signer" and r["status"] != "signed"]
        if not pending:
            return self._finalize(eid)
        lowest = min(r["routing_order"] for r in pending)
        for r in pending:
            if r["status"] == "created" and (not e["sequential"] or r["routing_order"] == lowest):
                if not self.db.x("UPDATE recipients SET status='sent' WHERE id=? AND status='created'", (r["id"],)):
                    continue  # another request activated them
                r["status"] = "sent"
                self._event(eid, "recipient_sent", r["email"])
                self._emit(eid, "recipient.sent", r)
                self._mail(
                    r,
                    e,
                    f"Please sign: {e['subject']}",
                    e["message"],
                    "Review and sign",
                    f"Please review and sign: {e['subject']}",
                )

    def _finalize(self, eid: str) -> None:
        if not self.db.x(
            "UPDATE envelopes SET status='finalizing', updated_at=? WHERE id=? AND status='sent'", (now(), eid)
        ):
            return  # someone else is finalizing, or it is already done
        try:
            t = now()
            e = self.env(eid)
            e = {**e, "status": "completed", "completed_at": t}
            recs = self.recipients(eid)
            events = [*self.events(eid), {"ts": t, "type": "completed", "actor": "system", "ip": "", "detail": ""}]
            cert = pdfs.certificate(
                e, recs, events, org_name=self.org_name(e["org_id"]), verify_url=self.s.base_url.rstrip("/") + "/verify"
            )
            fields = self.db.q("SELECT * FROM fields WHERE envelope_id=?", (eid,))
            original = self.storage.get(f"{eid}.pdf")
            final = pdfs.finalize(original, fields, cert, e["mode"] == "test", eid, e["subject"])
            sealed = self.sealer.seal(final, reason=f"Completed envelope {eid}")
            self.storage.put(f"{eid}.signed.pdf", sealed)
        except Exception:
            self.db.x(
                "UPDATE envelopes SET status='sent' WHERE id=? AND status='finalizing'", (eid,)
            )  # the sweeper retries
            raise
        self.db.x(
            "UPDATE envelopes SET status='completed', completed_at=?, final_sha256=? WHERE id=?",
            (t, hashlib.sha256(sealed).hexdigest(), eid),
        )
        self._event(eid, "completed", "system")
        self._emit(eid, "envelope.completed")
        for r in recs:
            self._mail(
                r,
                e,
                f"Completed: {e['subject']}",
                "All parties have signed. Your copy is ready to download.",
                "View the signed document",
                f"Completed: {e['subject']}",
            )

    def maintenance(self) -> None:
        """Called by the worker: finish envelopes whose last signer signed but whose finalize failed or stalled."""
        stale = (datetime.now(UTC) - timedelta(minutes=5)).isoformat(timespec="microseconds")
        self.db.x("UPDATE envelopes SET status='sent' WHERE status='finalizing' AND updated_at < ?", (stale,))
        stuck = self.db.q(
            "SELECT id FROM envelopes WHERE status='sent' AND NOT EXISTS (SELECT 1 FROM recipients r WHERE r.envelope_id=envelopes.id "
            "AND r.role='signer' AND r.status<>'signed') LIMIT 10"
        )
        for e in stuck:
            try:
                self._finalize(e["id"])
            except Exception:
                pass

    # ---- templates -----------------------------------------------------------------------------------------------
    def create_template(
        self, org, user, mode, *, name, description, doc: bytes, doc_name, roles, fields, sequential
    ) -> str:
        pdf, parts = self._load([{"id": "1", "name": doc_name, "data": doc}])
        fields = self._place(pdf, parts, fields)
        self._check(parts[0]["pages"], roles, fields)
        for r in roles:
            if (r.get("authentication") or {}).get("method", "none") not in ("none", "sms", "email", "access_code"):
                raise Error(422, "unknown authentication method")
        tid = rid("tpl")
        self.storage.put(f"{tid}.pdf", doc)
        self.db.x(
            "INSERT INTO templates(id,org_id,created_by,mode,name,description,doc_name,pages,roles,fields,sequential,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (tid, org, user, mode, name, description, doc_name, parts[0]["pages"], json.dumps(roles), json.dumps(fields), int(sequential), now()),
        )  # fmt: skip
        return tid

    def template(self, tid: str, org: str, mode: str) -> dict:
        t = self.db.one("SELECT * FROM templates WHERE id=? AND org_id=? AND mode=?", (tid, org, mode))
        if not t:
            raise Error(404, "template not found")
        return t | {
            "roles": json.loads(t["roles"]),
            "fields": json.loads(t["fields"]),
            "sequential": bool(t["sequential"]),
        }

    def delete_template(self, tid: str, org: str, mode: str) -> None:
        self.template(tid, org, mode)
        self.db.x("DELETE FROM templates WHERE id=?", (tid,))
        self.storage.delete(f"{tid}.pdf")

    def use_template(self, tid, org, user, mode, *, people, subject, message, metadata, send) -> str:
        t = self.template(tid, org, mode)
        if len(people) != len(t["roles"]):
            raise Error(422, f"this template has {len(t['roles'])} roles; send one recipient per role")
        recipients = []
        for r, p in zip(t["roles"], people, strict=True):
            method = (r.get("authentication") or {}).get("method", "none")
            recipients.append(
                {
                    "name": p["name"],
                    "email": p["email"],
                    "role": r["role"],
                    "routing_order": r["routing_order"],
                    "authentication": {"method": method, "access_code": p.get("access_code"), "phone": p.get("phone")},
                }  # fmt: skip
            )
        doc = self.storage.get(f"{tid}.pdf")
        eid = self.create(
            org, user, mode, subject=subject or t["name"], message=message, documents=[{"id": "1", "name": t["doc_name"], "data": doc}], recipients=recipients,
            fields=t["fields"], sequential=t["sequential"], metadata=metadata,
        )  # fmt: skip
        if send:
            self.send(eid, org, mode)
        return eid

    # ---- bulk send -----------------------------------------------------------------------------------------------
    def create_batch(self, org, user, mode, tid, *, rows, subject, message, send) -> str:
        t = self.template(tid, org, mode)
        if not 1 <= len(rows) <= self.s.bulk_max_rows:
            raise Error(422, f"a batch must have 1 to {self.s.bulk_max_rows} rows")
        for i, row in enumerate(rows):
            if len(row) != len(t["roles"]):
                raise Error(422, f"row {i + 1} has {len(row)} recipients but the template has {len(t['roles'])} roles")
            if any(p.get("access_code") for p in row):
                raise Error(422, "access codes are not supported in bulk send; use SMS or email codes")
        bid = rid("bat")
        self.db.x(
            "INSERT INTO batches(id,org_id,created_by,mode,template_id,subject,message,send,total,done,failed,status,rows,errors,created_at,updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (bid, org, user, mode, tid, subject, message, int(send), len(rows), 0, 0, "queued", json.dumps(rows), json.dumps({"errors": [], "envelopes": []}), now(), now()),
        )  # fmt: skip
        if self.s.webhooks_inline:
            self.process_batches()
        return bid

    def batch(self, bid: str, org: str, mode: str) -> dict:
        b = self.db.one("SELECT * FROM batches WHERE id=? AND org_id=? AND mode=?", (bid, org, mode))
        if not b:
            raise Error(404, "batch not found")
        e = json.loads(b["errors"])
        return {k: b[k] for k in ("id", "template_id", "total", "done", "failed", "status", "created_at")} | {
            "send": bool(b["send"]), "errors": e["errors"], "envelope_ids": e["envelopes"],
        }  # fmt: skip

    def process_batches(self) -> None:
        stale = (datetime.now(UTC) - timedelta(minutes=5)).isoformat(timespec="microseconds")
        self.db.x("UPDATE batches SET status='queued' WHERE status='running' AND updated_at < ?", (stale,))
        for b in self.db.q("SELECT id FROM batches WHERE status='queued' ORDER BY created_at LIMIT 3"):
            if self.db.x(
                "UPDATE batches SET status='running', updated_at=? WHERE id=? AND status='queued'", (now(), b["id"])
            ):
                self._run_batch(b["id"])

    def _run_batch(self, bid: str) -> None:
        b = self.db.one("SELECT * FROM batches WHERE id=?", (bid,))
        rows, info = json.loads(b["rows"]), json.loads(b["errors"])
        done, failed = b["done"], b["failed"]
        for i in range(done + failed, len(rows)):  # resumes where a crashed worker stopped
            try:
                eid = self.use_template(
                    b["template_id"], b["org_id"], b["created_by"], b["mode"], people=rows[i], subject=b["subject"], message=b["message"],
                    metadata={"batch": bid, "row": str(i + 1)}, send=bool(b["send"]),
                )  # fmt: skip
                info["envelopes"].append(eid)
                done += 1
            except Error as e:
                failed += 1
                if len(info["errors"]) < 50:
                    info["errors"].append({"row": i + 1, "error": e.msg})
            self.db.x(
                "UPDATE batches SET done=?, failed=?, errors=?, updated_at=? WHERE id=?",
                (done, failed, json.dumps(info), now(), bid),
            )
        status = "done" if not failed else ("failed" if not done else "partial")
        self.db.x(
            "UPDATE batches SET status=?, rows='[]', updated_at=? WHERE id=?", (status, now(), bid)
        )  # drop recipient data once processed

    # ---- signer side (public, by token) ------------------------------------------------------------------------------
    def by_token(self, token: str) -> tuple[dict, dict]:
        r = self.db.one("SELECT * FROM recipients WHERE token=?", (token,))
        if not r:
            raise Error(404, "link not found")
        return r, self.env(r["envelope_id"])

    @staticmethod
    def state(r: dict, e: dict) -> str:
        st = pub(e["status"])
        if st in ("voided", "declined", "completed"):
            return st
        if r["status"] == "signed":
            return "signed"
        return "ready" if r["status"] in ACTIVE else "waiting"

    def require_session(self, r: dict, cookie: str | None) -> None:
        if not self.identity.session_ok(r, cookie):
            raise Error(401, "verification required")

    def auth_info(self, r: dict) -> dict:
        hint = (
            mask_phone(r["phone"])
            if r["auth_method"] == "sms"
            else (r["email"][:1] + "•••@" + r["email"].partition("@")[2] if r["auth_method"] == "email" else "")
        )
        return {"method": r["auth_method"], "hint": hint}

    def signer_view(self, token: str, ip: str, ua: str, cookie: str | None = None) -> dict:
        r, e = self.by_token(token)
        st = self.state(r, e)
        base = {
            "subject": e["subject"],
            "sender": self.org_name(e["org_id"]),
            "sandbox": e["mode"] == "test",
            "recipient": {"name": r["name"], "email": r["email"], "role": r["role"]},
        }
        if (
            r["auth_method"] != "none"
            and not self.identity.session_ok(r, cookie)
            and st in ("ready", "signed", "completed")
        ):
            return {"state": "verify", "auth": self.auth_info(r), **base, "message": "", "pages": 0, "fields": []}
        if st == "ready" and r["status"] == "sent" and r["role"] == "signer":
            if self.db.x("UPDATE recipients SET status='viewed' WHERE id=? AND status='sent'", (r["id"],)):
                r["status"] = "viewed"
                self._event(e["id"], "viewed", r["email"], ip, ua)
                self._emit(e["id"], "recipient.viewed", r)
        fields = []
        if st == "ready":
            fields = self.db.q(
                "SELECT id,type,page,x,y,w,h,required,label,locked,value FROM fields WHERE recipient_id=? ORDER BY page,y,x",
                (r["id"],),
            )
        for f in fields:
            if f["type"] in ("signature", "initials") or not f["locked"]:
                f["value"] = None  # only prefilled text is sent down
        base["return_url"] = r["return_url"]
        base["allow_reassign"] = (
            bool(e["allow_reassign"]) and r["role"] == "signer" and r["auth_method"] in ("none", "email")
        )
        return {
            "state": st,
            "message": e["message"],
            "pages": e["pages"],
            "fields": fields,
            "auth": self.auth_info(r),
            **base,
        }

    def auth_send(self, token: str, ip: str, ua: str) -> None:
        r, e = self.by_token(token)
        if self.state(r, e) not in ("ready", "signed", "completed"):
            raise Error(409, "nothing to verify yet")
        try:
            self.identity.send_code(r, e["mode"])
        except AuthError as x:
            raise Error(x.status, x.msg) from x
        self._event(e["id"], "auth_sent", r["email"], ip, ua, r["auth_method"])

    def auth_verify(self, token: str, code: str, ip: str, ua: str) -> str:
        r, e = self.by_token(token)
        if r["auth_method"] == "none":
            raise Error(400, "this link does not need verification")
        limit, window = AUTH_LOCK
        allowed, remaining, wait = self.db.hit(f"authfail:{r['id']}", limit, window)
        if not allowed:
            raise Error(429, f"too many attempts, try again in {wait // 60 + 1} minutes")
        try:
            ok = self.identity.check(r, code)
        except AuthError as x:
            raise Error(x.status, x.msg) from x
        if not ok:
            self._event(e["id"], "auth_failed", r["email"], ip, ua, r["auth_method"])
            if remaining == 0:  # that was the last allowed attempt: the recipient is now locked out
                self._emit(e["id"], "recipient.auth_failed", r)
            raise Error(401, "that code is not correct")
        self.db.reset_hits(f"authfail:{r['id']}")
        tok, h, exp = self.identity.new_session()
        self.db.x(
            "UPDATE recipients SET session_hash=?, session_expires=?, verified_at=? WHERE id=?",
            (h, exp, now(), r["id"]),
        )
        self._event(e["id"], "auth_ok", r["email"], ip, ua, r["auth_method"])
        return tok

    def complete(self, token: str, values: dict, ip: str, ua: str, cookie: str | None = None) -> dict:
        r, e = self.by_token(token)
        self.require_session(r, cookie)
        if self.state(r, e) != "ready":
            raise Error(409, f"cannot sign: envelope is {self.state(r, e)}")
        mine = self.db.q("SELECT * FROM fields WHERE recipient_id=?", (r["id"],))
        clean: dict[str, str] = {}
        for f in mine:
            if f["locked"]:
                continue  # prefilled by the sender: the signer cannot change it
            v = values.get(f["id"])
            if f["type"] == "date":
                v = datetime.now(UTC).date().isoformat()  # never trust a client-supplied signing date
            elif f["type"] in ("name", "email"):
                v = r[f["type"]]  # taken from the recipient record, not the client
            elif f["type"] in ("signature", "initials"):
                if v is not None and not pdfs.png_from_data_url(str(v)):
                    raise Error(422, f"{f['type']} must be a PNG data URL")
            elif f["type"] == "checkbox":
                v = "true" if v in (True, "true") else ("false" if v is not None else None)
                if f["required"] and v != "true":
                    v = None
            else:
                v = str(v).strip()[:500] if v is not None else None
            if f["required"] and not v:
                raise Error(422, f"required {f['type']} field is empty")
            if v:
                clean[f["id"]] = v
        for fid, v in clean.items():
            self.db.x("UPDATE fields SET value=? WHERE id=?", (v, fid))
        if not self.db.x(
            "UPDATE recipients SET status='signed', signed_at=?, sign_ip=? WHERE id=? AND status IN ('sent','viewed')",
            (now(), ip, r["id"]),
        ):
            raise Error(409, "already signed")
        r["status"] = "signed"
        self._event(e["id"], "consent", r["email"], ip, ua, "agreed to use electronic records and signatures")
        self._event(e["id"], "signed", r["email"], ip, ua)
        self._emit(e["id"], "recipient.signed", r)
        self._advance(e["id"])
        return {"state": self.state(r, self.env(e["id"]))}

    def decline(self, token: str, reason: str, ip: str, ua: str, cookie: str | None = None) -> None:
        r, e = self.by_token(token)
        self.require_session(r, cookie)
        if self.state(r, e) != "ready":
            raise Error(409, f"cannot decline: envelope is {self.state(r, e)}")
        if not self.db.x("UPDATE envelopes SET status='declined' WHERE id=? AND status='sent'", (e["id"],)):
            raise Error(409, "this envelope can no longer be declined")
        self.db.x("UPDATE recipients SET status='declined' WHERE id=?", (r["id"],))
        r["status"] = "declined"
        self._event(e["id"], "declined", r["email"], ip, ua, reason[:300])
        self._emit(e["id"], "recipient.declined", r)
        self._emit(e["id"], "envelope.declined")

    def reassign(self, token: str, name: str, email: str, ip: str, ua: str, cookie: str | None = None) -> None:
        """The signer hands their part to someone else (e.g. their accountant). The old link stops working."""
        r, e = self.by_token(token)
        self.require_session(r, cookie)
        if not e["allow_reassign"] or r["role"] != "signer" or r["auth_method"] not in ("none", "email"):
            raise Error(403, "this document cannot be reassigned")
        if self.state(r, e) != "ready":
            raise Error(409, f"cannot reassign: envelope is {self.state(r, e)}")
        if email.lower() == r["email"].lower():
            raise Error(422, "pick someone else")
        new = secrets.token_urlsafe(32)
        if not self.db.x(
            "UPDATE recipients SET name=?, email=?, token=?, status='sent', session_hash=NULL, session_expires=NULL, verified_at=NULL "
            "WHERE id=? AND token=? AND status IN ('sent','viewed')",
            (name, email.lower(), new, r["id"], token),
        ):
            raise Error(409, "already changed")
        self._event(e["id"], "reassigned", r["email"], ip, ua, f"to {email.lower()}")
        r2 = self.db.one("SELECT * FROM recipients WHERE id=?", (r["id"],))
        self._emit(e["id"], "recipient.reassigned", r2)
        self._mail(
            r2,
            e,
            f"Please sign: {e['subject']}",
            e["message"],
            "Review and sign",
            f"Please review and sign: {e['subject']}",
        )

    def form_data(self, eid: str, org: str, mode: str) -> dict[str, str]:
        """What signers typed or ticked, by field label. Signatures and initials are images and are not included."""
        self.env(eid, org, mode)
        rows = self.db.q(
            "SELECT label, type, value FROM fields WHERE envelope_id=? AND label<>'' AND value IS NOT NULL ORDER BY page, y, x",
            (eid,),
        )
        return {r["label"]: r["value"] for r in rows if r["type"] not in ("signature", "initials")}

    def document_excerpt(self, eid: str, doc_id: str, org: str, mode: str) -> tuple[bytes, str]:
        """One document of a completed envelope with its signatures on, sealed on its own (the whole-file seal covers
        the combined PDF, so an excerpt is signed again as an excerpt)."""
        e = self.env(eid, org, mode)
        if e["status"] != "completed":
            raise Error(409, "it isn't signed yet")
        part = next((p for p in json.loads(e["parts"]) if p["id"] == doc_id), None)
        if not part:
            raise Error(404, "no such document in this envelope")
        whole = self.file_bytes(eid, True)
        piece = pdfs.excerpt(whole, part["start"], part["pages"])
        return self.sealer.seal(piece, reason=f"Document {doc_id} of completed envelope {eid}"), part["name"]

    def file_bytes(self, eid: str, signed: bool) -> bytes:
        data = self.storage.get(f"{eid}.signed.pdf" if signed else f"{eid}.pdf")
        if data is None:
            raise Error(404, "document not available")
        return data

    # ---- mail ----------------------------------------------------------------------------------------------------
    def _mail(self, r: dict, e: dict, subject: str, body: str, button: str, headline: str) -> None:
        if r.get("embedded"):
            return  # they sign inside the sender's own app and are never emailed
        link = f"{self.s.base_url.rstrip('/')}/sign/{r['token']}"
        sender = e.get("sender_name") or self.org_name(e["org_id"]) or "Someone"
        reply = json.loads(e["reply_to"]) if e.get("reply_to") else None
        text = f"Hi {r['name']},\n\n{sender} sent you a document.\n\n{body}\n\n{link}\n\nThe link is personal to you.\n-- HubSign"
        html = mail.signing_html(
            sender=sender, name=r["name"], headline=headline, message=body, link=link, button=button
        )
        mail.send(
            self.s,
            r["email"],
            subject,
            text,
            html=html,
            reply_to=reply,
            from_name=sender,
            background=not self.s.webhooks_inline,
        )
