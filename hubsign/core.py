"""Envelope lifecycle: create -> send -> sign (sequential or parallel routing) -> complete | decline | void."""

from __future__ import annotations

import hashlib
import json
import secrets
import smtplib
import threading
from datetime import UTC, datetime
from email.message import EmailMessage

from . import pdfs
from .config import Settings
from .db import Database
from .webhooks import Webhooks

FIELD_TYPES = {"signature", "initials", "date", "text", "checkbox"}
DEFAULT_SIZE = {
    "signature": (0.25, 0.06),
    "initials": (0.08, 0.05),
    "date": (0.15, 0.03),
    "text": (0.25, 0.03),
    "checkbox": (0.025, 0.02),
}
ACTIVE = ("sent", "viewed")


class Error(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def rid(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


class Service:
    def __init__(self, settings: Settings, db: Database, hooks: Webhooks):
        self.s, self.db, self.hooks = settings, db, hooks
        self.docs = settings.data_dir / "docs"
        self.docs.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()  # serialises signing so two clicks cannot both complete a recipient

    # ---- reads ---------------------------------------------------------------------------------------------------
    def env(self, eid: str, uid: str | None = None, mode: str | None = None) -> dict:
        e = self.db.one("SELECT * FROM envelopes WHERE id=?", (eid,))
        if not e or (uid and (e["user_id"] != uid or e["mode"] != mode)):
            raise Error(404, "envelope not found")
        return e

    def recipients(self, eid: str) -> list[dict]:
        return self.db.q("SELECT * FROM recipients WHERE envelope_id=? ORDER BY routing_order, rowid", (eid,))

    def summary(self, eid: str) -> dict:
        e = self.env(eid)
        return {
            "id": e["id"],
            "status": e["status"],
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

    def detail(self, eid: str, uid: str, mode: str) -> dict:
        e = self.env(eid, uid, mode)
        recs = []
        for r in self.recipients(eid):
            item = {k: r[k] for k in ("id", "name", "email", "role", "routing_order", "status", "signed_at")}
            if r["status"] in ACTIVE:  # embedded signing: the owner may hand this link to the signer
                item["signing_url"] = f"{self.s.base_url.rstrip('/')}/sign/{r['token']}"
            recs.append(item)
        fields = self.db.q(
            "SELECT id,recipient_id,type,page,x,y,w,h,required,label FROM fields WHERE envelope_id=? ORDER BY page,y,x",
            (eid,),
        )
        return {
            "id": e["id"],
            "status": e["status"],
            "mode": e["mode"],
            "subject": e["subject"],
            "message": e["message"],
            "sequential": bool(e["sequential"]),
            "metadata": json.loads(e["metadata"]),
            "document": {"name": e["doc_name"], "sha256": e["doc_sha256"], "pages": e["pages"]},
            "final_sha256": e["final_sha256"],
            "created_at": e["created_at"],
            "sent_at": e["sent_at"],
            "completed_at": e["completed_at"],
            "recipients": recs,
            "fields": fields,
        }

    def events(self, eid: str) -> list[dict]:
        return self.db.q("SELECT ts,type,actor,ip,ua,detail FROM events WHERE envelope_id=? ORDER BY id", (eid,))

    def _event(self, eid: str, type_: str, actor: str, ip: str = "", ua: str = "", detail: str = "") -> None:
        self.db.x(
            "INSERT INTO events(envelope_id,ts,type,actor,ip,ua,detail) VALUES(?,?,?,?,?,?,?)",
            (eid, now(), type_, actor, ip, ua[:200], detail),
        )
        self.db.x("UPDATE envelopes SET updated_at=? WHERE id=?", (now(), eid))

    def _emit(self, eid: str, event: str, recipient: dict | None = None) -> None:
        e = self.env(eid)
        data = {"envelope": self.summary(eid)}
        if recipient:
            data["recipient"] = {k: recipient[k] for k in ("id", "name", "email", "status")}
        self.hooks.emit(e["user_id"], e["mode"], event, data)

    # ---- create / send --------------------------------------------------------------------------------------------
    def create(
        self, uid, mode, *, subject, message, doc: bytes, doc_name, recipients, fields, sequential, metadata
    ) -> str:
        if len(doc) > self.s.max_doc_mb * 1024 * 1024:
            raise Error(413, f"document exceeds {self.s.max_doc_mb} MB")
        try:
            pages = pdfs.inspect(doc)
        except ValueError as e:
            raise Error(422, str(e)) from e
        emails = [r["email"].lower() for r in recipients if r["role"] == "signer"]
        if not emails:
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
        eid = rid("env")
        (self.docs / f"{eid}.pdf").write_bytes(doc)
        t = now()
        self.db.x(
            "INSERT INTO envelopes(id,user_id,mode,subject,message,status,sequential,doc_name,doc_sha256,pages,metadata,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, uid, mode, subject, message, "draft", int(sequential), doc_name, hashlib.sha256(doc).hexdigest(), pages,
             json.dumps(metadata), t, t),
        )  # fmt: skip
        ids = []
        for r in recipients:
            ids.append(rid("rcp"))
            self.db.x(
                "INSERT INTO recipients(id,envelope_id,name,email,role,routing_order,token,status) VALUES(?,?,?,?,?,?,?,?)",
                (
                    ids[-1],
                    eid,
                    r["name"],
                    r["email"],
                    r["role"],
                    r["routing_order"],
                    secrets.token_urlsafe(32),
                    "created",
                ),
            )
        for f in fields:
            self.db.x(
                "INSERT INTO fields(id,envelope_id,recipient_id,type,page,x,y,w,h,required,label) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (rid("fld"), eid, ids[f["recipient"]], f["type"], f["page"], f["x"], f["y"], f["w"], f["h"],
                 int(f["required"]), f["label"]),
            )  # fmt: skip
        self._event(eid, "created", "api")
        return eid

    def send(self, eid: str, uid: str, mode: str) -> None:
        with self.lock:
            e = self.env(eid, uid, mode)
            if e["status"] != "draft":
                raise Error(409, f"envelope is {e['status']}, only drafts can be sent")
            for r in self.recipients(eid):
                if r["role"] == "signer" and not self.db.one(
                    "SELECT 1 AS x FROM fields WHERE recipient_id=? AND type IN ('signature','initials')", (r["id"],)
                ):
                    raise Error(422, f"signer {r['email']} needs at least one signature or initials field")
            self.db.x("UPDATE envelopes SET status='sent', sent_at=? WHERE id=?", (now(), eid))
            self._event(eid, "sent", "owner")
            self._emit(eid, "envelope.sent")
            self._advance(eid)

    def void(self, eid: str, uid: str, mode: str, reason: str) -> None:
        with self.lock:
            e = self.env(eid, uid, mode)
            if e["status"] not in ("draft", "sent"):
                raise Error(409, f"envelope is {e['status']} and can no longer be voided")
            self.db.x("UPDATE envelopes SET status='voided' WHERE id=?", (eid,))
            self._event(eid, "voided", "owner", detail=reason[:300])
            self._emit(eid, "envelope.voided")

    def delete_draft(self, eid: str, uid: str, mode: str) -> None:
        e = self.env(eid, uid, mode)
        if e["status"] != "draft":
            raise Error(409, "only drafts can be deleted; void a sent envelope instead")
        for t in ("fields", "recipients", "events"):
            self.db.x(f"DELETE FROM {t} WHERE envelope_id=?", (eid,))
        self.db.x("DELETE FROM envelopes WHERE id=?", (eid,))
        (self.docs / f"{eid}.pdf").unlink(missing_ok=True)

    def _advance(self, eid: str) -> None:
        e = self.env(eid)
        pending = [r for r in self.recipients(eid) if r["role"] == "signer" and r["status"] != "signed"]
        if not pending:
            return self._finalize(eid)
        lowest = min(r["routing_order"] for r in pending)
        for r in pending:
            if r["status"] == "created" and (not e["sequential"] or r["routing_order"] == lowest):
                self.db.x("UPDATE recipients SET status='sent' WHERE id=?", (r["id"],))
                r["status"] = "sent"
                self._event(eid, "recipient_sent", r["email"])
                self._emit(eid, "recipient.sent", r)
                self._mail(r, f"Please sign: {e['subject']}", e["message"], f"/sign/{r['token']}")

    def _finalize(self, eid: str) -> None:
        e = self.env(eid)
        t = now()
        self.db.x("UPDATE envelopes SET status='completed', completed_at=? WHERE id=?", (t, eid))
        self._event(eid, "completed", "system")
        e = self.env(eid)
        recs = self.recipients(eid)
        cert = pdfs.certificate(e, recs, self.events(eid))
        fields = self.db.q("SELECT * FROM fields WHERE envelope_id=?", (eid,))
        final = pdfs.finalize((self.docs / f"{eid}.pdf").read_bytes(), fields, cert, e["mode"] == "test")
        (self.docs / f"{eid}.signed.pdf").write_bytes(final)
        self.db.x("UPDATE envelopes SET final_sha256=? WHERE id=?", (hashlib.sha256(final).hexdigest(), eid))
        self._emit(eid, "envelope.completed")
        for r in recs:
            self._mail(
                r, f"Completed: {e['subject']}", "All parties have signed. Your copy is ready.", f"/sign/{r['token']}"
            )

    # ---- signer side (public, by token) ----------------------------------------------------------------------------
    def by_token(self, token: str) -> tuple[dict, dict]:
        r = self.db.one("SELECT * FROM recipients WHERE token=?", (token,))
        if not r:
            raise Error(404, "link not found")
        return r, self.env(r["envelope_id"])

    @staticmethod
    def state(r: dict, e: dict) -> str:
        if e["status"] in ("voided", "declined", "completed"):
            return e["status"]
        if r["status"] == "signed":
            return "signed"
        return "ready" if r["status"] in ACTIVE else "waiting"

    def signer_view(self, token: str, ip: str, ua: str) -> dict:
        r, e = self.by_token(token)
        st = self.state(r, e)
        if st == "ready" and r["status"] == "sent" and r["role"] == "signer":
            self.db.x("UPDATE recipients SET status='viewed' WHERE id=?", (r["id"],))
            r["status"] = "viewed"
            self._event(e["id"], "viewed", r["email"], ip, ua)
            self._emit(e["id"], "recipient.viewed", r)
        fields = []
        if st == "ready":
            fields = self.db.q(
                "SELECT id,type,page,x,y,w,h,required,label FROM fields WHERE recipient_id=? ORDER BY page,y,x",
                (r["id"],),
            )
        return {
            "state": st,
            "sandbox": e["mode"] == "test",
            "subject": e["subject"],
            "message": e["message"],
            "pages": e["pages"],
            "recipient": {"name": r["name"], "email": r["email"], "role": r["role"]},
            "fields": fields,
        }

    def complete(self, token: str, values: dict, ip: str, ua: str) -> dict:
        with self.lock:
            r, e = self.by_token(token)
            if self.state(r, e) != "ready":
                raise Error(409, f"cannot sign: envelope is {self.state(r, e)}")
            mine = self.db.q("SELECT * FROM fields WHERE recipient_id=?", (r["id"],))
            clean: dict[str, str] = {}
            for f in mine:
                v = values.get(f["id"])
                if f["type"] == "date":
                    v = datetime.now(UTC).date().isoformat()  # never trust a client-supplied signing date
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
            self.db.x("UPDATE recipients SET status='signed', signed_at=?, sign_ip=? WHERE id=?", (now(), ip, r["id"]))
            r.update(status="signed")
            self._event(e["id"], "consent", r["email"], ip, ua, "agreed to use electronic records and signatures")
            self._event(e["id"], "signed", r["email"], ip, ua)
            self._emit(e["id"], "recipient.signed", r)
            self._advance(e["id"])
            return {"state": self.state(r, self.env(e["id"]))}

    def decline(self, token: str, reason: str, ip: str, ua: str) -> None:
        with self.lock:
            r, e = self.by_token(token)
            if self.state(r, e) != "ready":
                raise Error(409, f"cannot decline: envelope is {self.state(r, e)}")
            self.db.x("UPDATE recipients SET status='declined' WHERE id=?", (r["id"],))
            r["status"] = "declined"
            self.db.x("UPDATE envelopes SET status='declined' WHERE id=?", (e["id"],))
            self._event(e["id"], "declined", r["email"], ip, ua, reason[:300])
            self._emit(e["id"], "recipient.declined", r)
            self._emit(e["id"], "envelope.declined")

    def file_for(self, eid: str, signed: bool):
        p = self.docs / (f"{eid}.signed.pdf" if signed else f"{eid}.pdf")
        if not p.exists():
            raise Error(404, "document not available")
        return p

    # ---- mail ----------------------------------------------------------------------------------------------------
    def _mail(self, r: dict, subject: str, body: str, path: str) -> None:
        s = self.s
        if not (s.smtp_host and s.smtp_from):
            return
        m = EmailMessage()
        m["Subject"], m["From"], m["To"] = subject, s.smtp_from, r["email"]
        m.set_content(f"Hi {r['name']},\n\n{body}\n\n{s.base_url.rstrip('/')}{path}\n\n-- HubSign")

        def go() -> None:
            try:
                with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=15) as c:
                    c.starttls()
                    if s.smtp_user:
                        c.login(s.smtp_user, s.smtp_password)
                    c.send_message(m)
            except Exception:
                pass  # the signing link is also on the API response; mail is best effort

        threading.Thread(target=go, daemon=True).start()
