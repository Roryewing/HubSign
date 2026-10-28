"""HTTP surface: /auth (dashboard sessions), /v1 (developer API, Bearer key or session), /sign-api (signers, by link)."""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from . import __version__, security
from .config import Settings
from .core import DEFAULT_SIZE, Error, Service, now, rid
from .db import Database
from .webhooks import EVENTS, Webhooks

WEB = Path(__file__).parent / "web"
EMAIL = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
Mode = Literal["test", "live"]


# ---- request bodies ----------------------------------------------------------------------------------------------
class Creds(BaseModel):
    email: str = Field(pattern=EMAIL, max_length=200)
    password: str = Field(min_length=8, max_length=200)
    name: str = Field(default="", max_length=100)


class RecipientIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: str = Field(pattern=EMAIL, max_length=200)
    role: Literal["signer", "cc"] = "signer"
    routing_order: int = Field(default=1, ge=1, le=20)


class FieldIn(BaseModel):
    recipient: int = Field(ge=0, description="Index into `recipients`")
    type: Literal["signature", "initials", "date", "name", "email", "text", "checkbox"]
    page: int = Field(ge=1)
    x: float = Field(ge=0, le=1, description="Left edge, fraction of page width")
    y: float = Field(ge=0, le=1, description="Top edge, fraction of page height")
    w: float | None = Field(default=None, gt=0, le=1)
    h: float | None = Field(default=None, gt=0, le=1)
    required: bool = True
    label: str = Field(default="", max_length=100)


class EnvelopeIn(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    message: str = Field(default="", max_length=2000)
    document_base64: str = Field(description="The PDF, base64 encoded")
    document_name: str = Field(default="document.pdf", max_length=200)
    recipients: list[RecipientIn] = Field(min_length=1)
    fields: list[FieldIn] = []
    sequential: bool = Field(default=True, description="Signers sign in routing_order; false = all at once")
    send: bool = Field(default=False, description="Send immediately instead of leaving a draft")
    metadata: dict[str, str] = Field(default_factory=dict, description="Your own references, echoed in webhooks")


class RoleIn(BaseModel):
    name: str = Field(min_length=1, max_length=100, description="Role label, e.g. Tenant")
    role: Literal["signer", "cc"] = "signer"
    routing_order: int = Field(default=1, ge=1, le=20)


class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    document_base64: str
    document_name: str = Field(default="document.pdf", max_length=200)
    roles: list[RoleIn] = Field(min_length=1)
    fields: list[FieldIn] = []
    sequential: bool = True


class PersonIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: str = Field(pattern=EMAIL, max_length=200)


class UseTemplateIn(BaseModel):
    recipients: list[PersonIn] = Field(min_length=1, description="One person per template role, in role order")
    subject: str = Field(default="", max_length=200)
    message: str = Field(default="", max_length=2000)
    send: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)


class VoidIn(BaseModel):
    reason: str = Field(default="", max_length=300)


class KeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    mode: Mode = "test"


class WebhookIn(BaseModel):
    url: str = Field(max_length=500)
    events: list[str] = Field(default=[], description="Empty = every event")


class CompleteIn(BaseModel):
    consent: Literal[True]
    values: dict[str, str | bool] = {}


class DeclineIn(BaseModel):
    reason: str = Field(default="", max_length=300)


@dataclass
class Ctx:
    user: dict
    mode: str
    via: str


def create_app(settings: Settings | None = None, sender=None) -> FastAPI:
    s = settings or Settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    secret_file = s.data_dir / "secret"
    if not s.secret:
        if not secret_file.exists():
            secret_file.write_text(secrets.token_hex(32))
        s.secret = secret_file.read_text().strip()
    db = Database(s.data_dir / "hubsign.db")
    hooks = Webhooks(db, s, **({"sender": sender} if sender else {}))
    svc = Service(s, db, hooks)
    fails: dict[str, list[float]] = {}  # login throttle: key -> attempt timestamps

    app = FastAPI(
        title="HubSign API",
        version=__version__,
        description="Send documents for signature. Authenticate with `Authorization: Bearer hs_test_...` "
        "(sandbox) or `hs_live_...`. Webhooks are signed with HMAC-SHA256; see the Developer page.",
    )
    app.state.svc = svc

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"  # signing links carry the secret in the path
        if request.url.path.startswith(("/sign", "/v1", "/auth")):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.exception_handler(Error)
    async def on_error(_: Request, e: Error):
        return JSONResponse({"detail": e.msg}, status_code=e.status)

    def ip_of(request: Request) -> str:
        return request.client.host if request.client else ""

    def ctx(request: Request) -> Ctx:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            k = db.one("SELECT * FROM api_keys WHERE hash=? AND revoked=0", (security.key_hash(auth[7:]),))
            if k:
                db.x("UPDATE api_keys SET last_used_at=? WHERE id=?", (now(), k["id"]))
                return Ctx(db.one("SELECT * FROM users WHERE id=?", (k["user_id"],)), k["mode"], "key")
        else:
            uid = security.read_session(s.secret, request.cookies.get("hubsign_session"))
            u = uid and db.one("SELECT * FROM users WHERE id=?", (uid,))
            if u:
                mode = request.headers.get("x-hubsign-mode") or request.query_params.get("mode") or "test"
                return Ctx(u, mode if mode in ("test", "live") else "test", "session")
        raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})

    def session_only(c: Ctx = Depends(ctx)) -> Ctx:
        if c.via != "session":
            raise HTTPException(403, "this endpoint needs a dashboard login, not an API key")
        return c

    # ---- auth ----------------------------------------------------------------------------------------------------
    def start_session(resp: Response, uid: str) -> None:
        resp.set_cookie(
            "hubsign_session", security.make_session(s.secret, uid), httponly=True, samesite="lax",
            secure=s.base_url.startswith("https"), max_age=14 * 86400,
        )  # fmt: skip

    @app.post("/auth/signup", tags=["auth"])
    def signup(b: Creds, resp: Response):
        first = not db.one("SELECT 1 AS x FROM users LIMIT 1")
        if not (first or s.allow_signup):
            raise HTTPException(403, "signup is disabled")
        email = b.email.lower()
        if db.one("SELECT 1 AS x FROM users WHERE email=?", (email,)):
            raise HTTPException(409, "an account with that email already exists")
        uid = rid("usr")
        db.x(
            "INSERT INTO users VALUES(?,?,?,?,?)",
            (uid, email, b.name or email.split("@")[0], security.hash_password(b.password), now()),
        )
        start_session(resp, uid)
        return {"id": uid, "email": email}

    @app.post("/auth/login", tags=["auth"])
    def login(b: Creds, request: Request, resp: Response):
        key = f"{b.email.lower()}|{ip_of(request)}"
        recent = [t for t in fails.get(key, []) if t > time.time() - 900]
        if len(recent) >= 5:
            raise HTTPException(429, "too many attempts, try again in 15 minutes")
        u = db.one("SELECT * FROM users WHERE email=?", (b.email.lower(),))
        if not (u and security.check_password(b.password, u["pw_hash"])):
            fails[key] = [*recent, time.time()]
            raise HTTPException(401, "wrong email or password")
        fails.pop(key, None)
        start_session(resp, u["id"])
        return {"id": u["id"], "email": u["email"]}

    @app.post("/auth/logout", tags=["auth"])
    def logout(resp: Response):
        resp.delete_cookie("hubsign_session")
        return {"ok": True}

    @app.get("/auth/me", tags=["auth"])
    def me(c: Ctx = Depends(ctx)):
        return {"id": c.user["id"], "email": c.user["email"], "name": c.user["name"], "mode": c.mode, "via": c.via}

    # ---- envelopes -------------------------------------------------------------------------------------------------
    @app.post("/v1/envelopes", status_code=201, tags=["envelopes"])
    def create_envelope(b: EnvelopeIn, c: Ctx = Depends(ctx)):
        try:
            doc = base64.b64decode(b.document_base64, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(422, "document_base64 is not valid base64") from None
        fields = []
        for f in b.fields:
            dw, dh = DEFAULT_SIZE[f.type]
            fields.append({**f.model_dump(), "w": f.w or dw, "h": f.h or dh})
        eid = svc.create(
            c.user["id"], c.mode, subject=b.subject, message=b.message, doc=doc, doc_name=b.document_name,
            recipients=[r.model_dump() for r in b.recipients], fields=fields, sequential=b.sequential,
            metadata=b.metadata,
        )  # fmt: skip
        if b.send:
            svc.send(eid, c.user["id"], c.mode)
        return svc.detail(eid, c.user["id"], c.mode)

    @app.get("/v1/envelopes", tags=["envelopes"])
    def list_envelopes(
        status: str | None = None, q: str | None = None, limit: int = 50, offset: int = 0, c: Ctx = Depends(ctx)
    ):
        sql, args = "SELECT id FROM envelopes WHERE user_id=? AND mode=?", [c.user["id"], c.mode]
        if status:
            sql, args = sql + " AND status=?", [*args, status]
        if q:
            like = "%" + q[:100].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            sql += " AND (subject LIKE ? ESCAPE '\\' OR id IN (SELECT envelope_id FROM recipients WHERE name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\'))"
            args += [like, like, like]
        rows = db.q(
            sql + " ORDER BY updated_at DESC, rowid DESC LIMIT ? OFFSET ?",
            (*args, min(max(limit, 1), 200), max(offset, 0)),
        )
        return {"envelopes": [svc.summary(r["id"]) | {"updated_at": svc.env(r["id"])["updated_at"]} for r in rows]}

    @app.get("/v1/envelopes/counts", tags=["envelopes"])
    def envelope_counts(c: Ctx = Depends(ctx)):
        out = {k: 0 for k in ("draft", "sent", "completed", "declined", "voided")}
        for r in db.q(
            "SELECT status, COUNT(*) AS n FROM envelopes WHERE user_id=? AND mode=? GROUP BY status",
            (c.user["id"], c.mode),
        ):
            out[r["status"]] = r["n"]
        month_ago = (datetime.now(UTC) - timedelta(days=30)).isoformat()
        done = db.one(
            "SELECT COUNT(*) AS n FROM envelopes WHERE user_id=? AND mode=? AND status='completed' AND completed_at>=?",
            (c.user["id"], c.mode, month_ago),
        )
        return out | {"all": sum(out.values()), "completed_30d": done["n"]}

    @app.get("/v1/envelopes/{eid}", tags=["envelopes"])
    def get_envelope(eid: str, c: Ctx = Depends(ctx)):
        return svc.detail(eid, c.user["id"], c.mode)

    @app.post("/v1/envelopes/{eid}/send", tags=["envelopes"])
    def send_envelope(eid: str, c: Ctx = Depends(ctx)):
        svc.send(eid, c.user["id"], c.mode)
        return svc.detail(eid, c.user["id"], c.mode)

    @app.post("/v1/envelopes/{eid}/void", tags=["envelopes"])
    def void_envelope(eid: str, b: VoidIn, c: Ctx = Depends(ctx)):
        svc.void(eid, c.user["id"], c.mode, b.reason)
        return svc.detail(eid, c.user["id"], c.mode)

    @app.delete("/v1/envelopes/{eid}", status_code=204, tags=["envelopes"])
    def delete_envelope(eid: str, c: Ctx = Depends(ctx)):
        svc.delete_draft(eid, c.user["id"], c.mode)

    @app.get("/v1/envelopes/{eid}/events", tags=["envelopes"])
    def envelope_events(eid: str, c: Ctx = Depends(ctx)):
        svc.env(eid, c.user["id"], c.mode)
        return {"events": svc.events(eid)}

    @app.get("/v1/envelopes/{eid}/document", tags=["envelopes"])
    def original_document(eid: str, c: Ctx = Depends(ctx)):
        e = svc.env(eid, c.user["id"], c.mode)
        return FileResponse(svc.file_for(eid, False), media_type="application/pdf", filename=e["doc_name"])

    @app.get("/v1/envelopes/{eid}/signed", tags=["envelopes"])
    def signed_document(eid: str, c: Ctx = Depends(ctx)):
        svc.env(eid, c.user["id"], c.mode)
        return FileResponse(svc.file_for(eid, True), media_type="application/pdf", filename=f"{eid}-signed.pdf")

    # ---- templates ---------------------------------------------------------------------------------------------------
    def tpl_out(t: dict) -> dict:
        return {
            k: t[k]
            for k in ("id", "name", "description", "doc_name", "pages", "roles", "fields", "sequential", "created_at")
        }

    @app.post("/v1/templates", status_code=201, tags=["templates"])
    def create_template(b: TemplateIn, c: Ctx = Depends(ctx)):
        try:
            doc = base64.b64decode(b.document_base64, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(422, "document_base64 is not valid base64") from None
        fields = []
        for f in b.fields:
            dw, dh = DEFAULT_SIZE[f.type]
            fields.append({**f.model_dump(), "w": f.w or dw, "h": f.h or dh})
        tid = svc.create_template(
            c.user["id"], c.mode, name=b.name, description=b.description, doc=doc, doc_name=b.document_name,
            roles=[r.model_dump() for r in b.roles], fields=fields, sequential=b.sequential,
        )  # fmt: skip
        return tpl_out(svc.template(tid, c.user["id"], c.mode))

    @app.get("/v1/templates", tags=["templates"])
    def list_templates(c: Ctx = Depends(ctx)):
        rows = db.q(
            "SELECT id FROM templates WHERE user_id=? AND mode=? ORDER BY created_at DESC, rowid DESC",
            (c.user["id"], c.mode),
        )
        return {"templates": [tpl_out(svc.template(r["id"], c.user["id"], c.mode)) for r in rows]}

    @app.get("/v1/templates/{tid}", tags=["templates"])
    def get_template(tid: str, c: Ctx = Depends(ctx)):
        return tpl_out(svc.template(tid, c.user["id"], c.mode))

    @app.get("/v1/templates/{tid}/document", tags=["templates"])
    def template_document(tid: str, c: Ctx = Depends(ctx)):
        t = svc.template(tid, c.user["id"], c.mode)
        return FileResponse(svc.file_for(tid, False), media_type="application/pdf", filename=t["doc_name"])

    @app.delete("/v1/templates/{tid}", status_code=204, tags=["templates"])
    def delete_template(tid: str, c: Ctx = Depends(ctx)):
        svc.delete_template(tid, c.user["id"], c.mode)

    @app.post("/v1/templates/{tid}/envelopes", status_code=201, tags=["templates"])
    def envelope_from_template(tid: str, b: UseTemplateIn, c: Ctx = Depends(ctx)):
        eid = svc.use_template(
            tid, c.user["id"], c.mode, people=[p.model_dump() for p in b.recipients], subject=b.subject,
            message=b.message, metadata=b.metadata, send=b.send,
        )  # fmt: skip
        return svc.detail(eid, c.user["id"], c.mode)

    # ---- developer tools: keys ------------------------------------------------------------------------------------
    @app.post("/v1/api-keys", status_code=201, tags=["developer"])
    def create_key(b: KeyIn, c: Ctx = Depends(session_only)):
        key, prefix, h = security.new_api_key(b.mode)
        kid = rid("key")
        db.x(
            "INSERT INTO api_keys(id,user_id,name,mode,prefix,hash,created_at) VALUES(?,?,?,?,?,?,?)",
            (kid, c.user["id"], b.name, b.mode, prefix, h, now()),
        )
        return {
            "id": kid,
            "name": b.name,
            "mode": b.mode,
            "key": key,
            "note": "Store this key now. It is not shown again.",
        }

    @app.get("/v1/api-keys", tags=["developer"])
    def list_keys(c: Ctx = Depends(session_only)):
        return {
            "keys": db.q(
                "SELECT id,name,mode,prefix,created_at,last_used_at FROM api_keys WHERE user_id=? AND revoked=0 ORDER BY created_at DESC",
                (c.user["id"],),
            )
        }

    @app.delete("/v1/api-keys/{kid}", status_code=204, tags=["developer"])
    def revoke_key(kid: str, c: Ctx = Depends(session_only)):
        if not db.x("UPDATE api_keys SET revoked=1 WHERE id=? AND user_id=?", (kid, c.user["id"])):
            raise HTTPException(404, "key not found")

    # ---- developer tools: webhooks ----------------------------------------------------------------------------------
    def wh_or_404(wid: str, c: Ctx) -> dict:
        w = db.one("SELECT * FROM webhooks WHERE id=? AND user_id=? AND mode=?", (wid, c.user["id"], c.mode))
        if not w:
            raise HTTPException(404, "webhook not found")
        return w

    def wh_out(w: dict, secret: bool = False) -> dict:
        out = {
            "id": w["id"],
            "url": w["url"],
            "events": json.loads(w["events"]),
            "active": bool(w["active"]),
            "mode": w["mode"],
            "created_at": w["created_at"],
        }
        return out | ({"secret": w["secret"]} if secret else {})

    @app.get("/v1/webhook-events", tags=["developer"])
    def webhook_events():
        return {"events": EVENTS}

    @app.post("/v1/webhooks", status_code=201, tags=["developer"])
    def create_webhook(b: WebhookIn, c: Ctx = Depends(ctx)):
        bad = security.url_is_safe(b.url, s.allow_private_webhooks)
        if bad:
            raise HTTPException(422, bad)
        unknown = [e for e in b.events if e not in EVENTS]
        if unknown:
            raise HTTPException(422, f"unknown events: {unknown}")
        w = {"id": rid("wh"), "secret": "whsec_" + secrets.token_urlsafe(24)}
        db.x(
            "INSERT INTO webhooks VALUES(?,?,?,?,?,?,?,?)",
            (w["id"], c.user["id"], c.mode, b.url, w["secret"], json.dumps(b.events), 1, now()),
        )
        return wh_out(wh_or_404(w["id"], c), secret=True)

    @app.get("/v1/webhooks", tags=["developer"])
    def list_webhooks(c: Ctx = Depends(ctx)):
        return {
            "webhooks": [
                wh_out(w)
                for w in db.q(
                    "SELECT * FROM webhooks WHERE user_id=? AND mode=? AND active=1 ORDER BY created_at DESC",
                    (c.user["id"], c.mode),
                )
            ]
        }

    @app.get("/v1/webhooks/{wid}", tags=["developer"])
    def get_webhook(wid: str, c: Ctx = Depends(ctx)):
        return wh_out(wh_or_404(wid, c), secret=True)

    @app.delete("/v1/webhooks/{wid}", status_code=204, tags=["developer"])
    def delete_webhook(wid: str, c: Ctx = Depends(ctx)):
        wh_or_404(wid, c)
        db.x("UPDATE webhooks SET active=0 WHERE id=?", (wid,))

    @app.get("/v1/webhooks/{wid}/deliveries", tags=["developer"])
    def deliveries(wid: str, c: Ctx = Depends(ctx)):
        wh_or_404(wid, c)
        rows = db.q(
            "SELECT id,event,status,attempts,http_status,response,created_at,last_at,payload FROM deliveries WHERE webhook_id=? ORDER BY created_at DESC, rowid DESC LIMIT 50",
            (wid,),
        )
        return {"deliveries": [r | {"payload": json.loads(r["payload"])} for r in rows]}

    @app.post("/v1/webhooks/{wid}/test", tags=["developer"])
    def test_webhook(wid: str, c: Ctx = Depends(ctx)):
        wh_or_404(wid, c)
        payload = {
            "id": "evt_" + secrets.token_hex(8),
            "type": "webhook.test",
            "created": now(),
            "mode": c.mode,
            "data": {"hello": "from HubSign"},
        }
        return {"delivery_id": hooks.queue(wid, "webhook.test", payload)}

    @app.post("/v1/webhook-deliveries/{did}/redeliver", tags=["developer"])
    def redeliver(did: str, c: Ctx = Depends(ctx)):
        d = db.one(
            "SELECT d.* FROM deliveries d JOIN webhooks w ON w.id=d.webhook_id WHERE d.id=? AND w.user_id=? AND w.mode=?",
            (did, c.user["id"], c.mode),
        )
        if not d:
            raise HTTPException(404, "delivery not found")
        return {"delivery_id": hooks.queue(d["webhook_id"], d["event"], json.loads(d["payload"]))}

    # ---- signer (public; the link is the credential) -------------------------------------------------------------------
    @app.get("/sign/{token}", include_in_schema=False)
    def sign_page(token: str):
        return FileResponse(WEB / "sign.html")

    @app.get("/sign-api/{token}", tags=["signing"])
    def sign_info(token: str, request: Request):
        return svc.signer_view(token, ip_of(request), request.headers.get("user-agent", ""))

    @app.get("/sign-api/{token}/document", tags=["signing"])
    def sign_doc(token: str):
        r, e = svc.by_token(token)
        return FileResponse(svc.file_for(e["id"], False), media_type="application/pdf")

    @app.get("/sign-api/{token}/signed", tags=["signing"])
    def sign_signed(token: str):
        r, e = svc.by_token(token)
        if e["status"] != "completed":
            raise HTTPException(409, "envelope is not complete yet")
        return FileResponse(svc.file_for(e["id"], True), media_type="application/pdf", filename=f"{e['id']}-signed.pdf")

    @app.post("/sign-api/{token}/complete", tags=["signing"])
    def sign_complete(token: str, b: CompleteIn, request: Request):
        return svc.complete(token, b.values, ip_of(request), request.headers.get("user-agent", ""))

    @app.post("/sign-api/{token}/decline", tags=["signing"])
    def sign_decline(token: str, b: DeclineIn, request: Request):
        svc.decline(token, b.reason, ip_of(request), request.headers.get("user-agent", ""))
        return {"ok": True}

    # ---- misc ----------------------------------------------------------------------------------------------------
    @app.get("/api/ping", include_in_schema=False)
    def ping():
        return {"ok": True, "version": __version__}

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(WEB / "index.html")

    return app
