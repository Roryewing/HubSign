"""HTTP surface: /auth (dashboard sessions), /v1 (developer API, Bearer key or session), /sign-api (signers, by link)."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import secrets
import threading
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator

from . import __version__, mail, security
from .config import Settings
from .core import DEFAULT_SIZE, Error, Service, now, rid
from .db import Database
from .identity import Identity
from .seal import Sealer
from .storage import make_storage
from .webhooks import EVENTS, Webhooks

log = logging.getLogger("hubsign")
WEB = Path(__file__).parent / "web"
EMAIL = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
Mode = Literal["test", "live"]
RANK = {"viewer": 1, "sender": 2, "admin": 3, "owner": 4}
FieldType = Literal["signature", "initials", "date", "name", "email", "text", "checkbox"]


# ---- request bodies ----------------------------------------------------------------------------------------------
class Creds(BaseModel):
    email: str = Field(pattern=EMAIL, max_length=200)
    password: str = Field(min_length=8, max_length=200)
    name: str = Field(default="", max_length=100)
    invite_token: str = Field(default="", max_length=200)


class AuthIn(BaseModel):
    method: Literal["none", "access_code", "sms", "email"] = "none"
    access_code: str | None = Field(
        default=None, max_length=64, description="Share it with the signer yourself, by phone for example"
    )
    phone: str | None = Field(default=None, max_length=20, description="E.164, e.g. +14165550123, for method=sms")


def _ok_return_url(u: str | None) -> str | None:
    if not u:
        return None
    from urllib.parse import urlsplit

    p = urlsplit(u)
    local = p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1")
    if not (p.scheme == "https" or local) or not p.hostname or len(u) > 500:
        raise ValueError("return_url must be https (or http://localhost)")
    return u


class RecipientIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: str = Field(pattern=EMAIL, max_length=200)
    role: Literal["signer", "cc"] = "signer"
    routing_order: int = Field(default=1, ge=1, le=20)
    authentication: AuthIn = AuthIn()
    embedded: bool = Field(
        default=False, description="They sign inside your own app: no email is sent, use signing_url"
    )
    return_url: str | None = Field(
        default=None, description="Where the signer's browser goes after signing or declining"
    )

    @field_validator("return_url")
    @classmethod
    def _return_url(cls, v):
        return _ok_return_url(v)


class ReplyTo(BaseModel):
    name: str = Field(default="", max_length=100)
    email: str = Field(pattern=EMAIL, max_length=200)


class AnchorIn(BaseModel):
    text: str = Field(
        min_length=1, max_length=80, description="Text printed in the PDF, even invisibly; one field per occurrence"
    )
    x_offset: float = Field(default=0, ge=-600, le=600, description="Points right of the text's left edge")
    y_offset: float = Field(
        default=0, ge=-800, le=800, description="Points below the text's top edge (negative = above)"
    )
    width: float | None = Field(default=None, gt=0, le=600, description="Points")
    height: float | None = Field(default=None, gt=0, le=400, description="Points")
    optional: bool = Field(default=False, description="Skip silently when the text is not in the document")


class FieldIn(BaseModel):
    recipient: int = Field(ge=0, description="Index into `recipients`")
    type: FieldType
    document: int | None = Field(
        default=None,
        ge=0,
        description="Index into `documents`. Positioned fields default to the first; anchored fields search them all",
    )
    page: int = Field(default=1, ge=1, description="Page within that document (not needed with an anchor)")
    x: float | None = Field(default=None, ge=0, le=1, description="Left edge, fraction of page width")
    y: float | None = Field(default=None, ge=0, le=1, description="Top edge, fraction of page height")
    w: float | None = Field(default=None, gt=0, le=1)
    h: float | None = Field(default=None, gt=0, le=1)
    anchor: AnchorIn | None = Field(default=None, description="Place by text in the PDF instead of x and y")
    required: bool = True
    label: str = Field(default="", max_length=100, description="A name for the field; form data is returned by label")
    value: str | None = Field(
        default=None, max_length=4000, description="Prefill a text or checkbox field; the signer cannot change it"
    )

    @model_validator(mode="after")
    def _where(self):
        if self.anchor is None and (self.x is None or self.y is None):
            raise ValueError("give x and y, or an anchor")
        return self


class DocIn(BaseModel):
    id: str = Field(default="", max_length=20, pattern=r"^[A-Za-z0-9_-]*$")
    name: str = Field(default="document.pdf", max_length=200)
    document_base64: str


class EnvelopeIn(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    message: str = Field(default="", max_length=2000)
    document_base64: str | None = Field(default=None, description="The PDF, base64 encoded (or use `documents`)")
    document_name: str = Field(default="document.pdf", max_length=200)
    documents: list[DocIn] = Field(
        default=[], max_length=10, description="Several PDFs in one envelope; fields refer to them by index"
    )
    recipients: list[RecipientIn] = Field(min_length=1)
    fields: list[FieldIn] = []
    sequential: bool = Field(default=True, description="Signers sign in routing_order; false = all at once")
    send: bool = Field(default=False, description="Send immediately instead of leaving a draft")
    metadata: dict[str, str] = Field(default_factory=dict, description="Your own references, echoed in webhooks")
    allow_reassign: bool = Field(default=False, description="Signers may hand their part to someone else")
    reply_to: ReplyTo | None = None
    sender_name: str = Field(
        default="", max_length=100, description="Shown in the email as who sent it; defaults to the organisation"
    )

    @model_validator(mode="after")
    def _one_source(self):
        if bool(self.document_base64) == bool(self.documents):
            raise ValueError("give either document_base64 or documents")
        return self


class RoleAuthIn(BaseModel):
    method: Literal["none", "access_code", "sms", "email"] = "none"


class RoleIn(BaseModel):
    name: str = Field(min_length=1, max_length=100, description="Role label, e.g. Tenant")
    role: Literal["signer", "cc"] = "signer"
    routing_order: int = Field(default=1, ge=1, le=20)
    authentication: RoleAuthIn = RoleAuthIn()


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
    phone: str | None = Field(default=None, max_length=20)
    access_code: str | None = Field(default=None, max_length=64)


class UseTemplateIn(BaseModel):
    recipients: list[PersonIn] = Field(min_length=1, description="One person per template role, in role order")
    subject: str = Field(default="", max_length=200)
    message: str = Field(default="", max_length=2000)
    send: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)


class BulkIn(BaseModel):
    rows: list[list[PersonIn]] = Field(
        min_length=1, description="One list of people (one per template role) for each envelope"
    )
    subject: str = Field(default="", max_length=200)
    message: str = Field(default="", max_length=2000)
    send: bool = True


class VoidIn(BaseModel):
    reason: str = Field(default="", max_length=300)


class KeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    mode: Mode = "test"
    role: Literal["viewer", "sender", "admin"] = "sender"


class WebhookIn(BaseModel):
    url: str = Field(max_length=500)
    events: list[str] = Field(default=[], description="Empty = every event")


class CompleteIn(BaseModel):
    consent: Literal[True]
    values: dict[str, str | bool] = {}


class ReassignIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: str = Field(pattern=EMAIL, max_length=200)


class DeclineIn(BaseModel):
    reason: str = Field(default="", max_length=300)


class CodeIn(BaseModel):
    code: str = Field(max_length=64)


class OrgIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class RoleChange(BaseModel):
    role: Literal["viewer", "sender", "admin", "owner"]


class InviteIn(BaseModel):
    email: str = Field(pattern=EMAIL, max_length=200)
    role: Literal["viewer", "sender", "admin"] = "sender"


class TokenIn(BaseModel):
    token: str = Field(max_length=200)


@dataclass
class Ctx:
    user: dict
    org: str
    role: str
    mode: str
    via: str


def pdf_response(data: bytes, filename: str, inline: bool = False) -> Response:
    cd = ("inline" if inline else "attachment") + f"; filename*=UTF-8''{quote(filename)}"
    return Response(data, media_type="application/pdf", headers={"Content-Disposition": cd})


def create_app(
    settings: Settings | None = None, sender=None, sms_sender=None, timestamper=None, db_schema: str | None = None
) -> FastAPI:
    s = settings or Settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    secret_file = s.data_dir / "secret"
    if not s.secret:
        if not secret_file.exists():
            secret_file.write_text(secrets.token_hex(32))
        s.secret = secret_file.read_text().strip()
    db = Database(s.database_url or (s.data_dir / "hubsign.db"), schema=db_schema)
    hooks = Webhooks(db, s, **({"sender": sender} if sender else {}))
    ident = Identity(s, db, **({"sms_sender": sms_sender} if sms_sender else {}))
    storage = make_storage(s)
    svc = Service(s, db, hooks, storage, ident, Sealer(s, timestamper=timestamper))
    https = s.base_url.startswith("https")
    if https and s.trust_proxy_hops == 0:
        log.warning(
            "HUBSIGN_BASE_URL is https but HUBSIGN_TRUST_PROXY_HOPS=0: behind a proxy every client will look like one IP "
            "(shared rate limits, wrong IPs in certificates). Set it to the number of proxies in front, usually 1."
        )

    stop = threading.Event()

    def worker() -> None:
        tick = 0
        while not stop.wait(1.0):
            try:
                hooks.process_due()
                svc.process_batches()
                if tick % 30 == 0:
                    svc.maintenance()
            except Exception:
                log.exception("worker error")
            tick += 1

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        t = None
        if not s.webhooks_inline:
            t = threading.Thread(target=worker, daemon=True, name="hubsign-worker")
            t.start()
        yield
        stop.set()
        if t:
            await asyncio.to_thread(t.join, 5)

    app = FastAPI(
        title="HubSign API",
        version=__version__,
        lifespan=lifespan,
        description="Send documents for signature. Authenticate with `Authorization: Bearer hs_test_...` "
        "(sandbox) or `hs_live_...`. Webhooks are signed with HMAC-SHA256. Completed PDFs carry a PAdES seal.",
    )
    app.state.svc, app.state.db = svc, db

    def ip_of(request: Request) -> str:
        n = s.trust_proxy_hops
        if n > 0:
            parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
            if len(parts) >= n:
                return parts[
                    -n
                ]  # the address our outermost trusted proxy saw; anything left of it is client-controlled
        return request.client.host if request.client else ""

    def limited(request: Request) -> tuple[str, int] | None:
        p = request.url.path
        if p == "/v1/verify":
            return f"pub:{ip_of(request)}", s.rate_public_per_min
        if p.startswith("/sign-api/"):
            return f"sign:{ip_of(request)}", s.rate_sign_per_min
        if p.startswith("/auth/"):
            return f"auth:{ip_of(request)}", s.rate_auth_per_min
        if p.startswith("/v1/"):
            a = request.headers.get("authorization", "")
            who = (
                "k:" + hashlib.sha256(a.encode()).hexdigest()[:16]
                if a
                else "s:" + (request.cookies.get("hubsign_session", "")[:20] or ip_of(request))
            )
            return who, s.rate_api_per_min
        return None

    max_body = s.max_doc_mb * 2 * 1024 * 1024 + 65536  # a base64 document, or a PDF sent to /v1/verify

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            cl = request.headers.get("content-length")
            if cl is None and request.headers.get("transfer-encoding"):
                return JSONResponse(
                    {"detail": "send a Content-Length (chunked uploads are not accepted)"}, status_code=411
                )
            if cl and (not cl.isdigit() or int(cl) > max_body):
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        lim = limited(request)
        remaining = None
        if lim and lim[1] > 0:
            ok, remaining, wait = await asyncio.to_thread(db.hit, lim[0], lim[1], 60)
            if not ok:
                return JSONResponse(
                    {"detail": "rate limit exceeded"},
                    status_code=429,
                    headers={"Retry-After": str(wait), "X-RateLimit-Limit": str(lim[1]), "X-RateLimit-Remaining": "0"},
                )
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"  # signing links carry the secret in the path
        if lim and lim[1] > 0:
            resp.headers["X-RateLimit-Limit"], resp.headers["X-RateLimit-Remaining"] = str(lim[1]), str(remaining)
        if request.url.path.startswith(("/sign", "/v1", "/auth")):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.exception_handler(Error)
    async def on_error(_: Request, e: Error):
        return JSONResponse({"detail": e.msg}, status_code=e.status)

    # ---- identity of the caller ------------------------------------------------------------------------------------
    def memberships(uid: str) -> list[dict]:
        return db.q(
            "SELECT m.org_id AS id, o.name, m.role FROM memberships m JOIN orgs o ON o.id=m.org_id WHERE m.user_id=? ORDER BY m.created_at, m.org_id",
            (uid,),
        )

    def ctx(request: Request) -> Ctx:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            k = db.one("SELECT * FROM api_keys WHERE hash=? AND revoked=0", (security.key_hash(auth[7:]),))
            if k:
                db.x("UPDATE api_keys SET last_used_at=? WHERE id=?", (now(), k["id"]))
                return Ctx(
                    db.one("SELECT * FROM users WHERE id=?", (k["created_by"],)),
                    k["org_id"],
                    k["role"],
                    k["mode"],
                    "key",
                )
        else:
            uid = security.read_session(s.secret, request.cookies.get("hubsign_session"))
            u = uid and db.one("SELECT * FROM users WHERE id=?", (uid,))
            if u:
                mine = memberships(uid)
                if mine:
                    want = request.headers.get("x-hubsign-org") or request.query_params.get("org")
                    pick = next((m for m in mine if m["id"] == want), None) if want else mine[0]
                    if not pick:
                        raise HTTPException(403, "you are not a member of that organisation")
                    mode = request.headers.get("x-hubsign-mode") or request.query_params.get("mode") or "test"
                    return Ctx(u, pick["id"], pick["role"], mode if mode in ("test", "live") else "test", "session")
        raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})

    def need(level: str):
        def dep(c: Ctx = Depends(ctx)) -> Ctx:
            if RANK[c.role] < RANK[level]:
                raise HTTPException(403, f"this needs the {level} role")
            return c

        return dep

    def session_admin(c: Ctx = Depends(need("admin"))) -> Ctx:
        if c.via != "session":
            raise HTTPException(403, "this endpoint needs a dashboard login, not an API key")
        return c

    # ---- auth ------------------------------------------------------------------------------------------------------
    def start_session(resp: Response, uid: str) -> None:
        resp.set_cookie(
            "hubsign_session",
            security.make_session(s.secret, uid),
            httponly=True,
            samesite="lax",
            secure=https,
            max_age=14 * 86400,
        )

    def new_org(name: str, uid: str, role: str = "owner") -> str:
        oid = rid("org")
        db.x("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)", (oid, name, now()))
        db.x("INSERT INTO memberships(org_id,user_id,role,created_at) VALUES(?,?,?,?)", (oid, uid, role, now()))
        return oid

    def find_invite(token: str) -> dict | None:
        inv = db.one("SELECT * FROM invites WHERE token_hash=? AND accepted_at IS NULL", (security.key_hash(token),))
        return inv if inv and inv["expires_at"] > now() else None

    @app.post("/auth/signup", tags=["auth"])
    def signup(b: Creds, resp: Response):
        first = not db.one("SELECT 1 AS x FROM users LIMIT 1")
        inv = find_invite(b.invite_token) if b.invite_token else None
        if b.invite_token and not inv:
            raise HTTPException(422, "that invitation is invalid or expired")
        if not (first or s.allow_signup or inv):
            raise HTTPException(403, "signup is disabled")
        email = b.email.lower()
        if inv and inv["email"] != email:
            raise HTTPException(422, "that invitation was sent to a different email address")
        if db.one("SELECT 1 AS x FROM users WHERE email=?", (email,)):
            raise HTTPException(409, "an account with that email already exists")
        uid, name = rid("usr"), b.name or email.split("@")[0]
        db.x(
            "INSERT INTO users(id,email,name,pw_hash,created_at) VALUES(?,?,?,?,?)",
            (uid, email, name, security.hash_password(b.password), now()),
        )
        if inv:
            db.x(
                "INSERT INTO memberships(org_id,user_id,role,created_at) VALUES(?,?,?,?)",
                (inv["org_id"], uid, inv["role"], now()),
            )
            db.x("UPDATE invites SET accepted_at=? WHERE id=?", (now(), inv["id"]))
        else:
            new_org(f"{name}'s workspace", uid)
        start_session(resp, uid)
        return {"id": uid, "email": email}

    @app.post("/auth/login", tags=["auth"])
    def login(b: Creds, request: Request, resp: Response):
        key = f"login:{b.email.lower()}|{ip_of(request)}"
        ok, _, wait = db.hit(key, 5, 900)
        if not ok:
            raise HTTPException(429, f"too many attempts, try again in {wait // 60 + 1} minutes")
        u = db.one("SELECT * FROM users WHERE email=?", (b.email.lower(),))
        if not (u and security.check_password(b.password, u["pw_hash"])):
            raise HTTPException(401, "wrong email or password")
        db.reset_hits(key)
        start_session(resp, u["id"])
        return {"id": u["id"], "email": u["email"]}

    @app.post("/auth/logout", tags=["auth"])
    def logout(resp: Response):
        resp.delete_cookie("hubsign_session")
        return {"ok": True}

    @app.get("/auth/me", tags=["auth"])
    def me(c: Ctx = Depends(ctx)):
        return {
            "id": c.user["id"], "email": c.user["email"], "name": c.user["name"], "mode": c.mode, "via": c.via,
            "org": c.org, "role": c.role, "orgs": memberships(c.user["id"]),
        }  # fmt: skip

    # ---- organisations ---------------------------------------------------------------------------------------------
    @app.post("/v1/orgs", status_code=201, tags=["organisation"])
    def create_org(b: OrgIn, c: Ctx = Depends(ctx)):
        if c.via != "session":
            raise HTTPException(403, "needs a dashboard login")
        return {"id": new_org(b.name.strip(), c.user["id"]), "name": b.name.strip(), "role": "owner"}

    @app.get("/v1/org", tags=["organisation"])
    def get_org(c: Ctx = Depends(ctx)):
        o = db.one("SELECT * FROM orgs WHERE id=?", (c.org,))
        members = db.q(
            "SELECT u.id, u.name, u.email, m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=? ORDER BY m.created_at, u.id",
            (c.org,),
        )
        invites = []
        if RANK[c.role] >= RANK["admin"]:
            invites = db.q(
                "SELECT id,email,role,created_at,expires_at FROM invites WHERE org_id=? AND accepted_at IS NULL AND expires_at>? ORDER BY created_at",
                (c.org, now()),
            )
        return {"id": o["id"], "name": o["name"], "role": c.role, "members": members, "invites": invites}

    @app.patch("/v1/org", tags=["organisation"])
    def rename_org(b: OrgIn, c: Ctx = Depends(session_admin)):
        db.x("UPDATE orgs SET name=? WHERE id=?", (b.name.strip(), c.org))
        return get_org(c)

    def owners(org: str) -> int:
        return db.one("SELECT COUNT(*) AS n FROM memberships WHERE org_id=? AND role='owner'", (org,))["n"]

    @app.patch("/v1/org/members/{uid}", tags=["organisation"])
    def change_role(uid: str, b: RoleChange, c: Ctx = Depends(session_admin)):
        m = db.one("SELECT * FROM memberships WHERE org_id=? AND user_id=?", (c.org, uid))
        if not m:
            raise HTTPException(404, "member not found")
        if (m["role"] == "owner" or b.role == "owner") and c.role != "owner":
            raise HTTPException(403, "only an owner can change owner roles")
        if m["role"] == "owner" and b.role != "owner" and owners(c.org) <= 1:
            raise HTTPException(409, "an organisation needs at least one owner")
        db.x("UPDATE memberships SET role=? WHERE org_id=? AND user_id=?", (b.role, c.org, uid))
        return get_org(c)

    @app.delete("/v1/org/members/{uid}", status_code=204, tags=["organisation"])
    def remove_member(uid: str, c: Ctx = Depends(ctx)):
        if c.via != "session" or (uid != c.user["id"] and RANK[c.role] < RANK["admin"]):
            raise HTTPException(403, "you cannot remove that member")
        m = db.one("SELECT * FROM memberships WHERE org_id=? AND user_id=?", (c.org, uid))
        if not m:
            raise HTTPException(404, "member not found")
        if m["role"] == "owner" and (c.role != "owner" or owners(c.org) <= 1):
            raise HTTPException(409, "an organisation needs at least one owner")
        db.x("DELETE FROM memberships WHERE org_id=? AND user_id=?", (c.org, uid))
        db.x("UPDATE api_keys SET revoked=1 WHERE org_id=? AND created_by=?", (c.org, uid))  # their keys go with them

    @app.post("/v1/org/invites", status_code=201, tags=["organisation"])
    def invite(b: InviteIn, c: Ctx = Depends(session_admin)):
        tok = secrets.token_urlsafe(32)
        iid = rid("inv")
        db.x(
            "INSERT INTO invites(id,org_id,email,role,token_hash,invited_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                iid,
                c.org,
                b.email.lower(),
                b.role,
                security.key_hash(tok),
                c.user["id"],
                now(),
                (datetime.now(UTC) + timedelta(days=7)).isoformat(timespec="microseconds"),
            ),
        )
        url = f"{s.base_url.rstrip('/')}/#invite/{tok}"
        org = db.one("SELECT name FROM orgs WHERE id=?", (c.org,))["name"]
        mail.send(
            s,
            b.email,
            f"{c.user['name']} invited you to {org} on HubSign",
            f"{c.user['name']} invited you to join {org} on HubSign.\n\n{url}\n\nThe link works for 7 days.",
        )
        return {"id": iid, "email": b.email.lower(), "role": b.role, "accept_url": url}

    @app.delete("/v1/org/invites/{iid}", status_code=204, tags=["organisation"])
    def cancel_invite(iid: str, c: Ctx = Depends(session_admin)):
        db.x("DELETE FROM invites WHERE id=? AND org_id=?", (iid, c.org))

    @app.post("/v1/invites/accept", tags=["organisation"])
    def accept_invite(b: TokenIn, c: Ctx = Depends(ctx)):
        inv = find_invite(b.token)
        if not inv or c.via != "session":
            raise HTTPException(422, "that invitation is invalid or expired")
        if inv["email"] != c.user["email"]:
            raise HTTPException(403, "that invitation was sent to a different email address")
        if not db.x("UPDATE invites SET accepted_at=? WHERE id=? AND accepted_at IS NULL", (now(), inv["id"])):
            raise HTTPException(422, "that invitation was already used")
        db.x(
            "INSERT INTO memberships(org_id,user_id,role,created_at) VALUES(?,?,?,?) ON CONFLICT(org_id,user_id) DO NOTHING",
            (inv["org_id"], c.user["id"], inv["role"], now()),
        )
        return {"org": inv["org_id"]}

    # ---- envelopes -------------------------------------------------------------------------------------------------
    def decode_doc(b64: str) -> bytes:
        try:
            return base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(422, "document_base64 is not valid base64") from None

    def sized(fields: list[FieldIn]) -> list[dict]:
        out = []
        for f in fields:
            dw, dh = DEFAULT_SIZE[f.type]
            d = f.model_dump()
            if f.anchor is None:
                d["w"], d["h"] = f.w or dw, f.h or dh
            out.append(d)
        return out

    @app.post("/v1/envelopes", status_code=201, tags=["envelopes"])
    def create_envelope(b: EnvelopeIn, c: Ctx = Depends(need("sender"))):
        docs = (
            [
                {"id": d.id or str(i + 1), "name": d.name, "data": decode_doc(d.document_base64)}
                for i, d in enumerate(b.documents)
            ]
            if b.documents
            else [{"id": "1", "name": b.document_name, "data": decode_doc(b.document_base64)}]
        )
        eid = svc.create(
            c.org, c.user["id"], c.mode, subject=b.subject, message=b.message, documents=docs,
            recipients=[r.model_dump() for r in b.recipients], fields=sized(b.fields), sequential=b.sequential, metadata=b.metadata,
            allow_reassign=b.allow_reassign, reply_to=b.reply_to.model_dump() if b.reply_to else None, sender_name=b.sender_name,
        )  # fmt: skip
        if b.send:
            svc.send(eid, c.org, c.mode)
        return svc.detail(eid, c.org, c.mode)

    @app.get("/v1/envelopes", tags=["envelopes"])
    def list_envelopes(
        status: str | None = None, q: str | None = None, limit: int = 50, offset: int = 0, c: Ctx = Depends(ctx)
    ):
        sql, args = (
            "SELECT id, updated_at FROM envelopes WHERE org_id=? AND mode=? AND status<>'deleting'",
            [c.org, c.mode],
        )
        if status:
            sql, args = (
                sql + (" AND status IN ('sent','finalizing')" if status == "sent" else " AND status=?"),
                [*args, *([] if status == "sent" else [status])],
            )
        if q:
            like = "%" + q[:100].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            sql += " AND (subject LIKE ? ESCAPE '\\' OR id IN (SELECT envelope_id FROM recipients WHERE name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\'))"
            args += [like, like, like]
        rows = db.q(
            sql + " ORDER BY updated_at DESC, id LIMIT ? OFFSET ?", (*args, min(max(limit, 1), 200), max(offset, 0))
        )
        return {"envelopes": [svc.summary(r["id"]) | {"updated_at": r["updated_at"]} for r in rows]}

    @app.get("/v1/envelopes/counts", tags=["envelopes"])
    def envelope_counts(c: Ctx = Depends(ctx)):
        out = {k: 0 for k in ("draft", "sent", "completed", "declined", "voided")}
        for r in db.q(
            "SELECT status, COUNT(*) AS n FROM envelopes WHERE org_id=? AND mode=? GROUP BY status", (c.org, c.mode)
        ):
            k = "sent" if r["status"] == "finalizing" else r["status"]
            if k in out:
                out[k] += r["n"]
        month_ago = (datetime.now(UTC) - timedelta(days=30)).isoformat(timespec="microseconds")
        done = db.one(
            "SELECT COUNT(*) AS n FROM envelopes WHERE org_id=? AND mode=? AND status='completed' AND completed_at>=?",
            (c.org, c.mode, month_ago),
        )
        return out | {"all": sum(out.values()), "completed_30d": done["n"]}

    @app.get("/v1/envelopes/{eid}", tags=["envelopes"])
    def get_envelope(eid: str, c: Ctx = Depends(ctx)):
        return svc.detail(eid, c.org, c.mode)

    @app.post("/v1/envelopes/{eid}/send", tags=["envelopes"])
    def send_envelope(eid: str, c: Ctx = Depends(need("sender"))):
        svc.send(eid, c.org, c.mode)
        return svc.detail(eid, c.org, c.mode)

    @app.post("/v1/envelopes/{eid}/void", tags=["envelopes"])
    def void_envelope(eid: str, b: VoidIn, c: Ctx = Depends(need("sender"))):
        svc.void(eid, c.org, c.mode, b.reason)
        return svc.detail(eid, c.org, c.mode)

    @app.delete("/v1/envelopes/{eid}", status_code=204, tags=["envelopes"])
    def delete_envelope(eid: str, c: Ctx = Depends(need("sender"))):
        svc.delete_draft(eid, c.org, c.mode)

    @app.get("/v1/envelopes/{eid}/events", tags=["envelopes"])
    def envelope_events(eid: str, c: Ctx = Depends(ctx)):
        svc.env(eid, c.org, c.mode)
        return {"events": svc.events(eid)}

    @app.get("/v1/envelopes/{eid}/document", tags=["envelopes"])
    def original_document(eid: str, c: Ctx = Depends(ctx)):
        e = svc.env(eid, c.org, c.mode)
        return pdf_response(svc.file_bytes(eid, False), e["doc_name"])

    @app.get("/v1/envelopes/{eid}/signed", tags=["envelopes"])
    def signed_document(eid: str, c: Ctx = Depends(ctx)):
        svc.env(eid, c.org, c.mode)
        return pdf_response(svc.file_bytes(eid, True), f"{eid}-signed.pdf")

    @app.get("/v1/envelopes/{eid}/form_data", tags=["envelopes"])
    def envelope_form_data(eid: str, c: Ctx = Depends(ctx)):
        """What signers typed or ticked, by field label."""
        return {"form_data": svc.form_data(eid, c.org, c.mode)}

    @app.get("/v1/envelopes/{eid}/documents/{doc_id}", tags=["envelopes"])
    def envelope_document(eid: str, doc_id: str, c: Ctx = Depends(ctx)):
        """One document of a completed envelope with signatures on it, sealed as an excerpt."""
        data, name = svc.document_excerpt(eid, doc_id, c.org, c.mode)
        return pdf_response(data, f"signed-{name}")

    # ---- templates + bulk ------------------------------------------------------------------------------------------
    def tpl_out(t: dict) -> dict:
        return {
            k: t[k]
            for k in ("id", "name", "description", "doc_name", "pages", "roles", "fields", "sequential", "created_at")
        }

    @app.post("/v1/templates", status_code=201, tags=["templates"])
    def create_template(b: TemplateIn, c: Ctx = Depends(need("sender"))):
        tid = svc.create_template(
            c.org, c.user["id"], c.mode, name=b.name, description=b.description, doc=decode_doc(b.document_base64), doc_name=b.document_name,
            roles=[r.model_dump() for r in b.roles], fields=sized(b.fields), sequential=b.sequential,
        )  # fmt: skip
        return tpl_out(svc.template(tid, c.org, c.mode))

    @app.get("/v1/templates", tags=["templates"])
    def list_templates(c: Ctx = Depends(ctx)):
        rows = db.q("SELECT id FROM templates WHERE org_id=? AND mode=? ORDER BY created_at DESC, id", (c.org, c.mode))
        return {"templates": [tpl_out(svc.template(r["id"], c.org, c.mode)) for r in rows]}

    @app.get("/v1/templates/{tid}", tags=["templates"])
    def get_template(tid: str, c: Ctx = Depends(ctx)):
        return tpl_out(svc.template(tid, c.org, c.mode))

    @app.get("/v1/templates/{tid}/document", tags=["templates"])
    def template_document(tid: str, c: Ctx = Depends(ctx)):
        t = svc.template(tid, c.org, c.mode)
        data = storage.get(f"{tid}.pdf")
        if data is None:
            raise HTTPException(404, "document not available")
        return pdf_response(data, t["doc_name"])

    @app.delete("/v1/templates/{tid}", status_code=204, tags=["templates"])
    def delete_template(tid: str, c: Ctx = Depends(need("sender"))):
        svc.delete_template(tid, c.org, c.mode)

    @app.post("/v1/templates/{tid}/envelopes", status_code=201, tags=["templates"])
    def envelope_from_template(tid: str, b: UseTemplateIn, c: Ctx = Depends(need("sender"))):
        eid = svc.use_template(
            tid, c.org, c.user["id"], c.mode, people=[p.model_dump() for p in b.recipients], subject=b.subject,
            message=b.message, metadata=b.metadata, send=b.send,
        )  # fmt: skip
        return svc.detail(eid, c.org, c.mode)

    @app.post("/v1/templates/{tid}/bulk", status_code=202, tags=["templates"])
    def bulk_send(tid: str, b: BulkIn, c: Ctx = Depends(need("sender"))):
        bid = svc.create_batch(
            c.org,
            c.user["id"],
            c.mode,
            tid,
            rows=[[p.model_dump() for p in row] for row in b.rows],
            subject=b.subject,
            message=b.message,
            send=b.send,
        )
        return svc.batch(bid, c.org, c.mode)

    @app.get("/v1/batches", tags=["templates"])
    def list_batches(c: Ctx = Depends(ctx)):
        rows = db.q(
            "SELECT id FROM batches WHERE org_id=? AND mode=? ORDER BY created_at DESC, id LIMIT 20", (c.org, c.mode)
        )
        return {"batches": [svc.batch(r["id"], c.org, c.mode) for r in rows]}

    @app.get("/v1/batches/{bid}", tags=["templates"])
    def get_batch(bid: str, c: Ctx = Depends(ctx)):
        return svc.batch(bid, c.org, c.mode)

    # ---- developer tools: keys -------------------------------------------------------------------------------------
    @app.post("/v1/api-keys", status_code=201, tags=["developer"])
    def create_key(b: KeyIn, c: Ctx = Depends(session_admin)):
        key, prefix, h = security.new_api_key(b.mode)
        kid = rid("key")
        db.x(
            "INSERT INTO api_keys(id,org_id,created_by,name,mode,role,prefix,hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (kid, c.org, c.user["id"], b.name, b.mode, b.role, prefix, h, now()),
        )
        return {
            "id": kid,
            "name": b.name,
            "mode": b.mode,
            "role": b.role,
            "key": key,
            "note": "Store this key now. It is not shown again.",
        }

    @app.get("/v1/api-keys", tags=["developer"])
    def list_keys(c: Ctx = Depends(session_admin)):
        return {
            "keys": db.q(
                "SELECT id,name,mode,role,prefix,created_at,last_used_at FROM api_keys WHERE org_id=? AND revoked=0 ORDER BY created_at DESC",
                (c.org,),
            )
        }

    @app.delete("/v1/api-keys/{kid}", status_code=204, tags=["developer"])
    def revoke_key(kid: str, c: Ctx = Depends(session_admin)):
        if not db.x("UPDATE api_keys SET revoked=1 WHERE id=? AND org_id=?", (kid, c.org)):
            raise HTTPException(404, "key not found")

    # ---- developer tools: webhooks ---------------------------------------------------------------------------------
    def wh_or_404(wid: str, c: Ctx) -> dict:
        w = db.one("SELECT * FROM webhooks WHERE id=? AND org_id=? AND mode=?", (wid, c.org, c.mode))
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
    def create_webhook(b: WebhookIn, c: Ctx = Depends(need("admin"))):
        bad = security.url_is_safe(b.url, s.allow_private_webhooks)
        if bad:
            raise HTTPException(422, bad)
        unknown = [e for e in b.events if e not in EVENTS]
        if unknown:
            raise HTTPException(422, f"unknown events: {unknown}")
        wid, secret = rid("wh"), "whsec_" + secrets.token_urlsafe(24)
        db.x(
            "INSERT INTO webhooks(id,org_id,created_by,mode,url,secret,events,active,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (wid, c.org, c.user["id"], c.mode, b.url, secret, json.dumps(b.events), 1, now()),
        )
        return wh_out(wh_or_404(wid, c), secret=True)

    @app.get("/v1/webhooks", tags=["developer"])
    def list_webhooks(c: Ctx = Depends(ctx)):
        return {
            "webhooks": [
                wh_out(w)
                for w in db.q(
                    "SELECT * FROM webhooks WHERE org_id=? AND mode=? AND active=1 ORDER BY created_at DESC",
                    (c.org, c.mode),
                )
            ]
        }

    @app.get("/v1/webhooks/{wid}", tags=["developer"])
    def get_webhook(wid: str, c: Ctx = Depends(need("admin"))):
        return wh_out(wh_or_404(wid, c), secret=True)

    @app.delete("/v1/webhooks/{wid}", status_code=204, tags=["developer"])
    def delete_webhook(wid: str, c: Ctx = Depends(need("admin"))):
        wh_or_404(wid, c)
        db.x("UPDATE webhooks SET active=0 WHERE id=?", (wid,))

    @app.get("/v1/webhooks/{wid}/deliveries", tags=["developer"])
    def deliveries(wid: str, c: Ctx = Depends(ctx)):
        wh_or_404(wid, c)
        rows = db.q(
            "SELECT id,event,status,attempts,http_status,response,created_at,last_at,payload FROM deliveries WHERE webhook_id=? ORDER BY created_at DESC, id LIMIT 50",
            (wid,),
        )
        return {"deliveries": [r | {"payload": json.loads(r["payload"])} for r in rows]}

    @app.post("/v1/webhooks/{wid}/test", tags=["developer"])
    def test_webhook(wid: str, c: Ctx = Depends(need("sender"))):
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
    def redeliver(did: str, c: Ctx = Depends(need("sender"))):
        d = db.one(
            "SELECT d.* FROM deliveries d JOIN webhooks w ON w.id=d.webhook_id WHERE d.id=? AND w.org_id=? AND w.mode=?",
            (did, c.org, c.mode),
        )
        if not d:
            raise HTTPException(404, "delivery not found")
        return {"delivery_id": hooks.queue(d["webhook_id"], d["event"], json.loads(d["payload"]))}

    # ---- signer (public; the link is the credential, plus the identity check if the sender asked for one) -----------------
    def sig_cookie(request: Request) -> str | None:
        return request.cookies.get("hs_sig")

    @app.get("/sign/{token}", include_in_schema=False)
    def sign_page(token: str):
        return FileResponse(WEB / "sign.html")

    @app.get("/sign-api/{token}", tags=["signing"])
    def sign_info(token: str, request: Request):
        return svc.signer_view(token, ip_of(request), request.headers.get("user-agent", ""), sig_cookie(request))

    @app.post("/sign-api/{token}/auth/send", tags=["signing"])
    def sign_auth_send(token: str, request: Request):
        svc.auth_send(token, ip_of(request), request.headers.get("user-agent", ""))
        return {"ok": True}

    @app.post("/sign-api/{token}/auth/verify", tags=["signing"])
    def sign_auth_verify(token: str, b: CodeIn, request: Request, resp: Response):
        tok = svc.auth_verify(token, b.code, ip_of(request), request.headers.get("user-agent", ""))
        resp.set_cookie(
            "hs_sig", tok, httponly=True, samesite="lax", secure=https, max_age=7200, path=f"/sign-api/{token}"
        )
        return {"ok": True}

    @app.get("/sign-api/{token}/document", tags=["signing"])
    def sign_doc(token: str, request: Request):
        r, e = svc.by_token(token)
        svc.require_session(r, sig_cookie(request))
        return pdf_response(svc.file_bytes(e["id"], False), e["doc_name"], inline=True)

    @app.get("/sign-api/{token}/signed", tags=["signing"])
    def sign_signed(token: str, request: Request):
        r, e = svc.by_token(token)
        svc.require_session(r, sig_cookie(request))
        if e["status"] != "completed":
            raise HTTPException(409, "envelope is not complete yet")
        return pdf_response(svc.file_bytes(e["id"], True), f"{e['id']}-signed.pdf")

    @app.post("/sign-api/{token}/complete", tags=["signing"])
    def sign_complete(token: str, b: CompleteIn, request: Request):
        return svc.complete(token, b.values, ip_of(request), request.headers.get("user-agent", ""), sig_cookie(request))

    @app.post("/sign-api/{token}/reassign", tags=["signing"])
    def sign_reassign(token: str, b: ReassignIn, request: Request):
        svc.reassign(token, b.name, b.email, ip_of(request), request.headers.get("user-agent", ""), sig_cookie(request))
        return {"ok": True}

    @app.post("/sign-api/{token}/decline", tags=["signing"])
    def sign_decline(token: str, b: DeclineIn, request: Request):
        svc.decline(token, b.reason, ip_of(request), request.headers.get("user-agent", ""), sig_cookie(request))
        return {"ok": True}

    # ---- public verification of a sealed PDF ---------------------------------------------------------------------------
    @app.post("/v1/verify", tags=["verification"])
    async def verify(request: Request):
        """Upload a PDF as the raw request body (Content-Type: application/pdf). No authentication needed."""
        data = await request.body()
        if len(data) > s.max_doc_mb * 1024 * 1024 * 2:
            raise HTTPException(413, "file too large")
        report = await asyncio.to_thread(svc.sealer.verify, data)
        report["issued_by_this_server"] = None
        try:
            import io

            from pypdf import PdfReader

            eid = (PdfReader(io.BytesIO(data)).metadata or {}).get("/HubSignEnvelope")
        except Exception:
            eid = None
        if eid:
            e = db.one("SELECT id, final_sha256, completed_at, mode FROM envelopes WHERE id=?", (eid,))
            if e:
                report["envelope_id"] = e["id"]
                report["completed_at"] = e["completed_at"]
                report["sandbox"] = e["mode"] == "test"
                report["issued_by_this_server"] = hashlib.sha256(data).hexdigest() == e["final_sha256"]
        return report

    @app.get("/verify", include_in_schema=False)
    def verify_page():
        return FileResponse(WEB / "verify.html")

    @app.get("/.well-known/hubsign-seal.pem", include_in_schema=False)
    def seal_cert():
        return Response(
            svc.sealer.cert_pem,
            media_type="application/x-pem-file",
            headers={"Content-Disposition": 'attachment; filename="hubsign-seal.pem"'},
        )

    @app.get("/v1/seal", tags=["verification"])
    def seal_info():
        return {
            "fingerprint_sha256": svc.sealer.fingerprint,
            "self_signed": svc.sealer.generated,
            "timestamping": bool(svc.sealer.timestamper),
            "certificate_url": "/.well-known/hubsign-seal.pem",
        }

    # ---- misc ------------------------------------------------------------------------------------------------------
    @app.get("/api/ping", include_in_schema=False)
    def ping():
        return {"ok": True, "version": __version__}

    @app.get("/api/ready", include_in_schema=False)
    def ready():
        try:
            db.q("SELECT 1 AS ok")
            storage.ping()
        except Exception as e:
            raise HTTPException(503, f"not ready: {type(e).__name__}") from e
        return {"ok": True}

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(WEB / "index.html")

    return app
