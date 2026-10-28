"""Signer identity checks beyond holding the link: sender-set access code, or a one-time code by SMS or email.

Sandbox envelopes never send anything: the one-time code is always 000000, so integrations can be tested.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta

import httpx

from . import mail, security
from .config import Settings
from .db import Database

METHODS = ("none", "access_code", "sms", "email")
PHONE = re.compile(r"^\+[1-9]\d{7,14}$")
OTP_TTL_MIN = 10
OTP_MAX_ATTEMPTS = 5
SANDBOX_CODE = "000000"


class AuthError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def twilio_send(s: Settings, to: str, body: str) -> None:
    r = httpx.post(
        f"https://api.twilio.com/2010-04-01/Accounts/{s.twilio_sid}/Messages.json",
        data={"To": to, "From": s.twilio_from, "Body": body},
        auth=(s.twilio_sid, s.twilio_token),
        timeout=10,
    )
    r.raise_for_status()


def mask_phone(p: str | None) -> str:
    return f"+••• ••• {p[-2:]}" if p else ""


def mask_email(e: str) -> str:
    u, _, d = e.partition("@")
    return f"{u[:1]}•••@{d}"


class Identity:
    def __init__(self, settings: Settings, db: Database, sms_sender=twilio_send):
        self.s, self.db, self.sms_sender = settings, db, sms_sender

    @property
    def sms_ready(self) -> bool:
        return bool(self.s.twilio_sid and self.s.twilio_token and self.s.twilio_from)

    def prepare(self, auth: dict | None, mode: str) -> tuple[str, str | None, str | None]:
        """Validate a recipient's authentication request -> (method, hashed access code, phone)."""
        auth = auth or {}
        method = auth.get("method", "none")
        if method not in METHODS:
            raise AuthError(422, f"unknown authentication method {method}")
        if method == "access_code":
            code = auth.get("access_code") or ""
            if not 4 <= len(code) <= 64:
                raise AuthError(422, "access_code must be 4 to 64 characters")
            return method, security.hash_password(code), None
        if method == "sms":
            phone = (auth.get("phone") or "").replace(" ", "")
            if not PHONE.match(phone):
                raise AuthError(
                    422, "sms authentication needs a phone number in international format, e.g. +14165550123"
                )
            if mode == "live" and not self.sms_ready:
                raise AuthError(422, "SMS verification is not configured on this server")
            return method, None, phone
        if method == "email" and mode == "live" and not mail.configured(self.s):
            raise AuthError(422, "email verification is not configured on this server")
        return method, None, None

    def _hash(self, rid: str, code: str) -> str:
        return hmac.new(self.s.secret.encode(), f"{rid}:{code}".encode(), "sha256").hexdigest()

    def send_code(self, r: dict, mode: str) -> None:
        if r["auth_method"] not in ("sms", "email"):
            raise AuthError(400, "this recipient does not use one-time codes")
        ok, _, wait = self.db.hit(f"otp:{r['id']}", 3, 600)
        if not ok:
            raise AuthError(429, f"too many codes requested, try again in {wait} seconds")
        code = SANDBOX_CODE if mode == "test" else f"{secrets.randbelow(10**6):06d}"
        exp = (datetime.now(UTC) + timedelta(minutes=OTP_TTL_MIN)).isoformat(timespec="seconds")
        self.db.x("DELETE FROM otps WHERE recipient_id=?", (r["id"],))
        self.db.x(
            "INSERT INTO otps(recipient_id,code_hash,expires_at,attempts,sent_at) VALUES(?,?,?,?,?)",
            (r["id"], self._hash(r["id"], code), exp, 0, datetime.now(UTC).isoformat(timespec="seconds")),
        )
        if mode == "test":
            return
        text = f"Your HubSign verification code is {code}. It expires in {OTP_TTL_MIN} minutes."
        if r["auth_method"] == "sms":
            try:
                self.sms_sender(self.s, r["phone"], text)
            except Exception as e:
                raise AuthError(502, "could not send the text message") from e
        else:
            mail.send(self.s, r["email"], "Your HubSign verification code", text)

    def check(self, r: dict, code: str) -> bool:
        code = (code or "").strip()
        if r["auth_method"] == "access_code":
            return bool(code) and security.check_password(code, r["auth_secret"] or "")
        o = self.db.one("SELECT * FROM otps WHERE recipient_id=?", (r["id"],))
        if not o:
            raise AuthError(400, "request a new code first")
        if o["expires_at"] < datetime.now(UTC).isoformat(timespec="seconds"):
            raise AuthError(400, "that code has expired, request a new one")
        if o["attempts"] >= OTP_MAX_ATTEMPTS:
            raise AuthError(429, "too many wrong codes, request a new one")
        if not hmac.compare_digest(self._hash(r["id"], code), o["code_hash"]):
            self.db.x("UPDATE otps SET attempts=attempts+1 WHERE recipient_id=?", (r["id"],))
            return False
        self.db.x("DELETE FROM otps WHERE recipient_id=?", (r["id"],))
        return True

    @staticmethod
    def new_session() -> tuple[str, str, str]:
        tok = secrets.token_urlsafe(32)
        exp = (datetime.now(UTC) + timedelta(hours=2)).isoformat(timespec="seconds")
        return tok, hashlib.sha256(tok.encode()).hexdigest(), exp

    @staticmethod
    def session_ok(r: dict, cookie: str | None) -> bool:
        if r["auth_method"] == "none":
            return True
        if not cookie or not r["session_hash"] or not r["session_expires"]:
            return False
        good = hmac.compare_digest(hashlib.sha256(cookie.encode()).hexdigest(), r["session_hash"])
        return good and r["session_expires"] > datetime.now(UTC).isoformat(timespec="seconds")
