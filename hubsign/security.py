"""Passwords, API keys, session cookies, webhook signatures, SSRF guard."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import socket
import time
from urllib.parse import urlsplit


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${h.hex()}"


def check_password(pw: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split("$")
        got = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
        return hmac.compare_digest(got.hex(), h)
    except ValueError:
        return False


def new_api_key(mode: str) -> tuple[str, str, str]:
    """-> (full key, display prefix, sha256). Only the hash is stored; the key is shown once."""
    key = f"hs_{mode}_{secrets.token_urlsafe(24)}"
    return key, key[:14], hashlib.sha256(key.encode()).hexdigest()


def key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def make_session(secret: str, uid: str, ttl: int = 14 * 86400) -> str:
    exp = int(time.time()) + ttl
    sig = hmac.new(secret.encode(), f"{uid}.{exp}".encode(), "sha256").hexdigest()
    return f"{uid}.{exp}.{sig}"


def read_session(secret: str, cookie: str | None) -> str | None:
    try:
        uid, exp, sig = (cookie or "").split(".")
        good = hmac.new(secret.encode(), f"{uid}.{exp}".encode(), "sha256").hexdigest()
        return uid if hmac.compare_digest(sig, good) and int(exp) > time.time() else None
    except ValueError:
        return None


def sign_webhook(secret: str, body: bytes, ts: int | None = None) -> str:
    """Header value: t=<unix>,v1=<hex hmac-sha256 of "<t>.<body>">. Receivers must also check t is recent."""
    ts = ts or int(time.time())
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, "sha256").hexdigest()
    return f"t={ts},v1={mac}"


def url_is_safe(url: str, allow_private: bool = False) -> str | None:
    """None if the URL may be called, else the reason. Blocks loopback/private/link-local targets (SSRF)."""
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return "URL must be http(s) with a host"
    if allow_private:
        return None
    try:
        for info in socket.getaddrinfo(u.hostname, u.port or (443 if u.scheme == "https" else 80)):
            ip = ipaddress.ip_address(info[4][0])
            if not ip.is_global:
                return "URL resolves to a private or loopback address"
    except OSError:
        return "host does not resolve"
    return None
