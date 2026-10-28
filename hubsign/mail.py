"""Email: SendGrid's API when HUBSIGN_SENDGRID_API_KEY is set, otherwise SMTP. Without either nothing is sent;
signing links are also in the API response. Best effort: a failed send is logged, never raised into a signing."""

from __future__ import annotations

import html as _html
import logging
import smtplib
import threading
from email.message import EmailMessage

import httpx

from .config import Settings

log = logging.getLogger("hubsign.mail")


def _from(s: Settings) -> str:
    return s.mail_from or s.smtp_from


def configured(s: Settings) -> bool:
    if s.mail_relay_url:
        return bool(s.mail_relay_secret)
    return bool(_from(s) and (s.sendgrid_api_key or s.smtp_host))


def _deliver(
    s: Settings, to: str, subject: str, text: str, html: str | None, reply_to: dict | None, from_name: str | None
) -> None:
    sender = {"email": _from(s), "name": from_name or s.mail_from_name}
    try:
        if s.mail_relay_url:
            # the relay owns the sender address and the provider credentials; we only say what to send, and to whom
            r = httpx.post(
                s.mail_relay_url,
                json={
                    "to": to,
                    "subject": subject,
                    "text": text,
                    "html": html,
                    "reply_to": reply_to,
                    "from_name": from_name or s.mail_from_name,
                },
                headers={"X-Relay-Secret": s.mail_relay_secret},
                timeout=20,
            )
            if r.status_code >= 300:
                log.error("mail relay refused mail to %s: %s %s", to, r.status_code, r.text[:200])
            return
        if s.sendgrid_api_key:
            body = {
                "personalizations": [{"to": [{"email": to}]}],
                "from": sender,
                "subject": subject,
                "content": [
                    {"type": "text/plain", "value": text},
                    *([{"type": "text/html", "value": html}] if html else []),
                ],
            }
            if reply_to:
                body["reply_to"] = {k: v for k, v in reply_to.items() if k in ("email", "name") and v}
            r = httpx.post(
                "https://api.sendgrid.com/v3/mail/send",
                json=body,
                headers={"Authorization": f"Bearer {s.sendgrid_api_key}"},
                timeout=15,
            )
            if r.status_code >= 300:
                log.error("sendgrid refused mail to %s: %s %s", to, r.status_code, r.text[:200])
            return
        m = EmailMessage()
        m["Subject"], m["From"], m["To"] = subject, f"{sender['name']} <{sender['email']}>", to
        if reply_to and reply_to.get("email"):
            m["Reply-To"] = reply_to["email"]
        m.set_content(text)
        if html:
            m.add_alternative(html, subtype="html")
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=15) as c:
            c.starttls()
            if s.smtp_user:
                c.login(s.smtp_user, s.smtp_password)
            c.send_message(m)
    except Exception:
        log.exception("could not send mail to %s", to)


def send(s: Settings, to: str, subject: str, text: str, *, html: str | None = None, reply_to: dict | None = None,
         from_name: str | None = None, background: bool = True) -> None:  # fmt: skip
    if not configured(s):
        return
    args = (s, to, subject, text, html, reply_to, from_name)
    if background:
        threading.Thread(target=_deliver, args=args, daemon=True).start()
    else:
        _deliver(*args)


def signing_html(*, sender: str, name: str, headline: str, message: str, link: str, button: str) -> str:
    e = _html.escape
    msg = (
        f'<p style="margin:16px 0;padding:12px 14px;background:#f3f1fb;border-radius:8px;white-space:pre-wrap">{e(message)}</p>'
        if message
        else ""
    )
    return (
        '<div style="font-family:Inter,Arial,sans-serif;max-width:560px;margin:0 auto;color:#150f33">'
        '<div style="background:#4b2bd6;color:#fff;padding:16px 22px;border-radius:12px 12px 0 0;font-weight:700;font-size:18px">HubSign</div>'
        '<div style="border:1px solid #e3e1ee;border-top:0;padding:22px;border-radius:0 0 12px 12px">'
        f'<p style="margin:0 0 6px;color:#645f7d">{e(sender)} sent you a document</p>'
        f'<h2 style="margin:0 0 8px;font-size:20px">{e(headline)}</h2><p>Hi {e(name)},</p>{msg}'
        f'<p style="margin:22px 0"><a href="{e(link)}" style="background:#ffd23f;color:#2a2000;padding:12px 22px;border-radius:6px;'
        f'text-decoration:none;font-weight:700">{e(button)}</a></p>'
        f'<p style="font-size:12.5px;color:#645f7d">Or paste this link into your browser:<br>{e(link)}</p>'
        '<p style="font-size:12px;color:#645f7d">Do not forward this email: the link is personal to you.</p></div></div>'
    )
