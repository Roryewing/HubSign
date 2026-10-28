"""Best-effort email. Without SMTP settings nothing is sent; signing links are also in the API response."""

from __future__ import annotations

import smtplib
import threading
from email.message import EmailMessage

from .config import Settings


def configured(s: Settings) -> bool:
    return bool(s.smtp_host and s.smtp_from)


def send(s: Settings, to: str, subject: str, body: str, background: bool = True) -> None:
    if not configured(s):
        return
    m = EmailMessage()
    m["Subject"], m["From"], m["To"] = subject, s.smtp_from, to
    m.set_content(body)

    def go() -> None:
        try:
            with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=15) as c:
                c.starttls()
                if s.smtp_user:
                    c.login(s.smtp_user, s.smtp_password)
                c.send_message(m)
        except Exception:
            pass

    threading.Thread(target=go, daemon=True).start() if background else go()
