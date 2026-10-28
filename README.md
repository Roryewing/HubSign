# HubSign

E-signature platform with a developer API: upload a PDF, place signature fields, route it to signers in order or in
parallel, collect legally-formed signatures with a full audit trail, and get a sealed PDF with a certificate of
completion. Everything the web app does is available over a documented REST API with signed webhooks and a sandbox.

> **Status: v0.1.** Working end to end and tested, but not yet a replacement for a regulated provider. See
> [Limits](#limits-read-before-relying-on-it).

## What it does

| Area | Capability |
|---|---|
| Sending | PDF upload, recipients (signer / gets a copy), routing order, sequential or parallel signing, subject and message, metadata echoed in webhooks |
| Fields | Signature, initials, date signed, name, email (all server-filled, never client-supplied), text, checkbox. Positioned as fractions of the page so they survive any page size. Drag from a palette onto the page, or click to place |
| Templates | Save a document with its roles and fields, then send it to real people in two clicks or one API call |
| Signing | Mobile-friendly signing page: consent step, Start/Next guidance tags, "Adopt Your Signature" with four script styles or freehand drawing, Finish bar, decline with reason, change signature style |
| Output | Signed PDF with every field stamped plus a **certificate of completion** (parties, IPs, timestamps, full audit trail, SHA-256 of the original) |
| Lifecycle | draft → sent → completed, or declined / voided. Drafts can be deleted, sent envelopes voided |
| Audit | Append-only event log per envelope: created, sent, viewed, consent, signed, declined, voided, completed |
| Dashboard | Home with status tiles, Agreements with folders, search and bulk void/delete, detail page with progress tracker, history, signing links and document preview, four-stage composer (documents, recipients, fields, review), Templates |

### Developer tools

| Tool | Detail |
|---|---|
| REST API | `/v1`, OpenAPI at `/docs` and `/redoc`, bearer-key auth |
| API keys | `hs_test_…` and `hs_live_…`, shown once, stored hashed, revocable, last-used tracking |
| Sandbox | Test keys and the Sandbox toggle see separate data. Sandbox PDFs carry a watermark and certificate banner |
| Webhooks | 8 events, per-endpoint subscriptions, HMAC-SHA256 signature with timestamp, retries after 5 s / 1 min / 10 min, delivery log with payloads, redeliver, send test event |
| Embedded signing | Every active recipient has a `signing_url` in the API response. Send it yourself instead of email |
| Python SDK | `hubsign.sdk.HubSign` client and `verify_signature()` for receivers |

## Quick start

```bash
uv sync
uv run hubsign            # http://127.0.0.1:8000
```

Open the app, create the first account, go to **Developer → API keys**, then:

```bash
curl -s localhost:8000/v1/envelopes \
  -H "Authorization: Bearer hs_test_…" -H "Content-Type: application/json" \
  -d '{"subject":"NDA","document_base64":"'"$(base64 -w0 nda.pdf)"'",
       "recipients":[{"name":"Ann Lee","email":"ann@example.com"}],
       "fields":[{"recipient":0,"type":"signature","page":1,"x":0.10,"y":0.85}],
       "metadata":{"deal":"D-1042"},"send":true}'
```

The response contains each active recipient's `signing_url`. Open it, sign, and fetch the result:

```bash
curl -H "Authorization: Bearer hs_test_…" localhost:8000/v1/envelopes/<id>/signed -o signed.pdf
```

### Verifying webhooks

Every delivery carries `HubSign-Signature: t=<unix>,v1=<hex>` where `v1 = HMAC-SHA256(secret, "<t>." + raw_body)`.

```python
from hubsign.sdk import verify_signature

verify_signature(secret, request.headers["HubSign-Signature"], raw_body)  # ValueError if invalid or older than 5 min
```

## Architecture

FastAPI + SQLite (one file) + PDFs on disk. `core.py` holds the envelope state machine and is the only place that
changes envelope state; `api.py` is thin. Stamping and certificates use pypdf and reportlab (`pdfs.py`). Webhook
delivery is in `webhooks.py`. The UI is two static pages (`web/index.html`, `web/sign.html`) with no build step;
pdf.js is loaded from cdnjs.

```
hubsign/
  api.py        routes, auth, request models
  core.py       envelope lifecycle and routing
  pdfs.py       validate, stamp, certificate
  webhooks.py   signing, retries, delivery log
  security.py   scrypt passwords, key hashing, sessions, SSRF guard
  sdk.py        Python client + verify_signature
```

## Hosting

| Where | How |
|---|---|
| Render | New → Blueprint → this repo (`render.yaml`). Needs the starter plan with the persistent disk. After the first deploy set `HUBSIGN_BASE_URL` to the service URL |
| Any Docker host | `docker compose up -d`, or `docker pull ghcr.io/roryewing/hubsign:latest` with a volume on `/data` |

Put it behind HTTPS. Session cookies become `Secure` automatically when `HUBSIGN_BASE_URL` starts with `https`.
Back up the `/data` directory: it holds the database and every document.

## Security notes

- Passwords: scrypt. API keys: 192-bit random, only the SHA-256 is stored. Keys cannot create other keys.
- Signer links are 256-bit random tokens, sent with `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
- Uploads must be unencrypted PDFs, size-capped; signatures must be real PNG data URLs. The signed date is always set server-side.
- Webhook URLs are checked against private, loopback and link-local ranges at registration and again at every delivery (SSRF guard); redirects are not followed.
- User-provided text is escaped in the certificate and in the UI. Login attempts are throttled per email and IP.

## Limits (read before relying on it)

- **Identity** is proven by possession of an emailed or shared link only. No ID check, SMS, or access codes yet.
- **Legal weight.** The consent step, audit trail, document hash and certificate are the ingredients of an ESIGN/UETA
  e-signature, but this is not a trust service. It does not produce PAdES/cryptographic seals or eIDAS advanced or
  qualified signatures. Have counsel confirm it suits a given contract type.
- Single node (SQLite, local disk). One signer at a time is serialised by an in-process lock.
- No rate limiting on the API, no per-organisation accounts or roles, no templates, no bulk send.
- Source pages with `/Rotate` are not handled by the stamper.

## Roadmap

Templates and bulk send · organisations and roles · access codes and SMS verification · cryptographic PDF sealing ·
rate limits · Postgres and object storage · reminders and expiry · branding per account · field resize and drag in the composer.

## Development

```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run pytest -q
```

## License

MIT
