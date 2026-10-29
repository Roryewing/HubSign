# HubSign

E-signature platform with a developer API: upload a PDF, place fields, route it to signers in order or in parallel,
verify who they are, collect signatures with a full audit trail, and get a cryptographically sealed PDF with a certificate
of completion. Everything the web app does is available over a documented REST API with signed webhooks and a sandbox.

> **Status: v0.3.** Works end to end, tested on SQLite and PostgreSQL. It is not a regulated trust service: read
> [Limits](#limits-read-before-relying-on-it) and [docs/TRUST.md](docs/TRUST.md) before relying on it for high-stakes contracts.

## What it does

| Area | Capability |
|---|---|
| Sending | PDF upload, recipients (signer / gets a copy), routing order, sequential or parallel signing, subject and message, metadata echoed in webhooks |
| Fields | Signature, initials, date signed, name, email (all server-filled, never client-supplied), text, checkbox. Positioned as fractions of the page. Drag from a palette onto the page, or click to place |
| Templates | Save a document with its roles, fields and identity checks, then send it to real people in two clicks or one API call |
| Bulk send | Up to 500 envelopes per batch from a template, by CSV in the app or `POST /v1/templates/{id}/bulk`. Runs in the background, resumes after a crash, reports per-row errors |
| Identity checks | Per recipient: link only, **access code**, **SMS code** (Twilio) or **email code**. Failed attempts are rate limited, locked out and audited |
| Signing | Mobile-friendly signing page: consent, Start/Next guidance, "Adopt Your Signature" (four script styles or freehand), decline with reason |
| Sealing | Every completed PDF is **cryptographically sealed (PAdES)** so any later change is detectable. Optional RFC 3161 trusted timestamp. Public verifier at `/verify` and `POST /v1/verify` |
| Certificate | Last page of the PDF: parties, identity check used and when, IPs, times, full audit trail, document hash |
| Organisations | Workspaces with **owner / admin / sender / viewer** roles, invitations, several organisations per person. Documents, templates, keys and webhooks belong to the organisation |
| Scale | **PostgreSQL** and S3-compatible storage for several nodes. Every state change is a conditional update, so two servers cannot double-sign or double-finalize. Webhooks and bulk jobs are database-backed |
| Protection | Shared rate limits (per key, per IP, per recipient), request size caps, SSRF-guarded webhooks, scrypt passwords, hashed keys |
| Dashboard | Home, Agreements with folders, search and bulk actions, progress tracker, history, document preview, four-stage composer, Templates, Team, Developer |

### Developer tools

| Tool | Detail |
|---|---|
| REST API | `/v1`, OpenAPI at `/docs` and `/redoc`, bearer-key auth |
| API keys | `hs_test_…` and `hs_live_…`, each **viewer, sender or admin**, shown once, stored hashed, revocable, last-used tracking. Leaving the organisation revokes the keys you made |
| Sandbox | Separate data for test keys. Sandbox PDFs carry a watermark; one-time codes are always `000000` and nothing is sent |
| Webhooks | 9 events, per-endpoint subscriptions, HMAC-SHA256 signature with timestamp, retries after 5 s / 1 min / 10 min that survive restarts, delivery log, redeliver, test event |
| Embedded signing | Every active recipient has a `signing_url` in the API response. Mark a recipient `embedded` and no email is sent; give a `return_url` and the signer's browser is sent back to your app afterwards |
| Field placement | By position, or by **anchor text** printed in the PDF (even invisibly): one field per occurrence, with point offsets, the way DocuSign anchor tabs work |
| Several documents | `documents: [...]` in one envelope, one signing session, one sealed PDF. Each document can also be downloaded on its own, sealed as an excerpt |
| Prefilled fields | A text or checkbox field with a `value` is filled in and locked; `label` names a field, and `GET /v1/envelopes/{id}/form_data` returns what signers typed, by label |
| Reassign | `allow_reassign` lets a signer hand their part to someone else; the old link dies, the audit trail records it |
| Email | SendGrid API (or SMTP), HTML emails, per-envelope `reply_to` and `sender_name` |
| Field detection | `POST /v1/detect-fields`: imports the PDF's own form fields and places fields beside printed Signature / Date / Initials labels, snapped to underlines (ported from DocuSeal; its ML box detector is not) |
| Python SDK | `hubsign.sdk.HubSign`: envelopes, templates, bulk send, verify, webhooks, plus `verify_signature()` for receivers |

## Quick start

```bash
uv sync
uv run hubsign            # http://127.0.0.1:8000, SQLite, files in ./data
```

Open the app, create the first account, go to **Developer → API keys**, then:

```bash
curl -s localhost:8000/v1/envelopes \
  -H "Authorization: Bearer hs_test_…" -H "Content-Type: application/json" \
  -d '{"subject":"NDA","document_base64":"'"$(base64 -w0 nda.pdf)"'",
       "recipients":[{"name":"Ann Lee","email":"ann@example.com",
                      "authentication":{"method":"sms","phone":"+14165550123"}}],
       "fields":[{"recipient":0,"type":"signature","page":1,"x":0.10,"y":0.85}],
       "metadata":{"deal":"D-1042"},"send":true}'
```

Then check any completed file:

```bash
curl -s localhost:8000/v1/verify -H "Content-Type: application/pdf" --data-binary @signed.pdf
```

### Verifying webhooks

Every delivery carries `HubSign-Signature: t=<unix>,v1=<hex>` where `v1 = HMAC-SHA256(secret, "<t>." + raw_body)`.

```python
from hubsign.sdk import verify_signature

verify_signature(secret, request.headers["HubSign-Signature"], raw_body)  # ValueError if invalid or older than 5 min
```

## Architecture

FastAPI, SQLite or PostgreSQL, PDFs on disk or S3. `core.py` is the only place envelope state changes; `api.py` is thin.
A background worker in each process drains webhook deliveries and bulk batches and recovers stalled work, claiming rows
with conditional updates so any number of nodes can run it. The UI is static pages with no build step.

```
hubsign/
  api.py        routes, auth, organisations and roles, rate limiting
  core.py       envelope lifecycle, routing, templates, bulk
  identity.py   access codes, SMS and email one-time codes
  seal.py       PAdES sealing and verification, certificate handling
  pdfs.py       validate, stamp, certificate of completion
  webhooks.py   signing, durable retries, delivery log
  db.py         SQLite and PostgreSQL behind one interface
  storage.py    local disk or S3-compatible
  security.py   scrypt passwords, key hashing, sessions, SSRF guard
  sdk.py        Python client + verify_signature
```

## Hosting

| Setup | How |
|---|---|
| Free | Render free web service + Neon free PostgreSQL with documents in the database. Step by step and the limits: [docs/FREE_HOSTING.md](docs/FREE_HOSTING.md) |
| One node | `docker compose up -d` or the Render blueprint. SQLite file and PDFs on a persistent disk. Back up `/data` |
| Several nodes | Set `HUBSIGN_DATABASE_URL` (PostgreSQL) and `HUBSIGN_S3_BUCKET`. Any node can serve any request. Put a load balancer in front |

**Behind a proxy or load balancer set `HUBSIGN_TRUST_PROXY_HOPS=1`** (the number of proxies in front). Without it every
client looks like one address, which merges rate limits and records the wrong IP in certificates. HubSign logs a
warning if it sees an https base URL with this unset. Use HTTPS; session cookies become `Secure` automatically.

## Configuration

| Variable | Purpose |
|---|---|
| `HUBSIGN_BASE_URL` | Public URL, used for signing links |
| `HUBSIGN_DATABASE_URL` | PostgreSQL URL. Blank = SQLite in the data directory |
| `HUBSIGN_S3_BUCKET`, `_PREFIX`, `_ENDPOINT_URL`, `_REGION` | Documents in S3, R2 or MinIO. Use bucket default encryption |
| `HUBSIGN_TRUST_PROXY_HOPS` | See above |
| `HUBSIGN_SEAL_CERT_FILE`, `_KEY_FILE`, `_CHAIN_FILE`, `_KEY_PASSWORD` | Your document-signing certificate. Blank = self-signed |
| `HUBSIGN_TSA_URL` | RFC 3161 timestamp authority |
| `HUBSIGN_TWILIO_SID`, `_TOKEN`, `_FROM` | Enables SMS codes in live mode |
| `HUBSIGN_SENDGRID_API_KEY`, `HUBSIGN_MAIL_FROM`, `HUBSIGN_MAIL_FROM_NAME` | Email through SendGrid's API. The from address must be verified in SendGrid |
| `HUBSIGN_SMTP_*` | Email through SMTP instead (SendGrid also offers an SMTP relay) |
| `HUBSIGN_RATE_API_PER_MIN` (600), `_SIGN_` (120), `_AUTH_` (30), `_PUBLIC_` (20) | Rate limits per minute, 0 disables |
| `HUBSIGN_ALLOW_SIGNUP` | The first account is always allowed; false closes registration (invitations still work) |

## Security notes

- Passwords: scrypt. API keys: 192-bit random, only the SHA-256 is stored. Access codes: scrypt. One-time codes: keyed hash, 10-minute expiry, 5 tries.
- Signer links are 256-bit tokens, sent with `Referrer-Policy: no-referrer` and `Cache-Control: no-store`. When an identity check is set, documents and the signed copy are refused without the verification cookie, which is scoped to that one link.
- Uploads must be unencrypted PDFs within the size cap, bodies are capped before they are read, signatures must be real PNG data URLs. The signed date, name and email are set by the server.
- Webhook URLs are checked against private, loopback and link-local ranges at registration and at every delivery; redirects are not followed.
- Every state change is a conditional update; concurrent sign, send and void requests cannot both win. Tests run two server instances against one database.

## Limits (read before relying on it)

See [docs/TRUST.md](docs/TRUST.md) for the full discussion.

- **Not a regulated trust service.** The platform seal protects integrity. Signers' signatures are electronic signatures (ESIGN / UETA style), not eIDAS advanced or qualified signatures. No government ID or liveness checks.
- **The default seal certificate is self-signed.** Acrobat shows a green tick only once you bring a certificate from an Adobe-trusted authority. Many such certificates require the key on an HSM, which HubSign cannot use yet.
- The generated seal key sits on disk, unencrypted. Protect the data directory, or supply your own encrypted key.
- Webhook delivery checks the destination address and then connects; a hostile DNS server could in theory change its answer in between (DNS rebinding). Run workers in a network without access to internal services if that matters.
- Rate limiting is shared through the database, which adds a small write per request. For very high volumes put a gateway in front.
- No SSO/SAML or SCIM, no admin-action audit log beyond per-envelope history, no reminders or expiry, no retention policies, one language.
- Source pages with `/Rotate` are not handled by the stamper.
- Schema changes are applied by creating missing tables only. There is no migration tool yet, so plan an upgrade path before holding real data.

## Roadmap

HSM / cloud-KMS signing keys · reminders and expiry · SSO and SCIM · admin audit log · schema migrations · retention
policies · government-ID verification providers · field resize and drag in the composer · localisation.

## Development

```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run pytest -q
```

## License

AGPL-3.0. Field detection (`hubsign/detect.py`) is ported from [DocuSeal](https://github.com/docusealco/docuseal) (AGPL-3.0); per `LICENSE_ADDITIONAL_TERMS` the DocuSeal attribution is retained. Earlier releases were MIT.
