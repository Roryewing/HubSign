# Trust, verification and what HubSign does not claim

A bank, insurer or court asks three questions of a signed document. This page says how HubSign answers each, what a
reviewer can check themselves, and where the limits are. Read it before telling anyone HubSign output is equivalent
to a regulated provider's.

## 1. Has the file been changed since it was signed?

Every completed PDF carries a **PAdES certification signature** (ETSI EN 319 142, signature type B-B, or B-T when a
timestamp authority is configured). It covers the whole file and forbids any later change. This is an open standard, so
anyone can check it without HubSign:

| Check | How |
|---|---|
| Adobe Acrobat | Open the PDF. The signature panel shows the seal and warns if the file was modified |
| Command line | `pdfsig signed.pdf` (poppler-utils), or pyHanko / EU DSS |
| HubSign | Drop the file on `/verify`, or `POST /v1/verify` with the PDF as the body. No account needed |
| Hash | The SHA-256 of the original document is printed in the certificate of completion; recompute with `sha256sum` |

A one-bit change, a re-save in another PDF tool, or an appended page all make the seal fail. The test suite checks
each of these.

## 2. Who signed, when, and how sure are we?

The **certificate of completion** is the last page of every signed PDF. It lists each party's name, email, role,
**identity check used** (link only, access code, SMS code or email code, with the time it was passed), IP address,
signing time, the full audit trail, and the document hash. The same events are available through the API.

Identity strength, honestly:

| Method | What it shows |
|---|---|
| Link only | Whoever held the emailed link. Weakest. Fine for low-risk documents |
| Access code | The person also knew a code the sender gave them by another channel |
| Email code | The person controlled the mailbox at signing time |
| SMS code | The person controlled the phone number at signing time |

Not provided: government ID checks, liveness, bank-based identity, qualified certificates held by the signer.
Where a contract needs those, use a provider that offers them.

## 3. Does the seal itself have a recognised issuer?

This is the gap that matters for outside recognition, and code cannot close it.

* By default HubSign generates a **self-signed** seal certificate. The seal proves the file is unchanged since HubSign
  sealed it, but Acrobat will say the signer is unknown until the certificate is added as a trusted identity. It is
  downloadable at `/.well-known/hubsign-seal.pem` and its fingerprint at `/v1/seal`.
* To get a **green tick without extra steps**, buy a document-signing certificate from a certificate authority on
  Adobe's Approved Trust List (AATL), then set `HUBSIGN_SEAL_CERT_FILE`, `HUBSIGN_SEAL_KEY_FILE` and, if you have
  intermediates, `HUBSIGN_SEAL_CHAIN_FILE`. Ask the CA how the private key is delivered: many issue document-signing
  certificates only with the key on a hardware token or HSM. HubSign today reads a PEM key from disk, so such a
  certificate would need an HSM or cloud key-management integration, which is on the roadmap and not built.
* Set `HUBSIGN_TSA_URL` to an RFC 3161 timestamp authority (for example `http://timestamp.digicert.com`). Then the time
  of sealing is vouched for by a third party instead of this server's clock. The verifier reports whether the
  timestamp is present and valid.

## What the platform seal is, and is not

The seal is applied by HubSign, the service. It protects the **integrity of the finished document**. The individual
signers' signatures are electronic signatures in the ESIGN / UETA sense (intent, consent, association with the record,
retention), evidenced by the audit trail. They are not signatures made with a key the signer holds, so HubSign does not
produce eIDAS **advanced** or **qualified** electronic signatures, and HubSign is not a qualified trust service provider.
Where a law or counterparty demands those, HubSign is not the right tool.

## Evidence to keep

Keep the signed PDF (it contains the certificate), the envelope's events from `GET /v1/envelopes/{id}/events`, and your
webhook delivery log. Back up the database and document store. Ask your own counsel whether this level of evidence
suits a given contract type and jurisdiction. This document is engineering information, not legal advice.
