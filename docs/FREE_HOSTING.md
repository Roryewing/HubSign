# Running HubSign for free

Everything here costs nothing: Render's free web service, Neon's free PostgreSQL, SendGrid's free tier (100 emails a day),
GitHub Actions on a public repo, a free timestamp authority, and a self-signed seal. The trade-offs are real, so read them.

| Piece | Free choice | Limit that matters |
|---|---|---|
| Server | Render free web service, public `https://<name>.onrender.com` | Sleeps after 15 idle minutes (cold start ~30-50 s). 750 instance hours a month **across the whole Render workspace** |
| Database and PDFs | Neon free PostgreSQL, documents stored in it (`HUBSIGN_DOCUMENTS_IN_DATABASE=true`) | 0.5 GB. A signed PDF is typically 50-500 KB, so thousands of envelopes |
| Email | SendGrid free tier (the account ServiceHub already uses) | 100 emails a day |
| Timestamps | `HUBSIGN_TSA_URL=http://timestamp.digicert.com` | Third-party service, no guarantee |
| Seal certificate | Self-signed (generated) | Acrobat will not show a trusted signer. A trusted certificate is not free |

## Setup

1. Neon: create a project (region close to Render, e.g. AWS us-east-2). Copy the connection string.
2. Render: new web service from this repo, runtime Docker, plan **Free**, no disk. Environment:
   - `HUBSIGN_DATABASE_URL` the Neon string, `HUBSIGN_DOCUMENTS_IN_DATABASE=true`
   - `HUBSIGN_BASE_URL` the service's public address, `HUBSIGN_TRUST_PROXY_HOPS=1`
   - `HUBSIGN_SECRET` a long random string (it signs sessions and one-time codes; keep it stable)
   - `HUBSIGN_FIRST_USER_EMAIL` your email, `HUBSIGN_ALLOW_SIGNUP=false`
   - `HUBSIGN_SENDGRID_API_KEY`, `HUBSIGN_MAIL_FROM`, `HUBSIGN_MAIL_FROM_NAME`
   - `HUBSIGN_TSA_URL=http://timestamp.digicert.com`
3. Sign up with the reserved email, then create a key and webhook as the ServiceHub runbook says.
4. Keep it awake in working hours: set the repository variable `HUBSIGN_URL` to the public address. The
   `keepalive` workflow then pings every 10 minutes on weekdays.

## What to watch

- **The 750-hour pool is shared.** Keeping HubSign awake around the clock uses about 720 hours and would starve any other
  free service on the same Render workspace, which then stops until the month turns. The keepalive covers weekday working
  hours only (about 260 hours) for that reason. Do not widen it without counting.
- **Asleep means no background work.** Webhook retries and bulk batches run while the server is awake; a request wakes it
  and pending work resumes. A signing link opened at night works after the cold start.
- **GitHub pauses scheduled workflows** on a repository with no activity for 60 days. Re-enable it from the Actions tab.
- **Neon's free database is not backed up for you beyond a short restore window.** Export it now and then
  (`pg_dump`) if the documents matter.
- None of this changes the trust limits in [TRUST.md](TRUST.md): free means a self-signed seal.
