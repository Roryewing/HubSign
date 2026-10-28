"""Settings from HUBSIGN_* environment variables."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HUBSIGN_", env_file=".env", extra="ignore")
    data_dir: Path = Path("data")
    base_url: str = "http://localhost:8000"  # used to build signing links
    secret: str = ""  # signs session cookies and OTP hashes; generated into data_dir/secret when blank
    first_user_email: str = ""  # when set, only this address may create the very first account
    allow_signup: bool = True  # the very first account is always allowed
    allow_private_webhooks: bool = False  # true only for local development
    webhooks_inline: bool = False  # tests: deliver synchronously, no background worker
    webhook_retry_delays: list[float] = [5, 60, 600]  # seconds between attempts after a failure
    max_doc_mb: int = 10
    # storage: SQLite file by default; set a Postgres URL to run more than one node
    database_url: str = ""  # postgresql://user:pass@host/db
    documents_in_database: bool = (
        False  # keep PDFs in the database instead of on disk (hosts without a persistent disk)
    )
    s3_bucket: str = ""  # documents go to S3-compatible storage when set (AWS creds from the usual env vars)
    s3_prefix: str = ""
    s3_endpoint_url: str = ""  # Cloudflare R2, MinIO, ...
    s3_region: str = ""
    # proxies: how many trusted reverse proxies sit in front (Render, nginx = 1). 0 = use the socket address.
    trust_proxy_hops: int = 0
    # rate limits (requests per minute); 0 disables
    rate_api_per_min: int = 600
    rate_sign_per_min: int = 120
    rate_auth_per_min: int = 30
    rate_public_per_min: int = 20
    # signer identity
    twilio_sid: str = ""
    twilio_token: str = ""
    twilio_from: str = ""
    # cryptographic sealing: bring your own document-signing certificate, or leave blank for a self-signed one
    seal_cert_file: str = ""
    seal_key_file: str = ""
    seal_chain_file: str = ""  # intermediates, PEM
    seal_key_password: str = ""
    tsa_url: str = ""  # RFC 3161 timestamp authority, e.g. http://timestamp.digicert.com
    bulk_max_rows: int = 500
    sendgrid_api_key: str = ""  # email through SendGrid's API; takes precedence over SMTP
    mail_from: str = ""  # a sender address verified with your email provider; falls back to smtp_from
    mail_from_name: str = "HubSign"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
