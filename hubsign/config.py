"""Settings from HUBSIGN_* environment variables."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HUBSIGN_", env_file=".env", extra="ignore")
    data_dir: Path = Path("data")
    base_url: str = "http://localhost:8000"  # used to build signing links
    secret: str = ""  # signs session cookies; generated into data_dir/secret when blank
    allow_signup: bool = True  # the very first account is always allowed
    allow_private_webhooks: bool = False  # true only for local development
    webhooks_inline: bool = False  # tests: deliver synchronously
    webhook_retry_delays: list[float] = [5, 60, 600]  # seconds between attempts after a failure
    max_doc_mb: int = 10
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
