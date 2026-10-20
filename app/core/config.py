"""
GHOSTSENTINEL Ω — Application Configuration
Loads settings from environment variables / .env file.
Secrets must never be committed to version control.
"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field


BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    # ── Application ──────────────────────────────────────────────────────────
    app_name: str = "GHOSTSENTINEL Ω"
    app_version: str = "0.1.0"
    license_tier: str = Field(default="community", env="LICENSE_TIER")
    debug: bool = Field(default=False, env="DEBUG")

    # ── Server ───────────────────────────────────────────────────────────────
    host: str = Field(default="127.0.0.1", env="HOST")
    port: int = Field(default=8000, env="PORT")

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = Field(
        default=f"sqlite:///{BASE_DIR / 'ghostsentinel.db'}",
        env="DATABASE_URL",
    )

    # ── Security ─────────────────────────────────────────────────────────────
    secret_key: str = Field(default="CHANGE_ME_IN_DOT_ENV_32chars_min", env="SECRET_KEY")
    access_token_expire_minutes: int = Field(default=60, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    algorithm: str = "HS256"

    # ── LAN access (disabled by default) ─────────────────────────────────────
    allow_lan_access: bool = Field(default=False, env="ALLOW_LAN_ACCESS")

    # ── Scan limits ───────────────────────────────────────────────────────────
    scan_timeout_seconds: int = Field(default=60, env="SCAN_TIMEOUT_SECONDS")
    device_scan_rate_limit: float = Field(default=0.1, env="DEVICE_SCAN_RATE_LIMIT")  # seconds between probes

    # ── Reports output directory ──────────────────────────────────────────────
    reports_dir: Path = Field(default=BASE_DIR / "reports_output", env="REPORTS_DIR")

    class Config:
        env_file = BASE_DIR / ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
