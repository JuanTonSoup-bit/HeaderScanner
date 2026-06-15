"""Centralized, environment-driven configuration (12-factor)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from the environment or a local .env file."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Scanning behavior
    allow_private_targets: bool = False
    request_timeout: float = 10.0
    max_redirects: int = 5
    max_response_bytes: int = 2_000_000
    user_agent: str = (
        "SecurityHeaderScanner/1.0 (+https://github.com/JuanTonSoup-bit/security-header-scanner)"
    )


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (used as a FastAPI dependency)."""
    return Settings()
