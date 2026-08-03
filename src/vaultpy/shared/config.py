"""Application settings."""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_prefix="VAULTPY_", env_file=".env", extra="ignore")

    app_name: str = "VaultPy"
    host: str = "127.0.0.1"
    port: int = 8000
    api_prefix: str = "/api/v1"
    database_url: str = f"sqlite:///{(Path.cwd() / 'vaultpy.db').as_posix()}"
    jwt_secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 30
    refresh_token_minutes: int = 240
    session_ttl_minutes: int = 240
    pbkdf2_iterations: int = 390_000
    ui_storage_secret: str = Field(default_factory=lambda: secrets.token_urlsafe(32))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
