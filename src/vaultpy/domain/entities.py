"""Domain entities for VaultPy."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class SecretKind(StrEnum):
    """Supported encrypted secret kinds."""

    PASSWORD = "password"
    TOKEN = "token"
    SECRET_KEY = "secret_key"
    CONNECTION_STRING = "connection_string"


DEFAULT_CATEGORIES = (
    "Database",
    "API",
    "Git",
    "Cloud",
    "RPA",
    "Infrastructure",
    "Email",
    "Other",
)


@dataclass(slots=True)
class VaultConfig:
    """Master vault configuration stored in the database."""

    id: int
    password_hash: str
    password_salt: str
    key_encryption_salt: str
    encrypted_data_key: str
    pbkdf2_iterations: int
    created_at: datetime
    updated_at: datetime
    last_access_at: datetime | None = None
    last_login_at: datetime | None = None


@dataclass(slots=True)
class Secret:
    """Secret aggregate root."""

    id: int | None
    name: str
    category: str
    username: str
    url: str | None
    notes: str | None
    tags: list[str]
    secret_kind: SecretKind
    secret_value_encrypted: str
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None
    last_access_at: datetime | None = None


@dataclass(slots=True)
class AuditLog:
    """Audit log entry."""

    id: int | None
    user: str
    action: str
    ip_address: str
    details: str
    created_at: datetime


@dataclass(slots=True)
class AuthenticatedContext:
    """Authenticated session context used by application services."""

    session_id: str
    data_key: bytes
    user: str = "master"


@dataclass(slots=True)
class DashboardSnapshot:
    """Dashboard data for the web interface and API."""

    total_secrets: int
    category_counts: dict[str, int]
    recent_updates: list[Secret] = field(default_factory=list)
    last_access_at: datetime | None = None
