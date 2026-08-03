"""Application DTOs."""

from __future__ import annotations

import json
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vaultpy.domain.entities import SecretKind


class SetupRequest(BaseModel):
    """Request body for initial master password setup."""

    master_password: str = Field(min_length=12)


class LoginRequest(BaseModel):
    """Request body for login."""

    master_password: str = Field(min_length=12)


class RefreshRequest(BaseModel):
    """Request body for token refresh."""

    refresh_token: str = Field(min_length=1)


class TokenPair(BaseModel):
    """JWT pair returned after authentication."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class SecretCreateRequest(BaseModel):
    """Request body for creating a secret."""

    model_config = ConfigDict(use_enum_values=False)

    name: str = Field(min_length=2, max_length=120)
    category: str = Field(min_length=2, max_length=60)
    username: str = Field(default="", max_length=120)
    secret_value: str | None = Field(default=None, min_length=1)
    secret_fields: dict[str, str] = Field(default_factory=dict)
    secret_kind: SecretKind = SecretKind.PASSWORD
    url: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=2000)
    tags: list[str] = Field(default_factory=list)

    @field_validator("tags", mode="before")
    @classmethod
    def normalize_tags(cls, value: object) -> list[str]:
        """Normalize tags from either a list or comma-separated string."""
        if value is None:
            return []
        if isinstance(value, str):
            items = [item.strip() for item in value.split(",")]
            return [item for item in items if item]
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        raise TypeError("tags must be a list or comma-separated string")

    @field_validator("secret_fields", mode="before")
    @classmethod
    def normalize_secret_fields(cls, value: object) -> dict[str, str]:
        """Normalize structured secret fields from JSON or dict input."""
        if value is None or value == "":
            return {}
        if isinstance(value, str):
            parsed = json.loads(value)
            if not isinstance(parsed, dict):
                raise TypeError("secret_fields JSON must be an object")
            value = parsed
        if isinstance(value, dict):
            normalized: dict[str, str] = {}
            for key, item in value.items():
                normalized_key = str(key).strip()
                normalized_value = str(item).strip()
                if normalized_key and normalized_value:
                    normalized[normalized_key] = normalized_value
            return normalized
        raise TypeError("secret_fields must be a dict or JSON object string")

    @model_validator(mode="after")
    def validate_secret_content(self) -> SecretCreateRequest:
        """Ensure at least one encrypted secret value is provided."""
        if not self.secret_value and not self.secret_fields:
            raise ValueError("Provide either secret_value or secret_fields.")
        return self


class SecretUpdateRequest(BaseModel):
    """Request body for updating a secret."""

    model_config = ConfigDict(use_enum_values=False)

    name: str | None = Field(default=None, min_length=2, max_length=120)
    category: str | None = Field(default=None, min_length=2, max_length=60)
    username: str | None = Field(default=None, max_length=120)
    secret_value: str | None = Field(default=None, min_length=1)
    secret_fields: dict[str, str] | None = None
    secret_kind: SecretKind | None = None
    url: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=2000)
    tags: list[str] | None = None

    @field_validator("tags", mode="before")
    @classmethod
    def normalize_tags(cls, value: object) -> list[str] | None:
        """Normalize tags from either a list or comma-separated string."""
        if value is None:
            return None
        if isinstance(value, str):
            items = [item.strip() for item in value.split(",")]
            return [item for item in items if item]
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        raise TypeError("tags must be a list or comma-separated string")

    @field_validator("secret_fields", mode="before")
    @classmethod
    def normalize_secret_fields(cls, value: object) -> dict[str, str] | None:
        """Normalize structured secret fields from JSON or dict input."""
        if value is None:
            return None
        if value == "":
            return {}
        if isinstance(value, str):
            parsed = json.loads(value)
            if not isinstance(parsed, dict):
                raise TypeError("secret_fields JSON must be an object")
            value = parsed
        if isinstance(value, dict):
            normalized: dict[str, str] = {}
            for key, item in value.items():
                normalized_key = str(key).strip()
                normalized_value = str(item).strip()
                if normalized_key and normalized_value:
                    normalized[normalized_key] = normalized_value
            return normalized
        raise TypeError("secret_fields must be a dict or JSON object string")


class SecretResponse(BaseModel):
    """Secret metadata returned by the API and UI."""

    id: int
    name: str
    category: str
    username: str
    secret_kind: SecretKind
    url: str | None
    notes: str | None
    tags: list[str]
    created_at: datetime
    updated_at: datetime
    last_access_at: datetime | None


class SecretValueResponse(BaseModel):
    """Decrypted secret value."""

    secret_value: str | None
    secret_fields: dict[str, str] = Field(default_factory=dict)


class DashboardResponse(BaseModel):
    """Dashboard snapshot."""

    total_secrets: int
    categories: dict[str, int]
    recent_updates: list[SecretResponse]
    last_access_at: datetime | None


class AuditLogResponse(BaseModel):
    """Audit log entry response."""

    id: int
    user: str
    action: str
    ip_address: str
    details: str
    created_at: datetime


class PasswordGenerateRequest(BaseModel):
    """Password generation request."""

    length: int = Field(default=24, ge=12, le=128)
    include_symbols: bool = True
    include_numbers: bool = True
    include_uppercase: bool = True
    include_lowercase: bool = True


class PasswordGenerateResponse(BaseModel):
    """Password generation response."""

    password: str


class StatusResponse(BaseModel):
    """Simple health and bootstrap status response."""

    bootstrapped: bool
    categories: list[str]
