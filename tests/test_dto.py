"""Tests for application DTO normalization and validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from vaultpy.application.dto import SecretCreateRequest, SecretUpdateRequest


def test_secret_create_request_normalizes_tags_and_secret_fields() -> None:
    """Incoming create payloads should accept flexible tag and field formats."""
    request = SecretCreateRequest(
        name="GitLab Production",
        category="Git",
        username="service-user",
        secret_value="  Sup3r$ecret!  ",
        secret_fields='{"tenant": " prod ", "id": 123, "empty": " "}',
        tags="gitlab, production ,,",
        secret_kind="password",
    )

    assert request.tags == ["gitlab", "production"]
    assert request.secret_fields == {"id": "123", "tenant": "prod"}


def test_secret_create_request_requires_secret_content() -> None:
    """A secret must include either a value or structured fields."""
    with pytest.raises(PydanticValidationError):
        SecretCreateRequest(
            name="GitLab Production",
            category="Git",
            username="service-user",
        )


def test_secret_update_request_normalizes_optional_fields() -> None:
    """Update payloads should normalize tags and accept empty structured input."""
    request = SecretUpdateRequest(
        tags=[" production ", "", "ops"],
        secret_fields="",
    )

    assert request.tags == ["production", "ops"]
    assert request.secret_fields == {}
