"""Tests for application service edge cases and helper behavior."""

from __future__ import annotations

import json

import pytest

from vaultpy.application.dto import LoginRequest, PasswordGenerateRequest, SecretUpdateRequest, SetupRequest
from vaultpy.domain.exceptions import InvalidMasterPasswordError, SecretNotFoundError, ValidationError


def test_auth_service_rejects_login_before_bootstrap_and_duplicate_bootstrap(
    container,
    master_password: str,
) -> None:
    """Authentication should enforce bootstrap order."""
    with pytest.raises(InvalidMasterPasswordError):
        container.auth_service.login(LoginRequest(master_password=master_password), "test-local")

    container.auth_service.bootstrap(SetupRequest(master_password=master_password), "test-local")

    with pytest.raises(ValidationError):
        container.auth_service.bootstrap(SetupRequest(master_password=master_password), "test-local")


def test_secret_service_reports_missing_secret_paths(container, master_password: str) -> None:
    """Missing secrets should fail consistently across the service surface."""
    container.auth_service.bootstrap(SetupRequest(master_password=master_password), "test-local")
    tokens = container.auth_service.login(LoginRequest(master_password=master_password), "test-local")
    context = container.auth_service.context_from_token(tokens.access_token)

    with pytest.raises(SecretNotFoundError):
        container.secret_service.get_secret(999)

    with pytest.raises(SecretNotFoundError):
        container.secret_service.update_secret(context, 999, SecretUpdateRequest(), "test-local")

    with pytest.raises(SecretNotFoundError):
        container.secret_service.delete_secret(context, 999, "test-local")

    with pytest.raises(SecretNotFoundError):
        container.secret_service.get_secret_value(context, 999, "test-local")

    with pytest.raises(SecretNotFoundError):
        container.secret_service.get_secret_value_by_name(context, "missing-secret", "test-local")


def test_secret_service_helper_methods_cover_edge_cases(container, master_password: str) -> None:
    """Secret serialization helpers should trim and reject invalid payloads."""
    container.auth_service.bootstrap(SetupRequest(master_password=master_password), "test-local")
    tokens = container.auth_service.login(LoginRequest(master_password=master_password), "test-local")
    context = container.auth_service.context_from_token(tokens.access_token)

    with pytest.raises(ValidationError):
        container.secret_service._serialize_secret_content(secret_value=None, secret_fields={})

    plaintext_response = container.secret_service._deserialize_secret_content("example", "plain-text")
    assert plaintext_response.secret_value == "plain-text"
    assert plaintext_response.secret_fields == {}

    array_response = container.secret_service._deserialize_secret_content(
        "example",
        json.dumps(["not", "an", "object"]),
    )
    assert array_response.secret_value == json.dumps(["not", "an", "object"])
    assert array_response.secret_fields == {}

    structured_response = container.secret_service._deserialize_secret_content(
        "example",
        json.dumps({"secret_value": "  value  ", "secret_fields": "oops"}),
    )
    assert structured_response.secret_value == "value"
    assert structured_response.secret_fields == {}

    generated_password = container.secret_service.generate_password(
        PasswordGenerateRequest(
            length=12,
            include_symbols=False,
            include_numbers=True,
            include_uppercase=False,
            include_lowercase=True,
        )
    )
    assert len(generated_password.password) == 12
    assert any(character.isdigit() for character in generated_password.password)
    assert any(character.islower() for character in generated_password.password)

    assert context.user == "master"
