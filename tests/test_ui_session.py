"""Tests for UI session recovery behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from vaultpy.application.dto import LoginRequest, SetupRequest
from vaultpy.presentation.dependencies import get_container
from vaultpy.presentation.ui import (
    collect_secret_fields,
    resolve_authenticated_context,
    secret_field_rows_from_mapping,
)
from vaultpy.shared.config import get_settings


def test_resolve_authenticated_context_refreshes_expired_access_token(
    master_password: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Expired UI access tokens should be refreshed instead of leaving stale storage behind."""
    monkeypatch.setenv("VAULTPY_DATABASE_URL", f"sqlite:///{(tmp_path / 'ui-refresh.db').as_posix()}")
    monkeypatch.setenv("VAULTPY_JWT_SECRET_KEY", "ui-refresh-secret-with-32-bytes!")
    monkeypatch.setenv("VAULTPY_UI_STORAGE_SECRET", "ui-refresh-ui-storage-secret")
    monkeypatch.setenv("VAULTPY_ACCESS_TOKEN_MINUTES", "30")
    monkeypatch.setenv("VAULTPY_REFRESH_TOKEN_MINUTES", "60")

    get_settings.cache_clear()
    get_container.cache_clear()
    container = get_container()
    container.init_database()
    container.auth_service.bootstrap(
        SetupRequest(master_password=master_password),
        "test-local",
    )
    tokens = container.auth_service.login(
        LoginRequest(master_password=master_password),
        "test-local",
    )
    payload = container.jwt_service.decode_token(
        tokens.refresh_token,
        expected_type="refresh",
    )
    original_access_minutes = container.jwt_service._access_minutes
    container.jwt_service._access_minutes = -1
    expired_access_token = container.jwt_service.create_access_token(str(payload["sid"]))
    container.jwt_service._access_minutes = original_access_minutes

    storage: dict[str, str] = {
        "access_token": expired_access_token,
        "refresh_token": tokens.refresh_token,
    }

    context = resolve_authenticated_context(storage, container.auth_service)

    assert context is not None
    assert storage["access_token"] != expired_access_token


def test_resolve_authenticated_context_clears_invalid_storage(
    master_password: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Invalid or unrefreshable UI tokens should be removed to avoid redirect loops."""
    monkeypatch.setenv("VAULTPY_DATABASE_URL", f"sqlite:///{(tmp_path / 'ui-clear.db').as_posix()}")
    monkeypatch.setenv("VAULTPY_JWT_SECRET_KEY", "ui-clear-secret-with-32-bytes!!")
    monkeypatch.setenv("VAULTPY_UI_STORAGE_SECRET", "ui-clear-ui-storage-secret")

    get_settings.cache_clear()
    get_container.cache_clear()
    container = get_container()
    container.init_database()
    container.auth_service.bootstrap(
        SetupRequest(master_password=master_password),
        "test-local",
    )

    storage: dict[str, str] = {
        "access_token": "invalid-token",
        "refresh_token": "invalid-refresh-token",
    }

    context = resolve_authenticated_context(storage, container.auth_service)

    assert context is None
    assert storage == {}


def test_collect_secret_fields_ignores_incomplete_rows() -> None:
    """Dashboard key/value rows should ignore incomplete entries."""
    fields = collect_secret_fields(
        [
            {"key": "chave_secret", "value": "xxxxx"},
            {"key": " ", "value": "ignored"},
            {"key": "tenant", "value": "fluid-prod"},
            {"key": "id", "value": " "},
        ]
    )

    assert fields == {
        "chave_secret": "xxxxx",
        "tenant": "fluid-prod",
    }


def test_secret_field_rows_from_mapping_preserves_pairs() -> None:
    """Stored structured fields should be converted into editable rows."""
    rows = secret_field_rows_from_mapping(
        {
            "chave_secret": "xxxxx",
            "intarid": "xxxxxxx",
        }
    )

    assert rows == [
        {"key": "chave_secret", "value": "xxxxx"},
        {"key": "intarid", "value": "xxxxxxx"},
    ]
