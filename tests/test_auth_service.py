"""Tests for authentication service behaviors."""

from __future__ import annotations

from pathlib import Path

import pytest

from vaultpy.application.dto import LoginRequest, SetupRequest
from vaultpy.presentation.dependencies import get_container
from vaultpy.shared.config import get_settings


def test_logout_accepts_expired_access_token(
    master_password: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Logout should still revoke the session when the access token is expired."""
    monkeypatch.setenv("VAULTPY_DATABASE_URL", f"sqlite:///{(tmp_path / 'logout-expired.db').as_posix()}")
    monkeypatch.setenv("VAULTPY_JWT_SECRET_KEY", "logout-test-secret-with-32-bytes!")
    monkeypatch.setenv("VAULTPY_UI_STORAGE_SECRET", "logout-test-ui-storage-secret")
    monkeypatch.setenv("VAULTPY_ACCESS_TOKEN_MINUTES", "-1")

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

    container.auth_service.logout(tokens.access_token, "test-local")
