"""Shared test fixtures."""

from __future__ import annotations

import os
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def client(tmp_path_factory: pytest.TempPathFactory) -> Generator[TestClient, None, None]:
    """Build a fully isolated API client with a temporary SQLite database."""
    db_path = tmp_path_factory.mktemp("vaultpy") / "vaultpy-test.db"
    os.environ["VAULTPY_DATABASE_URL"] = f"sqlite:///{db_path.as_posix()}"
    os.environ["VAULTPY_JWT_SECRET_KEY"] = "test-jwt-secret-with-32-bytes-length!"
    os.environ["VAULTPY_UI_STORAGE_SECRET"] = "test-ui-storage-secret"

    from vaultpy.presentation.dependencies import get_container
    from vaultpy.shared.config import get_settings

    get_settings.cache_clear()
    get_container.cache_clear()

    from vaultpy.presentation.app import create_app

    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def master_password() -> str:
    """Return a valid master password for tests."""
    return "VaultMaster#2026"
