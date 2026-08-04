"""Tests for infrastructure helpers and utility behavior."""

from __future__ import annotations

from types import SimpleNamespace

from loguru import logger

from vaultpy.infrastructure.database import Database, SqlAlchemyUnitOfWork
from vaultpy.presentation.api import get_client_ip
from vaultpy.shared.logging import configure_logging


class _DummySession:
    def __init__(self) -> None:
        self.commit_calls = 0
        self.rollback_calls = 0
        self.close_calls = 0

    def commit(self) -> None:
        self.commit_calls += 1

    def rollback(self) -> None:
        self.rollback_calls += 1

    def close(self) -> None:
        self.close_calls += 1


def test_sqlalchemy_unit_of_work_commits_and_rolls_back(tmp_path) -> None:
    """The unit of work should commit on success and roll back on failure."""
    database = Database(f"sqlite:///{(tmp_path / 'uow.db').as_posix()}")

    database.session().close()

    empty_uow = SqlAlchemyUnitOfWork(database)
    empty_uow.commit()
    empty_uow.rollback()
    empty_uow.__exit__(None, None, None)

    uow = SqlAlchemyUnitOfWork(database)
    dummy_session = _DummySession()
    uow._session = dummy_session
    uow.commit()
    uow.rollback()
    uow.__exit__(None, None, None)

    failing_uow = SqlAlchemyUnitOfWork(database)
    failing_session = _DummySession()
    failing_uow._session = failing_session
    failing_uow.__exit__(RuntimeError, RuntimeError("boom"), None)

    assert dummy_session.commit_calls == 2
    assert dummy_session.rollback_calls == 1
    assert dummy_session.close_calls == 1
    assert failing_session.rollback_calls == 1
    assert failing_session.close_calls == 1


def test_configure_logging_is_idempotent() -> None:
    """Logging should be configured once and subsequent calls should be no-ops."""
    logger.remove()

    configure_logging()
    first_handler_count = len(logger._core.handlers)  # type: ignore[attr-defined]

    configure_logging()
    second_handler_count = len(logger._core.handlers)  # type: ignore[attr-defined]

    assert first_handler_count == 1
    assert second_handler_count == 1

    logger.remove()


def test_get_client_ip_uses_request_client_and_fallback() -> None:
    """Client IP extraction should use the request client when available."""
    assert get_client_ip(SimpleNamespace(client=SimpleNamespace(host="10.0.0.1"))) == "10.0.0.1"
    assert get_client_ip(SimpleNamespace(client=None)) == "local"
