"""Database bootstrap and unit of work."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from vaultpy.application.interfaces import UnitOfWork
from vaultpy.infrastructure.models import Base
from vaultpy.infrastructure.repositories import (
    SqlAlchemyAuditLogRepository,
    SqlAlchemySecretRepository,
    SqlAlchemyVaultConfigRepository,
)


class Database:
    """Thin wrapper around the SQLAlchemy engine and session factory."""

    def __init__(self, database_url: str) -> None:
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self._engine = create_engine(database_url, future=True, connect_args=connect_args)
        self._session_factory = sessionmaker(
            bind=self._engine, autoflush=False, autocommit=False, expire_on_commit=False
        )

    def init(self) -> None:
        """Create database tables for the MVP."""
        Base.metadata.create_all(self._engine)

    def session(self) -> Session:
        """Open a database session."""
        return self._session_factory()


class SqlAlchemyUnitOfWork(UnitOfWork):
    """Unit of work backed by a SQLAlchemy session."""

    def __init__(self, database: Database) -> None:
        self._database = database
        self._session: Session | None = None

    def __enter__(self) -> SqlAlchemyUnitOfWork:
        self._session = self._database.session()
        self.configs = SqlAlchemyVaultConfigRepository(self._session)
        self.secrets = SqlAlchemySecretRepository(self._session)
        self.audits = SqlAlchemyAuditLogRepository(self._session)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._session is None:
            return
        if exc is None:
            self._session.commit()
        else:
            self._session.rollback()
        self._session.close()

    def commit(self) -> None:
        if self._session is not None:
            self._session.commit()

    def rollback(self) -> None:
        if self._session is not None:
            self._session.rollback()
