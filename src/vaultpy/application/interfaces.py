"""Interfaces and repository contracts."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from vaultpy.domain.entities import AuditLog, Secret, VaultConfig


class VaultConfigRepository(Protocol):
    """Persistence contract for vault configuration."""

    def get(self) -> VaultConfig | None:
        """Return the single vault configuration, if present."""

    def save(self, config: VaultConfig) -> VaultConfig:
        """Persist the vault configuration."""


class SecretRepository(Protocol):
    """Persistence contract for secrets."""

    def create(self, secret: Secret) -> Secret:
        """Create a secret."""

    def get_by_id(self, secret_id: int, *, include_deleted: bool = False) -> Secret | None:
        """Retrieve a secret by identifier."""

    def get_by_name(self, name: str, *, include_deleted: bool = False) -> Secret | None:
        """Retrieve a secret by name."""

    def list_active(self) -> list[Secret]:
        """List all non-deleted secrets."""

    def search(self, query: str) -> list[Secret]:
        """Search secrets by metadata."""

    def save(self, secret: Secret) -> Secret:
        """Persist changes to a secret."""

    def count_active(self) -> int:
        """Return the number of active secrets."""

    def category_counts(self) -> dict[str, int]:
        """Return counts grouped by category."""

    def recent_updated(self, limit: int) -> list[Secret]:
        """Return the most recently updated secrets."""


class AuditLogRepository(Protocol):
    """Persistence contract for audit logs."""

    def create(self, audit_log: AuditLog) -> AuditLog:
        """Create an audit log entry."""

    def list_recent(self, limit: int) -> list[AuditLog]:
        """Return the most recent audit entries."""


class UnitOfWork(Protocol):
    """Unit of work abstraction."""

    configs: VaultConfigRepository
    secrets: SecretRepository
    audits: AuditLogRepository

    def __enter__(self) -> UnitOfWork:
        """Enter the unit of work context."""

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Exit the unit of work context."""

    def commit(self) -> None:
        """Commit the current transaction."""

    def rollback(self) -> None:
        """Rollback the current transaction."""


UnitOfWorkFactory = Callable[[], UnitOfWork]
