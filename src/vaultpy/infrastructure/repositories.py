"""Repository implementations backed by SQLAlchemy."""

from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from vaultpy.domain.entities import AuditLog, Secret, SecretKind, VaultConfig
from vaultpy.infrastructure.models import AuditLogModel, SecretModel, VaultConfigModel


class SqlAlchemyVaultConfigRepository:
    """SQLAlchemy implementation of the vault configuration repository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self) -> VaultConfig | None:
        model = self._session.get(VaultConfigModel, 1)
        return self._to_entity(model) if model else None

    def save(self, config: VaultConfig) -> VaultConfig:
        model = self._session.get(VaultConfigModel, config.id)
        if model is None:
            model = VaultConfigModel(id=config.id)
            self._session.add(model)
        model.password_hash = config.password_hash
        model.password_salt = config.password_salt
        model.key_encryption_salt = config.key_encryption_salt
        model.encrypted_data_key = config.encrypted_data_key
        model.pbkdf2_iterations = config.pbkdf2_iterations
        model.created_at = config.created_at
        model.updated_at = config.updated_at
        model.last_access_at = config.last_access_at
        model.last_login_at = config.last_login_at
        self._session.flush()
        return self._to_entity(model)

    @staticmethod
    def _to_entity(model: VaultConfigModel) -> VaultConfig:
        return VaultConfig(
            id=model.id,
            password_hash=model.password_hash,
            password_salt=model.password_salt,
            key_encryption_salt=model.key_encryption_salt,
            encrypted_data_key=model.encrypted_data_key,
            pbkdf2_iterations=model.pbkdf2_iterations,
            created_at=model.created_at,
            updated_at=model.updated_at,
            last_access_at=model.last_access_at,
            last_login_at=model.last_login_at,
        )


class SqlAlchemySecretRepository:
    """SQLAlchemy implementation of the secret repository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, secret: Secret) -> Secret:
        model = SecretModel(
            name=secret.name,
            category=secret.category,
            username=secret.username,
            secret_kind=secret.secret_kind.value,
            secret_value_encrypted=secret.secret_value_encrypted,
            url=secret.url,
            notes=secret.notes,
            tags=self._serialize_tags(secret.tags),
            created_at=secret.created_at,
            updated_at=secret.updated_at,
            deleted_at=secret.deleted_at,
            last_access_at=secret.last_access_at,
        )
        self._session.add(model)
        self._session.flush()
        return self._to_entity(model)

    def get_by_id(self, secret_id: int, *, include_deleted: bool = False) -> Secret | None:
        model = self._session.get(SecretModel, secret_id)
        if model is None:
            return None
        if not include_deleted and model.deleted_at is not None:
            return None
        return self._to_entity(model)

    def get_by_name(self, name: str, *, include_deleted: bool = False) -> Secret | None:
        stmt = select(SecretModel).where(SecretModel.name == name.strip()).order_by(SecretModel.updated_at.desc())
        if not include_deleted:
            stmt = stmt.where(SecretModel.deleted_at.is_(None))
        model = self._session.scalars(stmt).first()
        return self._to_entity(model) if model else None

    def list_active(self) -> list[Secret]:
        stmt = select(SecretModel).where(SecretModel.deleted_at.is_(None)).order_by(SecretModel.updated_at.desc())
        models = self._session.scalars(stmt).all()
        return [self._to_entity(model) for model in models]

    def search(self, query: str) -> list[Secret]:
        pattern = f"%{query.strip()}%"
        stmt = (
            select(SecretModel)
            .where(SecretModel.deleted_at.is_(None))
            .where(
                or_(
                    SecretModel.name.ilike(pattern),
                    SecretModel.category.ilike(pattern),
                    SecretModel.username.ilike(pattern),
                    SecretModel.tags.ilike(pattern),
                )
            )
            .order_by(SecretModel.updated_at.desc())
        )
        models = self._session.scalars(stmt).all()
        return [self._to_entity(model) for model in models]

    def save(self, secret: Secret) -> Secret:
        model = self._session.get(SecretModel, secret.id)
        if model is None:
            raise ValueError(f"Secret {secret.id} does not exist.")
        model.name = secret.name
        model.category = secret.category
        model.username = secret.username
        model.secret_kind = secret.secret_kind.value
        model.secret_value_encrypted = secret.secret_value_encrypted
        model.url = secret.url
        model.notes = secret.notes
        model.tags = self._serialize_tags(secret.tags)
        model.created_at = secret.created_at
        model.updated_at = secret.updated_at
        model.deleted_at = secret.deleted_at
        model.last_access_at = secret.last_access_at
        self._session.flush()
        return self._to_entity(model)

    def count_active(self) -> int:
        stmt = select(func.count()).select_from(SecretModel).where(SecretModel.deleted_at.is_(None))
        return int(self._session.scalar(stmt) or 0)

    def category_counts(self) -> dict[str, int]:
        stmt = (
            select(SecretModel.category, func.count())
            .where(SecretModel.deleted_at.is_(None))
            .group_by(SecretModel.category)
            .order_by(SecretModel.category.asc())
        )
        rows = self._session.execute(stmt).all()
        return {str(category): int(count) for category, count in rows}

    def recent_updated(self, limit: int) -> list[Secret]:
        stmt = (
            select(SecretModel)
            .where(SecretModel.deleted_at.is_(None))
            .order_by(SecretModel.updated_at.desc())
            .limit(limit)
        )
        models = self._session.scalars(stmt).all()
        return [self._to_entity(model) for model in models]

    @staticmethod
    def _serialize_tags(tags: list[str]) -> str:
        return ",".join(sorted({tag.strip() for tag in tags if tag.strip()}))

    @staticmethod
    def _to_entity(model: SecretModel) -> Secret:
        return Secret(
            id=model.id,
            name=model.name,
            category=model.category,
            username=model.username,
            url=model.url,
            notes=model.notes,
            tags=[tag for tag in model.tags.split(",") if tag],
            secret_kind=SecretKind(model.secret_kind),
            secret_value_encrypted=model.secret_value_encrypted,
            created_at=model.created_at,
            updated_at=model.updated_at,
            deleted_at=model.deleted_at,
            last_access_at=model.last_access_at,
        )


class SqlAlchemyAuditLogRepository:
    """SQLAlchemy implementation of the audit log repository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, audit_log: AuditLog) -> AuditLog:
        model = AuditLogModel(
            user=audit_log.user,
            action=audit_log.action,
            ip_address=audit_log.ip_address,
            details=audit_log.details,
            created_at=audit_log.created_at,
        )
        self._session.add(model)
        self._session.flush()
        return self._to_entity(model)

    def list_recent(self, limit: int) -> list[AuditLog]:
        stmt = select(AuditLogModel).order_by(AuditLogModel.created_at.desc()).limit(limit)
        models = self._session.scalars(stmt).all()
        return [self._to_entity(model) for model in models]

    @staticmethod
    def _to_entity(model: AuditLogModel) -> AuditLog:
        return AuditLog(
            id=model.id,
            user=model.user,
            action=model.action,
            ip_address=model.ip_address,
            details=model.details,
            created_at=model.created_at,
        )
