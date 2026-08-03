"""Application services orchestrating the VaultPy use cases."""

from __future__ import annotations

import json
from datetime import UTC

from vaultpy.application.dto import (
    AuditLogResponse,
    DashboardResponse,
    LoginRequest,
    PasswordGenerateRequest,
    PasswordGenerateResponse,
    RefreshRequest,
    SecretCreateRequest,
    SecretResponse,
    SecretUpdateRequest,
    SecretValueResponse,
    SetupRequest,
    TokenPair,
)
from vaultpy.application.interfaces import UnitOfWork, UnitOfWorkFactory
from vaultpy.application.security import (
    DataKeyManager,
    JwtService,
    PasswordGenerator,
    PasswordHasher,
    SessionRegistry,
    utcnow,
)
from vaultpy.domain.entities import (
    AuditLog,
    AuthenticatedContext,
    DashboardSnapshot,
    Secret,
    VaultConfig,
)
from vaultpy.domain.exceptions import (
    InvalidMasterPasswordError,
    SecretNotFoundError,
    ValidationError,
)


class AuthService:
    """Handle vault bootstrap and JWT-based authentication."""

    def __init__(
        self,
        uow_factory: UnitOfWorkFactory,
        password_hasher: PasswordHasher,
        data_key_manager: DataKeyManager,
        jwt_service: JwtService,
        session_registry: SessionRegistry,
        pbkdf2_iterations: int,
    ) -> None:
        self._uow_factory = uow_factory
        self._password_hasher = password_hasher
        self._data_key_manager = data_key_manager
        self._jwt_service = jwt_service
        self._session_registry = session_registry
        self._pbkdf2_iterations = pbkdf2_iterations

    def is_bootstrapped(self) -> bool:
        """Return whether the master password has been configured."""
        with self._uow_factory() as uow:
            return uow.configs.get() is not None

    def bootstrap(self, request: SetupRequest, ip_address: str) -> None:
        """Initialize the vault with the first master password."""
        self._password_hasher.validate_strength(request.master_password)
        with self._uow_factory() as uow:
            if uow.configs.get() is not None:
                raise ValidationError("Vault is already bootstrapped.")
            password_hash, password_salt = self._password_hasher.hash_password(request.master_password)
            encrypted_data_key, key_encryption_salt = self._data_key_manager.create(request.master_password)
            now = utcnow()
            config = VaultConfig(
                id=1,
                password_hash=password_hash,
                password_salt=password_salt,
                key_encryption_salt=key_encryption_salt,
                encrypted_data_key=encrypted_data_key,
                pbkdf2_iterations=self._pbkdf2_iterations,
                created_at=now,
                updated_at=now,
            )
            uow.configs.save(config)
            uow.audits.create(
                AuditLog(
                    id=None,
                    user="master",
                    action="setup",
                    ip_address=ip_address,
                    details="Initial master password configured.",
                    created_at=now,
                )
            )

    def login(self, request: LoginRequest, ip_address: str) -> TokenPair:
        """Authenticate the master password and return JWT tokens."""
        with self._uow_factory() as uow:
            config = uow.configs.get()
            if config is None:
                raise InvalidMasterPasswordError("Vault is not bootstrapped.")
            if not self._password_hasher.verify_password(
                request.master_password,
                config.password_hash,
                config.password_salt,
            ):
                raise InvalidMasterPasswordError("Invalid master password.")
            data_key = self._data_key_manager.unlock(
                request.master_password,
                config.encrypted_data_key,
                config.key_encryption_salt,
            )
            session_id = self._session_registry.create(data_key)
            config.last_login_at = utcnow()
            config.last_access_at = config.last_login_at
            config.updated_at = config.last_login_at
            uow.configs.save(config)
            uow.audits.create(
                AuditLog(
                    id=None,
                    user="master",
                    action="login",
                    ip_address=ip_address,
                    details="Master password authentication succeeded.",
                    created_at=config.last_login_at,
                )
            )
        return TokenPair(
            access_token=self._jwt_service.create_access_token(session_id),
            refresh_token=self._jwt_service.create_refresh_token(session_id),
        )

    def refresh(self, request: RefreshRequest) -> TokenPair:
        """Refresh access and refresh tokens for an existing session."""
        payload = self._jwt_service.decode_token(request.refresh_token, expected_type="refresh")
        session_id = str(payload["sid"])
        self._session_registry.refresh(session_id)
        return TokenPair(
            access_token=self._jwt_service.create_access_token(session_id),
            refresh_token=self._jwt_service.create_refresh_token(session_id),
        )

    def logout(self, access_token: str, ip_address: str) -> None:
        """Invalidate an access token session."""
        payload = self._jwt_service.decode_token(
            access_token,
            expected_type="access",
            verify_exp=False,
        )
        session_id = str(payload["sid"])
        self._session_registry.revoke(session_id)
        with self._uow_factory() as uow:
            uow.audits.create(
                AuditLog(
                    id=None,
                    user="master",
                    action="logout",
                    ip_address=ip_address,
                    details="Session revoked.",
                    created_at=utcnow(),
                )
            )

    def context_from_token(self, access_token: str) -> AuthenticatedContext:
        """Resolve the authenticated context for an access token."""
        payload = self._jwt_service.decode_token(access_token, expected_type="access")
        session_id = str(payload["sid"])
        return self._session_registry.get_context(session_id)


class SecretService:
    """Handle secrets CRUD, search, dashboard, and audits."""

    def __init__(
        self,
        uow_factory: UnitOfWorkFactory,
        data_key_manager: DataKeyManager,
        password_generator: PasswordGenerator,
    ) -> None:
        self._uow_factory = uow_factory
        self._data_key_manager = data_key_manager
        self._password_generator = password_generator

    def create_secret(
        self,
        context: AuthenticatedContext,
        request: SecretCreateRequest,
        ip_address: str,
    ) -> SecretResponse:
        """Create a new secret."""
        encrypted_value = self._data_key_manager.encrypt_value(
            context.data_key,
            self._serialize_secret_content(
                secret_value=request.secret_value,
                secret_fields=request.secret_fields,
            ),
        )
        now = utcnow()
        secret = Secret(
            id=None,
            name=request.name.strip(),
            category=request.category.strip(),
            username=request.username.strip(),
            url=request.url.strip() if request.url else None,
            notes=request.notes.strip() if request.notes else None,
            tags=request.tags,
            secret_kind=request.secret_kind,
            secret_value_encrypted=encrypted_value,
            created_at=now,
            updated_at=now,
        )
        with self._uow_factory() as uow:
            created = uow.secrets.create(secret)
            uow.audits.create(
                AuditLog(
                    id=None,
                    user=context.user,
                    action="create",
                    ip_address=ip_address,
                    details=f"Created secret '{created.name}'.",
                    created_at=now,
                )
            )
        return self._secret_to_response(created)

    def list_secrets(self, *, query: str | None = None) -> list[SecretResponse]:
        """List or search active secrets."""
        with self._uow_factory() as uow:
            secrets = uow.secrets.search(query) if query else uow.secrets.list_active()
        return [self._secret_to_response(secret) for secret in secrets]

    def get_secret(self, secret_id: int) -> SecretResponse:
        """Return a single secret metadata view."""
        with self._uow_factory() as uow:
            secret = uow.secrets.get_by_id(secret_id)
            if secret is None:
                raise SecretNotFoundError(f"Secret {secret_id} was not found.")
        return self._secret_to_response(secret)

    def update_secret(
        self,
        context: AuthenticatedContext,
        secret_id: int,
        request: SecretUpdateRequest,
        ip_address: str,
    ) -> SecretResponse:
        """Update an existing secret."""
        with self._uow_factory() as uow:
            secret = uow.secrets.get_by_id(secret_id)
            if secret is None:
                raise SecretNotFoundError(f"Secret {secret_id} was not found.")
            if request.name is not None:
                secret.name = request.name.strip()
            if request.category is not None:
                secret.category = request.category.strip()
            if request.username is not None:
                secret.username = request.username.strip()
            if request.url is not None:
                secret.url = request.url.strip() or None
            if request.notes is not None:
                secret.notes = request.notes.strip() or None
            if request.tags is not None:
                secret.tags = request.tags
            if request.secret_kind is not None:
                secret.secret_kind = request.secret_kind
            if request.secret_value is not None or request.secret_fields is not None:
                current_content = self._deserialize_secret_content(
                    secret.name,
                    self._data_key_manager.decrypt_value(
                        context.data_key,
                        secret.secret_value_encrypted,
                    ),
                )
                secret.secret_value_encrypted = self._data_key_manager.encrypt_value(
                    context.data_key,
                    self._serialize_secret_content(
                        secret_value=(
                            request.secret_value if request.secret_value is not None else current_content.secret_value
                        ),
                        secret_fields=(
                            request.secret_fields
                            if request.secret_fields is not None
                            else current_content.secret_fields
                        ),
                    ),
                )
            secret.updated_at = utcnow()
            updated = uow.secrets.save(secret)
            uow.audits.create(
                AuditLog(
                    id=None,
                    user=context.user,
                    action="update",
                    ip_address=ip_address,
                    details=f"Updated secret '{updated.name}'.",
                    created_at=secret.updated_at,
                )
            )
        return self._secret_to_response(updated)

    def delete_secret(self, context: AuthenticatedContext, secret_id: int, ip_address: str) -> None:
        """Soft delete a secret."""
        with self._uow_factory() as uow:
            secret = uow.secrets.get_by_id(secret_id)
            if secret is None:
                raise SecretNotFoundError(f"Secret {secret_id} was not found.")
            secret.deleted_at = utcnow()
            secret.updated_at = secret.deleted_at
            uow.secrets.save(secret)
            uow.audits.create(
                AuditLog(
                    id=None,
                    user=context.user,
                    action="delete",
                    ip_address=ip_address,
                    details=f"Soft deleted secret '{secret.name}'.",
                    created_at=secret.deleted_at,
                )
            )

    def get_secret_value(
        self,
        context: AuthenticatedContext,
        secret_id: int,
        ip_address: str,
    ) -> SecretValueResponse:
        """Return a decrypted secret value for an authenticated request."""
        with self._uow_factory() as uow:
            secret = uow.secrets.get_by_id(secret_id)
            if secret is None:
                raise SecretNotFoundError(f"Secret {secret_id} was not found.")
            return self._build_secret_value_response(context, secret, ip_address, uow)

    def get_secret_value_by_name(
        self,
        context: AuthenticatedContext,
        name: str,
        ip_address: str,
    ) -> SecretValueResponse:
        """Return a decrypted secret value using the secret name."""
        with self._uow_factory() as uow:
            secret = uow.secrets.get_by_name(name)
            if secret is None:
                raise SecretNotFoundError(f"Secret '{name.strip()}' was not found.")
            return self._build_secret_value_response(context, secret, ip_address, uow)

    def dashboard(self) -> DashboardResponse:
        """Return dashboard aggregates."""
        with self._uow_factory() as uow:
            config = uow.configs.get()
            snapshot = DashboardSnapshot(
                total_secrets=uow.secrets.count_active(),
                category_counts=uow.secrets.category_counts(),
                recent_updates=uow.secrets.recent_updated(limit=5),
                last_access_at=config.last_access_at if config else None,
            )
        return DashboardResponse(
            total_secrets=snapshot.total_secrets,
            categories=snapshot.category_counts,
            recent_updates=[self._secret_to_response(secret) for secret in snapshot.recent_updates],
            last_access_at=snapshot.last_access_at,
        )

    def list_audit_logs(self) -> list[AuditLogResponse]:
        """Return recent audit logs."""
        with self._uow_factory() as uow:
            logs = uow.audits.list_recent(limit=20)
        return [
            AuditLogResponse(
                id=log.id or 0,
                user=log.user,
                action=log.action,
                ip_address=log.ip_address,
                details=log.details,
                created_at=log.created_at,
            )
            for log in logs
        ]

    def generate_password(self, request: PasswordGenerateRequest) -> PasswordGenerateResponse:
        """Generate a strong password."""
        password = self._password_generator.generate(
            length=request.length,
            include_symbols=request.include_symbols,
            include_numbers=request.include_numbers,
            include_uppercase=request.include_uppercase,
            include_lowercase=request.include_lowercase,
        )
        return PasswordGenerateResponse(password=password)

    def _build_secret_value_response(
        self,
        context: AuthenticatedContext,
        secret: Secret,
        ip_address: str,
        uow: UnitOfWork,
    ) -> SecretValueResponse:
        secret.last_access_at = utcnow()
        uow.secrets.save(secret)
        uow.audits.create(
            AuditLog(
                id=None,
                user=context.user,
                action="secret_view",
                ip_address=ip_address,
                details=f"Viewed secret value for '{secret.name}'.",
                created_at=secret.last_access_at,
            )
        )
        decrypted_value = self._data_key_manager.decrypt_value(
            context.data_key,
            secret.secret_value_encrypted,
        )
        return self._deserialize_secret_content(secret.name, decrypted_value)

    @staticmethod
    def _serialize_secret_content(
        *,
        secret_value: str | None,
        secret_fields: dict[str, str],
    ) -> str:
        normalized_value = secret_value.strip() if secret_value else None
        normalized_fields = {
            str(key).strip(): str(value).strip()
            for key, value in secret_fields.items()
            if str(key).strip() and str(value).strip()
        }
        if not normalized_value and not normalized_fields:
            raise ValidationError("Provide either secret_value or secret_fields.")
        return json.dumps(
            {
                "secret_value": normalized_value,
                "secret_fields": normalized_fields,
            },
            ensure_ascii=True,
            sort_keys=True,
        )

    @staticmethod
    def _deserialize_secret_content(secret_name: str, payload: str) -> SecretValueResponse:
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError:
            return SecretValueResponse(secret_name=secret_name, secret_value=payload, secret_fields={})
        if not isinstance(decoded, dict):
            return SecretValueResponse(secret_name=secret_name, secret_value=payload, secret_fields={})
        secret_value = decoded.get("secret_value")
        raw_fields = decoded.get("secret_fields", {})
        if not isinstance(raw_fields, dict):
            raw_fields = {}
        return SecretValueResponse(
            secret_name=secret_name,
            secret_value=str(secret_value).strip() if secret_value else None,
            secret_fields={
                str(key).strip(): str(value).strip()
                for key, value in raw_fields.items()
                if str(key).strip() and str(value).strip()
            },
        )

    @staticmethod
    def _secret_to_response(secret: Secret) -> SecretResponse:
        return SecretResponse(
            id=secret.id or 0,
            name=secret.name,
            category=secret.category,
            username=secret.username,
            secret_kind=secret.secret_kind,
            url=secret.url,
            notes=secret.notes,
            tags=secret.tags,
            created_at=secret.created_at.astimezone(UTC),
            updated_at=secret.updated_at.astimezone(UTC),
            last_access_at=secret.last_access_at.astimezone(UTC) if secret.last_access_at else None,
        )
