"""Application container and dependency helpers."""

from __future__ import annotations

from functools import lru_cache

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from vaultpy.application.security import (
    DataKeyManager,
    JwtService,
    PasswordGenerator,
    PasswordHasher,
    SessionRegistry,
)
from vaultpy.application.services import AuthService, SecretService
from vaultpy.domain.entities import DEFAULT_CATEGORIES, AuthenticatedContext
from vaultpy.domain.exceptions import AuthorizationError
from vaultpy.infrastructure.database import Database, SqlAlchemyUnitOfWork
from vaultpy.shared.config import Settings, get_settings


class Container:
    """Wire infrastructure and application services."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.database = Database(settings.database_url)
        self.password_hasher = PasswordHasher(settings.pbkdf2_iterations)
        self.data_key_manager = DataKeyManager(settings.pbkdf2_iterations)
        self.jwt_service = JwtService(
            secret_key=settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
            access_minutes=settings.access_token_minutes,
            refresh_minutes=settings.refresh_token_minutes,
        )
        self.session_registry = SessionRegistry(settings.session_ttl_minutes)
        self.password_generator = PasswordGenerator()
        self.auth_service = AuthService(
            uow_factory=self.new_uow,
            password_hasher=self.password_hasher,
            data_key_manager=self.data_key_manager,
            jwt_service=self.jwt_service,
            session_registry=self.session_registry,
            pbkdf2_iterations=settings.pbkdf2_iterations,
        )
        self.secret_service = SecretService(
            uow_factory=self.new_uow,
            data_key_manager=self.data_key_manager,
            password_generator=self.password_generator,
        )
        self.categories = list(DEFAULT_CATEGORIES)

    def init_database(self) -> None:
        """Create database tables."""
        self.database.init()

    def new_uow(self) -> SqlAlchemyUnitOfWork:
        """Build a new unit of work."""
        return SqlAlchemyUnitOfWork(self.database)


security_scheme = HTTPBearer(auto_error=False)


@lru_cache(maxsize=1)
def get_container() -> Container:
    """Return the cached application container."""
    return Container(get_settings())


def get_access_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
) -> str:
    """Extract the access token from the Authorization header."""
    if credentials is None:
        raise AuthorizationError("Authorization header is required.")
    return credentials.credentials


def get_authenticated_context(token: str = Depends(get_access_token)) -> AuthenticatedContext:
    """Resolve the authenticated context from the current JWT."""
    return get_container().auth_service.context_from_token(token)
