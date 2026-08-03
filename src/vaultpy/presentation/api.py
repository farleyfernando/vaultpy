"""FastAPI routers for VaultPy."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status

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
    StatusResponse,
    TokenPair,
)
from vaultpy.domain.entities import DEFAULT_CATEGORIES, AuthenticatedContext
from vaultpy.presentation.dependencies import (
    Container,
    get_access_token,
    get_authenticated_context,
)


def get_client_ip(request: Request) -> str:
    """Extract a best-effort client IP address."""
    return request.client.host if request.client else "local"


def create_api_router(container: Container) -> APIRouter:
    """Create the versioned API router."""
    router = APIRouter(prefix=container.settings.api_prefix)

    @router.get("/status", response_model=StatusResponse)
    def status_endpoint() -> StatusResponse:
        return StatusResponse(
            bootstrapped=container.auth_service.is_bootstrapped(),
            categories=list(DEFAULT_CATEGORIES),
        )

    @router.post("/setup", status_code=status.HTTP_201_CREATED)
    def setup_endpoint(request_body: SetupRequest, request: Request) -> dict[str, str]:
        container.auth_service.bootstrap(request_body, get_client_ip(request))
        return {"message": "Master password configured successfully."}

    @router.post("/auth/login", response_model=TokenPair)
    def login_endpoint(request_body: LoginRequest, request: Request) -> TokenPair:
        return container.auth_service.login(request_body, get_client_ip(request))

    @router.post("/auth/refresh", response_model=TokenPair)
    def refresh_endpoint(request_body: RefreshRequest) -> TokenPair:
        return container.auth_service.refresh(request_body)

    @router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
    def logout_endpoint(
        request: Request,
        access_token: str = Depends(get_access_token),
    ) -> Response:
        container.auth_service.logout(access_token, get_client_ip(request))
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.get("/dashboard", response_model=DashboardResponse)
    def dashboard_endpoint(
        _: AuthenticatedContext = Depends(get_authenticated_context),
    ) -> DashboardResponse:
        return container.secret_service.dashboard()

    @router.get("/audit-logs", response_model=list[AuditLogResponse])
    def audit_logs_endpoint(
        _: AuthenticatedContext = Depends(get_authenticated_context),
    ) -> list[AuditLogResponse]:
        return container.secret_service.list_audit_logs()

    @router.post("/passwords/generate", response_model=PasswordGenerateResponse)
    def password_generate_endpoint(
        request_body: PasswordGenerateRequest,
    ) -> PasswordGenerateResponse:
        return container.secret_service.generate_password(request_body)

    @router.post("/secrets", response_model=SecretResponse, status_code=status.HTTP_201_CREATED)
    def create_secret_endpoint(
        request_body: SecretCreateRequest,
        request: Request,
        context: AuthenticatedContext = Depends(get_authenticated_context),
    ) -> SecretResponse:
        return container.secret_service.create_secret(context, request_body, get_client_ip(request))

    @router.get("/secrets", response_model=list[SecretResponse])
    def list_secrets_endpoint(
        query: str | None = None,
        _: AuthenticatedContext = Depends(get_authenticated_context),
    ) -> list[SecretResponse]:
        return container.secret_service.list_secrets(query=query)

    @router.get("/secrets/search", response_model=list[SecretResponse])
    def search_secrets_endpoint(
        q: str,
        _: AuthenticatedContext = Depends(get_authenticated_context),
    ) -> list[SecretResponse]:
        return container.secret_service.list_secrets(query=q)

    @router.get("/secrets/{secret_id}", response_model=SecretResponse)
    def get_secret_endpoint(
        secret_id: int,
        _: AuthenticatedContext = Depends(get_authenticated_context),
    ) -> SecretResponse:
        return container.secret_service.get_secret(secret_id)

    @router.put("/secrets/{secret_id}", response_model=SecretResponse)
    def update_secret_endpoint(
        secret_id: int,
        request_body: SecretUpdateRequest,
        request: Request,
        context: AuthenticatedContext = Depends(get_authenticated_context),
    ) -> SecretResponse:
        return container.secret_service.update_secret(context, secret_id, request_body, get_client_ip(request))

    @router.delete("/secrets/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_secret_endpoint(
        secret_id: int,
        request: Request,
        context: AuthenticatedContext = Depends(get_authenticated_context),
    ) -> Response:
        container.secret_service.delete_secret(context, secret_id, get_client_ip(request))
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.get("/secrets/{secret_id}/value", response_model=SecretValueResponse)
    def get_secret_value_endpoint(
        secret_id: int,
        request: Request,
        context: AuthenticatedContext = Depends(get_authenticated_context),
    ) -> SecretValueResponse:
        return container.secret_service.get_secret_value(context, secret_id, get_client_ip(request))

    return router
