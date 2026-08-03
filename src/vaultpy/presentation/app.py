"""Application factory for FastAPI + NiceGUI."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from vaultpy.domain.exceptions import (
    AuthenticationError,
    AuthorizationError,
    EncryptionError,
    InvalidMasterPasswordError,
    SecretNotFoundError,
    ValidationError,
    VaultPyError,
)
from vaultpy.presentation.api import create_api_router
from vaultpy.presentation.dependencies import get_container
from vaultpy.presentation.ui import register_ui
from vaultpy.shared.logging import configure_logging


class SecureHeadersMiddleware(BaseHTTPMiddleware):
    """Add baseline security headers to every response."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


def create_app() -> FastAPI:
    """Create and configure the ASGI application."""
    configure_logging()
    container = get_container()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        container.init_database()
        logger.info("VaultPy initialized.")
        yield

    app = FastAPI(title=container.settings.app_name, version="0.1.0", lifespan=lifespan)
    app.add_middleware(SecureHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(create_api_router(container))
    register_ui(app, container)

    def build_exception_response(status_code: int, detail: str) -> JSONResponse:
        return JSONResponse(status_code=status_code, content={"detail": detail})

    @app.exception_handler(SecretNotFoundError)
    async def secret_not_found_handler(_: Request, exc: SecretNotFoundError) -> JSONResponse:
        return build_exception_response(404, str(exc))

    @app.exception_handler(ValidationError)
    @app.exception_handler(InvalidMasterPasswordError)
    @app.exception_handler(EncryptionError)
    async def validation_handler(_: Request, exc: VaultPyError) -> JSONResponse:
        return build_exception_response(400, str(exc))

    @app.exception_handler(AuthenticationError)
    @app.exception_handler(AuthorizationError)
    async def auth_handler(_: Request, exc: VaultPyError) -> JSONResponse:
        return build_exception_response(401, str(exc))

    return app
