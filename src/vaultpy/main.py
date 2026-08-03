"""Executable entrypoint for VaultPy."""

from __future__ import annotations

import uvicorn

from vaultpy.presentation.app import create_app
from vaultpy.shared.config import get_settings

app = create_app()


def run() -> None:
    """Run the ASGI application with Uvicorn."""
    settings = get_settings()
    uvicorn.run("vaultpy.main:app", host=settings.host, port=settings.port, reload=False)
