"""Loguru logging bootstrap."""

from __future__ import annotations

import sys

from loguru import logger


def configure_logging() -> None:
    """Configure Loguru only once for the application."""
    if logger._core.handlers:  # type: ignore[attr-defined]
        return
    logger.remove()
    logger.add(
        sys.stdout,
        level="INFO",
        enqueue=True,
        backtrace=False,
        diagnose=False,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level}</level> | {message}",
    )
