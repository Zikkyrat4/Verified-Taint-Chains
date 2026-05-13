"""Logger configuration using loguru."""

import sys
from typing import Any

from loguru import logger

# Remove default handler
logger.remove()

# Always log to file (DEBUG level, full details) — silent, no terminal noise
_LOG_FILE = "vtc.log"
logger.add(
    _LOG_FILE,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {module}:{function}:{line} | {message}",
    level="DEBUG",
    rotation="10 MB",
    retention="7 days",
)

_stderr_handler_id: int | None = None


def enable_stderr(level: str = "INFO") -> None:
    """Add stderr handler for terminal output.

    Called once by the CLI analyze command so that --help and other
    non-analysis commands stay quiet in the terminal.
    """
    global _stderr_handler_id
    if _stderr_handler_id is not None:
        return  # already enabled
    _stderr_handler_id = logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
        level=level,
        colorize=True,
    )


def setup_logger(level: str = "INFO", log_file: str | None = None) -> Any:
    """Configure and return a logger instance.

    Kept for backwards compatibility.

    Returns:
        Configured loguru logger instance.
    """
    return logger


def get_logger() -> Any:
    """Get the configured logger instance.

    Returns:
        Configured loguru logger instance.
    """
    return logger
