"""Explicit, application-owned Loguru configuration for VTC."""

from __future__ import annotations

import os
import re
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Optional, Union

from dotenv import load_dotenv
from loguru import logger

_PACKAGE = "src"
_DEFAULT_LEVEL = "INFO"
_DISABLED_FILE_VALUES = frozenset({"", "-", "none", "off", "false", "disabled"})
_FILE_FORMAT = (
    "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | "
    "{name}:{function}:{line} | run={extra[run_id]} command={extra[command]} "
    "target={extra[target]} function={extra[function_name]} | {message}\n{exception}"
)
_STDERR_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
    "<level>{level: <8}</level> | <level>{message}</level>"
)

_SECRET_PATTERNS = (
    (
        re.compile(
            r"(?i)(\b(?:authorization|api[_-]?key|token|password|secret)\b"
            r"\s*[:=]\s*(?:bearer\s+)?)([^\s,;]+)"
        ),
        r"\1<redacted>",
    ),
    (re.compile(r"(?i)\bsk-[a-z0-9_-]{8,}"), "sk-<redacted>"),
    (re.compile(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@"), r"\1<redacted>@"),
)

_managed_handler_ids: set[int] = set()
_configuration_lock = threading.RLock()
_run_id = "-"

# A library import must not write files or emit terminal noise. CLI entry points
# explicitly enable this namespace through ``configure_logging()``.
logger.disable(_PACKAGE)


def default_log_file() -> Path:
    """Return the per-user default log path without creating it."""
    state_home = os.getenv("XDG_STATE_HOME")
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return base / "vtc" / "vtc.log"


def _redact(message: str) -> str:
    """Remove common credential forms before a record reaches any VTC sink."""
    redacted = message
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _vtc_record(record: dict[str, Any]) -> bool:
    """Filter to VTC records, add stable context fields, and redact secrets."""
    name = str(record.get("name", ""))
    if name != _PACKAGE and not name.startswith(f"{_PACKAGE}."):
        return False

    extra = record["extra"]
    extra.setdefault("run_id", _run_id)
    extra.setdefault("command", "-")
    extra.setdefault("target", "-")
    extra.setdefault("function_name", "-")
    record["message"] = _redact(str(record["message"]))
    return True


def _secure_opener(path: str, flags: int) -> int:
    """Create rotated log files with owner-only permissions."""
    return os.open(path, flags, 0o600)


def _resolve_level(level: Optional[str]) -> tuple[str, Optional[str]]:
    requested = (level or os.getenv("LOG_LEVEL") or _DEFAULT_LEVEL).upper()
    try:
        logger.level(requested)
    except (TypeError, ValueError):
        return _DEFAULT_LEVEL, f"Invalid LOG_LEVEL {requested!r}; using {_DEFAULT_LEVEL}"
    return requested, None


def _resolve_log_file(log_file: Optional[Union[str, Path]]) -> Optional[Path]:
    if log_file is not None:
        value = str(log_file).strip()
    elif "LOG_FILE" in os.environ:
        value = os.environ["LOG_FILE"].strip()
    else:
        return default_log_file()

    if value.lower() in _DISABLED_FILE_VALUES:
        return None
    return Path(value).expanduser()


def _remove_managed_handlers() -> None:
    for handler_id in tuple(_managed_handler_ids):
        try:
            logger.remove(handler_id)
        except ValueError:
            pass
        finally:
            _managed_handler_ids.discard(handler_id)


def configure_logging(
    level: Optional[str] = None,
    log_file: Optional[Union[str, Path]] = None,
    *,
    stderr: bool = True,
    file_logging: bool = True,
    remove_default_handler: bool = True,
) -> Any:
    """Configure VTC-owned sinks and return the shared Loguru logger.

    Configuration is idempotent and only removes handlers previously installed
    by VTC. ``LOG_LEVEL`` and ``LOG_FILE`` are read after loading ``.env``.
    Set ``LOG_FILE=off`` to disable persistent logging.
    """
    global _run_id

    load_dotenv()
    resolved_level, level_warning = _resolve_level(level)
    resolved_file = _resolve_log_file(log_file) if file_logging else None

    with _configuration_lock:
        _remove_managed_handlers()

        # Loguru's built-in stderr handler is always ID 0. Removing only this
        # known handler avoids duplicate CLI output without touching host sinks.
        if remove_default_handler:
            try:
                logger.remove(0)
            except ValueError:
                pass

        _run_id = uuid.uuid4().hex[:12]
        logger.enable(_PACKAGE)

        if stderr:
            handler_id = logger.add(
                sys.stderr,
                format=_STDERR_FORMAT,
                level=resolved_level,
                colorize=None,
                filter=_vtc_record,
                backtrace=False,
                diagnose=False,
            )
            _managed_handler_ids.add(handler_id)

        if resolved_file is not None:
            try:
                resolved_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if resolved_file.exists():
                    resolved_file.chmod(0o600)
                handler_id = logger.add(
                    resolved_file,
                    format=_FILE_FORMAT,
                    level=resolved_level,
                    rotation="10 MB",
                    retention="7 days",
                    enqueue=True,
                    opener=_secure_opener,
                    filter=_vtc_record,
                    backtrace=False,
                    diagnose=False,
                )
                _managed_handler_ids.add(handler_id)
            except OSError as error:
                logger.warning(f"File logging disabled: {error}")

        if level_warning:
            logger.warning(level_warning)

    return logger


def enable_stderr(level: Optional[str] = None) -> None:
    """Configure the standard CLI sinks, including stderr."""
    configure_logging(level=level, stderr=True)


def setup_logger(
    level: Optional[str] = None,
    log_file: Optional[Union[str, Path]] = None,
) -> Any:
    """Backward-compatible alias for :func:`configure_logging`."""
    return configure_logging(level=level, log_file=log_file)


def shutdown_logging() -> None:
    """Flush and remove VTC-owned handlers, primarily for embedding and tests."""
    with _configuration_lock:
        logger.complete()
        _remove_managed_handlers()
        logger.disable(_PACKAGE)


def get_logger() -> Any:
    """Return the shared logger without configuring output sinks."""
    return logger
