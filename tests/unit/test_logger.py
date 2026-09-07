"""Behavioral tests for VTC logging configuration."""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

import pytest
from loguru import logger as loguru_logger

from src.utils.logger import (
    configure_logging,
    default_log_file,
    get_logger,
    setup_logger,
    shutdown_logging,
)

ROOT = Path(__file__).resolve().parents[2]


def _emit(level: str, message: str) -> None:
    """Emit a record whose name matches the VTC sink filter."""
    patched = get_logger().patch(lambda record: record.update(name="src.test_logger"))
    getattr(patched, level)(message)
    get_logger().complete()


@pytest.fixture(autouse=True)
def reset_vtc_logging(monkeypatch):
    shutdown_logging()
    monkeypatch.setenv("LOG_FILE", "off")
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    yield
    shutdown_logging()


def test_import_does_not_create_a_log_file(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["LOG_FILE"] = str(tmp_path / "should-not-exist.log")

    result = subprocess.run(
        [sys.executable, "-c", "import src.utils.logger"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "should-not-exist.log").exists()
    assert not (tmp_path / "vtc.log").exists()


def test_setup_logger_honors_level_and_file(tmp_path: Path) -> None:
    log_file = tmp_path / "configured.log"
    setup_logger(level="ERROR", log_file=log_file)

    _emit("warning", "FILTERED")
    _emit("error", "KEPT")

    contents = log_file.read_text()
    assert "FILTERED" not in contents
    assert "KEPT" in contents


def test_environment_controls_level_and_file(monkeypatch, tmp_path: Path) -> None:
    log_file = tmp_path / "environment.log"
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("LOG_FILE", str(log_file))
    configure_logging(stderr=False)

    _emit("debug", "ENV_DEBUG")

    assert "ENV_DEBUG" in log_file.read_text()


def test_default_log_file_uses_xdg_state_home(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("LOG_FILE", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))

    assert default_log_file() == tmp_path / "vtc" / "vtc.log"

    configure_logging(stderr=False)
    _emit("info", "DEFAULT_PATH")

    assert "DEFAULT_PATH" in default_log_file().read_text()


def test_log_file_is_owner_only(tmp_path: Path) -> None:
    log_file = tmp_path / "private.log"
    configure_logging(log_file=log_file, stderr=False)

    _emit("info", "PRIVATE")

    assert log_file.stat().st_mode & 0o777 == 0o600


def test_secrets_are_redacted(tmp_path: Path) -> None:
    log_file = tmp_path / "redacted.log"
    configure_logging(level="DEBUG", log_file=log_file, stderr=False)

    _emit(
        "debug",
        "Authorization: Bearer top-secret token=second-secret "
        "api_key=sk-1234567890 https://user:password@example.test/v1",
    )

    contents = log_file.read_text()
    assert "top-secret" not in contents
    assert "second-secret" not in contents
    assert "sk-1234567890" not in contents
    assert "user:password" not in contents
    assert contents.count("<redacted>") >= 4


def test_reconfiguration_replaces_only_vtc_handlers(tmp_path: Path) -> None:
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    host_output = io.StringIO()
    host_handler = loguru_logger.add(host_output, format="{message}")
    try:
        configure_logging(log_file=first, stderr=False)
        _emit("info", "FIRST")

        configure_logging(log_file=second, stderr=False)
        _emit("info", "SECOND")
        loguru_logger.warning("HOST_HANDLER_SURVIVED")
        loguru_logger.complete()
    finally:
        loguru_logger.remove(host_handler)

    assert "FIRST" in first.read_text()
    assert "SECOND" not in first.read_text()
    assert "SECOND" in second.read_text()
    assert "HOST_HANDLER_SURVIVED" in host_output.getvalue()


def test_context_is_written_to_file(tmp_path: Path) -> None:
    log_file = tmp_path / "context.log"
    configure_logging(log_file=log_file, stderr=False)

    with get_logger().contextualize(
        command="analyze",
        target="Example.java",
        function_name="handle",
    ):
        _emit("info", "CONTEXT")

    contents = log_file.read_text()
    assert "command=analyze" in contents
    assert "target=Example.java" in contents
    assert "function=handle" in contents


def test_unwritable_log_path_does_not_break_configuration(tmp_path: Path) -> None:
    regular_file = tmp_path / "not-a-directory"
    regular_file.write_text("blocker")

    configured = configure_logging(
        log_file=regular_file / "vtc.log",
        stderr=False,
    )
    _emit("warning", "FILE_SINK_UNAVAILABLE")

    assert configured is get_logger()


def test_invalid_level_falls_back_to_info(tmp_path: Path) -> None:
    log_file = tmp_path / "fallback.log"
    configure_logging(level="not-a-level", log_file=log_file, stderr=False)

    _emit("debug", "FILTERED_DEBUG")
    _emit("info", "KEPT_INFO")

    contents = log_file.read_text()
    assert "Invalid LOG_LEVEL" in contents
    assert "FILTERED_DEBUG" not in contents
    assert "KEPT_INFO" in contents


def test_get_logger_does_not_configure_output(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    assert get_logger() is not None
    assert not (tmp_path / "vtc.log").exists()
