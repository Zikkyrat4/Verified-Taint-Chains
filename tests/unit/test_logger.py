"""Unit tests for logger configuration."""

import tempfile
from pathlib import Path

from src.utils.logger import setup_logger, get_logger


class TestLoggerSetup:
    """Tests for logger configuration."""

    def test_setup_logger_default(self) -> None:
        """Test logger setup with default parameters."""
        logger = setup_logger()
        assert logger is not None

    def test_setup_logger_with_level(self) -> None:
        """Test logger setup with custom level."""
        logger = setup_logger(level="DEBUG")
        assert logger is not None

    def test_setup_logger_with_file(self) -> None:
        """Test logger setup returns logger (auto-configured at import)."""
        lgr = setup_logger()
        assert lgr is not None
        # Logger auto-writes to vtc.log; setup_logger is kept for compat
        lgr.info("Test message from test_setup_logger_with_file")

    def test_get_logger(self) -> None:
        """Test getting logger instance."""
        logger = get_logger()
        assert logger is not None

    def test_logger_can_log(self) -> None:
        """Test that logger can log messages."""
        logger = setup_logger(level="INFO")
        # These should not raise exceptions
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
