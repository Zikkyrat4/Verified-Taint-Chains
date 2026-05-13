"""Tests for __main__.py CLI interface."""

import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from src.__main__ import cli, main


@pytest.fixture
def runner():
    return CliRunner()


class TestMainCLI:
    """Tests for __main__.py CLI commands."""

    def test_cli_group(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Verified Taint Chains" in result.output

    def test_version_command(self, runner):
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "Verified Taint Chains" in result.output

    @patch("src.__main__.load_config_from_env")
    def test_config_command(self, mock_load, runner):
        mock_config = MagicMock()
        mock_config.llm_model = "gpt-4-turbo"
        mock_config.max_path_length = 15
        mock_config.min_confidence = 0.5
        mock_config.verification_enabled = True
        mock_config.symbolic_execution_enabled = False
        mock_load.return_value = mock_config

        result = runner.invoke(cli, ["config"])
        assert result.exit_code == 0
        assert "Configuration" in result.output
        assert "gpt-4-turbo" in result.output

    @patch("src.__main__.load_config_from_env")
    def test_config_command_error(self, mock_load, runner):
        mock_load.side_effect = ValueError("No API key")

        result = runner.invoke(cli, ["config"])
        assert result.exit_code != 0

    def test_help_env_command(self, runner):
        result = runner.invoke(cli, ["help-env"])
        assert result.exit_code == 0
        assert "OPENAI_API_KEY" in result.output
        assert "OPENAI_MODEL" in result.output
        assert "MAX_PATH_LENGTH" in result.output

    def test_analyze_missing_file(self, runner):
        result = runner.invoke(cli, ["analyze", "--file", "nonexistent.java"])
        assert result.exit_code != 0

    @patch("src.__main__.load_config_from_env")
    def test_analyze_config_error(self, mock_load, runner, tmp_path):
        mock_load.side_effect = ValueError("Missing API key")
        test_file = tmp_path / "test.java"
        test_file.write_text("public class Test {}")

        result = runner.invoke(cli, ["analyze", "--file", str(test_file)])
        assert result.exit_code != 0
        assert "Configuration Error" in result.output

    def test_main_function(self):
        # main() wraps cli(), test via cli with --help
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Verified Taint Chains" in result.output
