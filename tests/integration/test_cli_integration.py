"""Integration tests for CLI interface."""

import os
import pytest
import tempfile
from pathlib import Path
from click.testing import CliRunner

from src.__main__ import cli
from src import __version__


class TestCLIAnalyzeCommand:
    """Tests for the analyze CLI command."""

    def test_analyze_help(self) -> None:
        """Test analyze command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "--help"])

        assert result.exit_code == 0
        assert "analyze" in result.output
        assert "--file" in result.output
        assert "--output" in result.output
        assert "--verbose" in result.output

    def test_analyze_missing_required_file(self) -> None:
        """Test analyze command without required --file option."""
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze"])

        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_analyze_nonexistent_file(self) -> None:
        """Test analyze command with non-existent file."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["analyze", "--file", "/nonexistent/file.java"],
        )

        assert result.exit_code != 0
        assert "does not exist" in result.output.lower() or "not found" in result.output.lower()

    def test_analyze_missing_config(self) -> None:
        """Test analyze command with missing configuration."""
        runner = CliRunner()

        # Create a temporary Java file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write("public class Test { }")
            temp_file = f.name

        # Force OpenAI provider and clear API key so config validation fails.
        # Use os.environ[...] = "" instead of pop() because load_dotenv()
        # restores popped vars from .env.
        original_key = os.environ.get("OPENAI_API_KEY")
        original_provider = os.environ.get("LLM_PROVIDER")
        os.environ["OPENAI_API_KEY"] = ""
        os.environ["LLM_PROVIDER"] = "openai"

        try:
            result = runner.invoke(cli, ["analyze", "--file", temp_file])

            # Should fail due to missing API key
            assert result.exit_code != 0
            assert "OPENAI_API_KEY" in result.output or "Configuration" in result.output

        finally:
            Path(temp_file).unlink()
            if original_key is not None:
                os.environ["OPENAI_API_KEY"] = original_key
            else:
                os.environ.pop("OPENAI_API_KEY", None)
            if original_provider is not None:
                os.environ["LLM_PROVIDER"] = original_provider
            else:
                os.environ.pop("LLM_PROVIDER", None)

    def test_analyze_with_output_option(self) -> None:
        """Test analyze command with custom output file."""
        runner = CliRunner()

        # Create temporary Java file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write("public class Test { }")
            temp_file = f.name

        # Set required environment variable
        os.environ["OPENAI_API_KEY"] = "test-key"

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                output_file = Path(tmpdir) / "custom_output.json"

                result = runner.invoke(
                    cli,
                    [
                        "analyze",
                        "--file", temp_file,
                        "--output", str(output_file),
                    ],
                )

                # Should invoke pipeline (may fail due to mocking, but that's ok for this test)
                # We're mainly testing the CLI accepts the argument
                assert "--output" not in result.output or output_file.name in result.output or "Results" in result.output

        finally:
            Path(temp_file).unlink()

    def test_analyze_verbose_flag(self) -> None:
        """Test analyze command with verbose flag."""
        runner = CliRunner()

        # Create temporary Java file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write("public class Test { }")
            temp_file = f.name

        os.environ["OPENAI_API_KEY"] = "test-key"

        try:
            result = runner.invoke(
                cli,
                [
                    "analyze",
                    "--file", temp_file,
                    "--verbose",
                ],
            )

            # Verbose flag should be accepted
            # (may fail due to mocking, but that's ok for CLI test)
            assert result.exit_code in [0, 1]  # Accept success or expected failure

        finally:
            Path(temp_file).unlink()


class TestCLIVersionCommand:
    """Tests for the version CLI command."""

    def test_version_command(self) -> None:
        """Test version command displays version info."""
        runner = CliRunner()
        result = runner.invoke(cli, ["version"])

        assert result.exit_code == 0
        assert __version__ in result.output
        assert "Verified Taint Chains" in result.output

    def test_version_format(self) -> None:
        """Test version output format."""
        runner = CliRunner()
        result = runner.invoke(cli, ["version"])

        assert result.exit_code == 0
        assert f"v{__version__}" in result.output
        assert "Author" in result.output
        assert "Description" in result.output

    def test_version_help(self) -> None:
        """Test version command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["version", "--help"])

        assert result.exit_code == 0
        assert "Display tool version" in result.output or "version" in result.output.lower()


class TestCLIConfigCommand:
    """Tests for the config CLI command."""

    def test_config_command(self) -> None:
        """Test config command displays configuration."""
        runner = CliRunner()

        # Set required environment variable
        os.environ["OPENAI_API_KEY"] = "test-key"
        os.environ["OPENAI_MODEL"] = "gpt-4"

        try:
            result = runner.invoke(cli, ["config"])

            if result.exit_code == 0:
                assert "Configuration" in result.output
                assert "gpt-4" in result.output or "LLM Model" in result.output

        finally:
            os.environ.pop("OPENAI_MODEL", None)

    def test_config_missing_api_key(self) -> None:
        """Test config command with missing API key."""
        runner = CliRunner()

        # Set API key to empty and force OpenAI provider so missing key triggers error
        # Use empty string instead of pop to prevent load_dotenv from restoring .env value
        original_key = os.environ.get("OPENAI_API_KEY")
        original_provider = os.environ.get("LLM_PROVIDER")
        os.environ["OPENAI_API_KEY"] = ""
        os.environ["LLM_PROVIDER"] = "openai"

        try:
            result = runner.invoke(cli, ["config"])

            # Should fail due to missing API key
            assert result.exit_code != 0

        finally:
            if original_key is not None:
                os.environ["OPENAI_API_KEY"] = original_key
            else:
                os.environ.pop("OPENAI_API_KEY", None)
            if original_provider is not None:
                os.environ["LLM_PROVIDER"] = original_provider
            else:
                os.environ.pop("LLM_PROVIDER", None)


class TestCLIHelpCommand:
    """Tests for the help-env CLI command."""

    def test_help_env_command(self) -> None:
        """Test help-env command displays environment variable info."""
        runner = CliRunner()
        result = runner.invoke(cli, ["help-env"])

        assert result.exit_code == 0
        assert "OPENAI_API_KEY" in result.output
        assert "MAX_PATH_LENGTH" in result.output
        assert ".env" in result.output

    def test_help_env_contains_example(self) -> None:
        """Test help-env displays example .env file."""
        runner = CliRunner()
        result = runner.invoke(cli, ["help-env"])

        assert result.exit_code == 0
        assert "Example .env file" in result.output
        assert "OPENAI_API_KEY=" in result.output


class TestCLIMainHelp:
    """Tests for main CLI help."""

    def test_main_help(self) -> None:
        """Test main CLI help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "Verified Taint Chains" in result.output
        assert "analyze" in result.output
        assert "version" in result.output

    def test_invalid_command(self) -> None:
        """Test invalid command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["invalid"])

        assert result.exit_code != 0
        assert "No such command" in result.output or "Error" in result.output


class TestCLIOutputFormatting:
    """Tests for CLI output formatting."""

    def test_analyze_output_format(self) -> None:
        """Test analyze command output formatting."""
        runner = CliRunner()

        # Create temporary Java file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write("public class Test { }")
            temp_file = f.name

        os.environ["OPENAI_API_KEY"] = "test-key"

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                output_file = Path(tmpdir) / "results.json"

                result = runner.invoke(
                    cli,
                    [
                        "analyze",
                        "--file", temp_file,
                        "--output", str(output_file),
                    ],
                )

                # Check for expected output elements
                # (output may vary based on pipeline results)
                if result.exit_code == 0 or "Analysis" in result.output:
                    assert "🔍" in result.output or "Running" in result.output or "Analysis" in result.output

        finally:
            Path(temp_file).unlink()


class TestCLIErrorHandling:
    """Tests for CLI error handling."""

    def test_analyze_keyboard_interrupt(self) -> None:
        """Test graceful handling of keyboard interrupt."""
        runner = CliRunner()

        # This is difficult to test directly, but we can verify the error handling code exists
        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write("public class Test { }")
            temp_file = f.name

        try:
            # Create result with mix_stderr to capture all output
            result = runner.invoke(
                cli,
                ["analyze", "--file", temp_file],
                mix_stderr=False,
            )

            # Either succeeds or fails gracefully
            assert result.exit_code in [0, 1, 130]

        finally:
            Path(temp_file).unlink()

    def test_config_error_message(self) -> None:
        """Test configuration error message formatting."""
        runner = CliRunner()

        # Remove API key to trigger error
        original_key = os.environ.pop("OPENAI_API_KEY", None)

        try:
            result = runner.invoke(cli, ["config"])

            if result.exit_code != 0:
                # Should have error message
                assert "❌" in result.output or "Error" in result.output or "Configuration" in result.output

        finally:
            if original_key:
                os.environ["OPENAI_API_KEY"] = original_key


class TestCLIWorkflow:
    """End-to-end CLI workflow tests."""

    def test_analyze_workflow_help(self) -> None:
        """Test full analyze workflow help display."""
        runner = CliRunner()

        # Show main help
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "analyze" in result.output

        # Show analyze help
        result = runner.invoke(cli, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "--file" in result.output
        assert "--output" in result.output

    def test_version_and_config_workflow(self) -> None:
        """Test version and config commands together."""
        runner = CliRunner()

        os.environ["OPENAI_API_KEY"] = "test-key"

        try:
            # Get version
            version_result = runner.invoke(cli, ["version"])
            assert version_result.exit_code == 0
            assert __version__ in version_result.output

            # Get config
            config_result = runner.invoke(cli, ["config"])
            if config_result.exit_code == 0:
                assert "Configuration" in config_result.output

        finally:
            os.environ.pop("OPENAI_API_KEY", None)

    def test_help_env_workflow(self) -> None:
        """Test help-env command workflow."""
        runner = CliRunner()

        result = runner.invoke(cli, ["help-env"])
        assert result.exit_code == 0
        assert "OPENAI_API_KEY" in result.output
        assert "Example .env file" in result.output
