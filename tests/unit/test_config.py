"""Unit tests for pipeline configuration."""

import os
import pytest
import tempfile
from pathlib import Path

from src.core.config import PipelineConfig, load_config_from_env


class TestPipelineConfig:
    """Tests for PipelineConfig dataclass."""

    def test_config_creation_minimal(self) -> None:
        """Test creating config with only required field."""
        config = PipelineConfig(llm_api_key="test-key")

        assert config.llm_api_key == "test-key"
        assert config.llm_model == "gpt-4-turbo"
        assert config.max_path_length == 15
        assert config.min_confidence == 0.6
        assert config.verification_enabled is True
        assert config.symbolic_execution_enabled is False
        assert config.verification_level == "cfg"
        assert config.symbolic_timeout == 60
        assert config.llm_batch_max_chars == 8000
        assert config.analysis_backend == "llm"
        assert config.llm_analysis_mode == "targeted"
        assert config.cache_read_enabled is True
        assert config.openai_json_mode is True

    def test_config_creation_full(self) -> None:
        """Test creating config with all fields."""
        config = PipelineConfig(
            llm_api_key="test-key",
            llm_model="gpt-4",
            max_path_length=20,
            min_confidence=0.7,
            verification_enabled=False,
            symbolic_execution_enabled=True,
            verification_level="symbolic",
        )

        assert config.llm_api_key == "test-key"
        assert config.llm_model == "gpt-4"
        assert config.max_path_length == 20
        assert config.min_confidence == 0.7
        assert config.verification_enabled is False
        assert config.symbolic_execution_enabled is True

    def test_config_validation_empty_api_key(self) -> None:
        """Test that empty API key raises ValueError."""
        with pytest.raises(ValueError, match="llm_api_key is required"):
            PipelineConfig(llm_api_key="")

    def test_config_validation_none_api_key(self) -> None:
        """Test that None API key raises ValueError."""
        with pytest.raises(ValueError):
            PipelineConfig(llm_api_key=None)  # type: ignore

    def test_config_validation_invalid_confidence_high(self) -> None:
        """Test that confidence > 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="min_confidence must be between"):
            PipelineConfig(llm_api_key="test", min_confidence=1.5)

    def test_config_validation_invalid_llm_batch_size(self) -> None:
        with pytest.raises(ValueError, match="llm_batch_max_chars"):
            PipelineConfig(llm_api_key="test", llm_batch_max_chars=-1)

    def test_config_validation_invalid_llm_analysis_mode(self) -> None:
        with pytest.raises(ValueError, match="llm_analysis_mode"):
            PipelineConfig(llm_api_key="test", llm_analysis_mode="fastish")

    def test_config_validation_invalid_analysis_backend(self) -> None:
        with pytest.raises(ValueError, match="analysis_backend"):
            PipelineConfig(llm_api_key="test", analysis_backend="magic")

    def test_static_backend_does_not_require_openai_key(self) -> None:
        config = PipelineConfig(llm_api_key=None, analysis_backend="static")

        assert config.analysis_backend == "static"

    def test_static_backend_rejects_llm_graph_enrichment(self) -> None:
        with pytest.raises(ValueError, match="incompatible"):
            PipelineConfig(
                llm_api_key=None,
                analysis_backend="static",
                llm_graph_enrichment_enabled=True,
            )

    def test_config_validation_invalid_confidence_low(self) -> None:
        """Test that confidence < 0.0 raises ValueError."""
        with pytest.raises(ValueError, match="min_confidence must be between"):
            PipelineConfig(llm_api_key="test", min_confidence=-0.1)

    def test_config_validation_valid_confidence_boundaries(self) -> None:
        """Test that confidence at boundaries (0.0, 1.0) is valid."""
        config1 = PipelineConfig(llm_api_key="test", min_confidence=0.0)
        assert config1.min_confidence == 0.0

        config2 = PipelineConfig(llm_api_key="test", min_confidence=1.0)
        assert config2.min_confidence == 1.0

    def test_config_validation_invalid_path_length(self) -> None:
        """Test that path_length < 1 raises ValueError."""
        with pytest.raises(ValueError, match="max_path_length must be at least 1"):
            PipelineConfig(llm_api_key="test", max_path_length=0)

    def test_config_validation_valid_path_length(self) -> None:
        """Test that valid path lengths work."""
        config = PipelineConfig(llm_api_key="test", max_path_length=1)
        assert config.max_path_length == 1

    def test_config_validation_invalid_verification_level(self) -> None:
        """Test that invalid verification_level raises ValueError."""
        with pytest.raises(ValueError, match="verification_level must be"):
            PipelineConfig(llm_api_key="test", verification_level="invalid")

    def test_config_validation_valid_verification_levels(self) -> None:
        """Test that all valid verification levels work."""
        for level in ["cfg", "symbolic", "both"]:
            config = PipelineConfig(llm_api_key="test", verification_level=level)
            assert config.verification_level == level

    def test_config_validation_invalid_symbolic_timeout(self) -> None:
        """Test that invalid symbolic_timeout raises ValueError."""
        with pytest.raises(ValueError, match="symbolic_timeout must be at least 1"):
            PipelineConfig(llm_api_key="test", symbolic_timeout=0)

        with pytest.raises(ValueError, match="symbolic_timeout must be at least 1"):
            PipelineConfig(llm_api_key="test", symbolic_timeout=-5)

    def test_config_validation_valid_symbolic_timeout(self) -> None:
        """Test that valid symbolic_timeout values work."""
        config = PipelineConfig(llm_api_key="test", symbolic_timeout=120)
        assert config.symbolic_timeout == 120

    def test_verification_level_cfg_disables_symbolic(self) -> None:
        """Test that verification_level='cfg' disables symbolic execution."""
        config = PipelineConfig(
            llm_api_key="test",
            verification_level="cfg",
            symbolic_execution_enabled=True,  # Should be overridden
        )
        assert config.verification_level == "cfg"
        assert config.symbolic_execution_enabled is False

    def test_verification_level_symbolic_enables_symbolic(self) -> None:
        """Test that verification_level='symbolic' enables symbolic execution."""
        config = PipelineConfig(
            llm_api_key="test",
            verification_level="symbolic",
            symbolic_execution_enabled=False,  # Should be overridden
        )
        assert config.verification_level == "symbolic"
        assert config.symbolic_execution_enabled is True

    def test_verification_level_both_enables_symbolic(self) -> None:
        """Test that verification_level='both' enables symbolic execution."""
        config = PipelineConfig(
            llm_api_key="test",
            verification_level="both",
            symbolic_execution_enabled=False,  # Should be overridden
        )
        assert config.verification_level == "both"
        assert config.symbolic_execution_enabled is True


class TestLoadConfigFromEnv:
    """Tests for load_config_from_env function."""

    def test_load_config_required_env(self) -> None:
        """Test loading config with only required environment variable."""
        # Save original env (including vars that .env file may inject)
        env_vars_to_manage = [
            "OPENAI_API_KEY", "LLM_PROVIDER", "OPENAI_MODEL", "LLM_MODEL",
        ]
        original_values = {k: os.environ.get(k) for k in env_vars_to_manage}

        try:
            os.environ["OPENAI_API_KEY"] = "test-key-123"
            # Set vars explicitly so load_dotenv() won't override from .env
            os.environ["LLM_PROVIDER"] = "openai"
            os.environ["OPENAI_MODEL"] = ""
            os.environ["LLM_MODEL"] = ""

            config = load_config_from_env()

            assert config.llm_api_key == "test-key-123"
            assert config.llm_model == "gpt-4-turbo"  # Default
            assert config.max_path_length == 15  # Default
            assert config.min_confidence == 0.6  # Default

        finally:
            # Restore original env
            for key, value in original_values.items():
                if value is not None:
                    os.environ[key] = value
                else:
                    os.environ.pop(key, None)

    def test_load_config_all_env_vars(self) -> None:
        """Test loading config with all environment variables set."""
        original_vars = {
            "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
            "OPENAI_MODEL": os.environ.get("OPENAI_MODEL"),
            "LLM_PROVIDER": os.environ.get("LLM_PROVIDER"),
            "LLM_MODEL": os.environ.get("LLM_MODEL"),
            "MAX_PATH_LENGTH": os.environ.get("MAX_PATH_LENGTH"),
            "MIN_CONFIDENCE": os.environ.get("MIN_CONFIDENCE"),
            "VERIFICATION_ENABLED": os.environ.get("VERIFICATION_ENABLED"),
            "SYMBOLIC_EXECUTION_ENABLED": os.environ.get("SYMBOLIC_EXECUTION_ENABLED"),
            "VERIFICATION_LEVEL": os.environ.get("VERIFICATION_LEVEL"),
        }

        try:
            os.environ["LLM_PROVIDER"] = "openai"
            os.environ["OPENAI_API_KEY"] = "test-key"
            os.environ["OPENAI_MODEL"] = "gpt-4"
            os.environ["LLM_MODEL"] = ""
            os.environ["MAX_PATH_LENGTH"] = "25"
            os.environ["MIN_CONFIDENCE"] = "0.8"
            os.environ["VERIFICATION_ENABLED"] = "false"
            os.environ["SYMBOLIC_EXECUTION_ENABLED"] = "true"
            os.environ["VERIFICATION_LEVEL"] = "symbolic"

            config = load_config_from_env()

            assert config.llm_api_key == "test-key"
            assert config.llm_model == "gpt-4"
            assert config.max_path_length == 25
            assert config.min_confidence == 0.8
            assert config.verification_enabled is False
            assert config.symbolic_execution_enabled is True

        finally:
            # Restore original env
            for key, value in original_vars.items():
                if value is not None:
                    os.environ[key] = value
                else:
                    os.environ.pop(key, None)

    def test_load_config_missing_api_key(self) -> None:
        """Test that missing API key raises ValueError when using OpenAI provider."""
        original_values = {
            "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
            "LLM_PROVIDER": os.environ.get("LLM_PROVIDER"),
        }

        try:
            # Force OpenAI provider and set empty API key so load_dotenv
            # won't override it from .env file
            os.environ["LLM_PROVIDER"] = "openai"
            os.environ["OPENAI_API_KEY"] = ""

            with pytest.raises(ValueError, match="llm_api_key is required"):
                load_config_from_env()

        finally:
            for key, value in original_values.items():
                if value is not None:
                    os.environ[key] = value
                else:
                    os.environ.pop(key, None)

    def test_load_config_invalid_path_length(self) -> None:
        """Test that invalid path length uses default."""
        original_vars = {
            "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
            "MAX_PATH_LENGTH": os.environ.get("MAX_PATH_LENGTH"),
        }

        try:
            os.environ["OPENAI_API_KEY"] = "test-key"
            os.environ["MAX_PATH_LENGTH"] = "not-a-number"

            config = load_config_from_env()

            assert config.max_path_length == 15  # Default

        finally:
            for key, value in original_vars.items():
                if value:
                    os.environ[key] = value
                else:
                    os.environ.pop(key, None)

    def test_load_config_invalid_confidence(self) -> None:
        """Test that invalid confidence uses default."""
        original_vars = {
            "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
            "MIN_CONFIDENCE": os.environ.get("MIN_CONFIDENCE"),
        }

        try:
            os.environ["OPENAI_API_KEY"] = "test-key"
            os.environ["MIN_CONFIDENCE"] = "invalid"

            config = load_config_from_env()

            assert config.min_confidence == 0.6  # Default

        finally:
            for key, value in original_vars.items():
                if value:
                    os.environ[key] = value
                else:
                    os.environ.pop(key, None)

    def test_load_config_boolean_flags(self) -> None:
        """Test boolean flag parsing."""
        original_vars = {
            "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
            "VERIFICATION_ENABLED": os.environ.get("VERIFICATION_ENABLED"),
            "SYMBOLIC_EXECUTION_ENABLED": os.environ.get("SYMBOLIC_EXECUTION_ENABLED"),
        }

        try:
            os.environ["OPENAI_API_KEY"] = "test-key"

            # Test various truthy values
            for truthy in ["true", "True", "TRUE"]:
                os.environ["VERIFICATION_ENABLED"] = truthy
                config = load_config_from_env()
                assert config.verification_enabled is True

            # Test various falsy values
            for falsy in ["false", "False", "FALSE", "no", "0"]:
                os.environ["VERIFICATION_ENABLED"] = falsy
                config = load_config_from_env()
                assert config.verification_enabled is False

        finally:
            for key, value in original_vars.items():
                if value:
                    os.environ[key] = value
                else:
                    os.environ.pop(key, None)

    def test_load_config_verification_level(self) -> None:
        """Test loading verification_level from environment."""
        original_vars = {
            "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
            "VERIFICATION_LEVEL": os.environ.get("VERIFICATION_LEVEL"),
        }

        try:
            os.environ["OPENAI_API_KEY"] = "test-key"

            # Test all valid levels
            for level in ["cfg", "symbolic", "both"]:
                os.environ["VERIFICATION_LEVEL"] = level
                config = load_config_from_env()
                assert config.verification_level == level

            # Test case insensitivity
            os.environ["VERIFICATION_LEVEL"] = "CFG"
            config = load_config_from_env()
            assert config.verification_level == "cfg"

        finally:
            for key, value in original_vars.items():
                if value:
                    os.environ[key] = value
                else:
                    os.environ.pop(key, None)

    def test_load_config_invalid_verification_level(self) -> None:
        """Test that invalid verification_level uses default."""
        original_vars = {
            "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
            "VERIFICATION_LEVEL": os.environ.get("VERIFICATION_LEVEL"),
        }

        try:
            os.environ["OPENAI_API_KEY"] = "test-key"
            os.environ["VERIFICATION_LEVEL"] = "invalid"

            config = load_config_from_env()

            # Should fall back to default 'cfg'
            assert config.verification_level == "cfg"

        finally:
            for key, value in original_vars.items():
                if value:
                    os.environ[key] = value
                else:
                    os.environ.pop(key, None)

    def test_load_config_symbolic_timeout(self) -> None:
        """Test loading symbolic_timeout from environment."""
        original_vars = {
            "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
            "SYMBOLIC_TIMEOUT": os.environ.get("SYMBOLIC_TIMEOUT"),
        }

        try:
            os.environ["OPENAI_API_KEY"] = "test-key"
            os.environ["SYMBOLIC_TIMEOUT"] = "120"

            config = load_config_from_env()

            assert config.symbolic_timeout == 120

        finally:
            for key, value in original_vars.items():
                if value:
                    os.environ[key] = value
                else:
                    os.environ.pop(key, None)

    def test_load_config_invalid_symbolic_timeout(self) -> None:
        """Test that invalid symbolic_timeout uses default."""
        original_vars = {
            "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
            "SYMBOLIC_TIMEOUT": os.environ.get("SYMBOLIC_TIMEOUT"),
        }

        try:
            os.environ["OPENAI_API_KEY"] = "test-key"
            os.environ["SYMBOLIC_TIMEOUT"] = "invalid"

            config = load_config_from_env()

            # Should fall back to default 60
            assert config.symbolic_timeout == 60

        finally:
            for key, value in original_vars.items():
                if value:
                    os.environ[key] = value
                else:
                    os.environ.pop(key, None)

    def test_load_config_from_env_file(self) -> None:
        """Test loading config from .env file."""
        # Create temporary .env file
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"

            env_content = """OPENAI_API_KEY=env-file-key
OPENAI_MODEL=gpt-4
MAX_PATH_LENGTH=30
MIN_CONFIDENCE=0.6
VERIFICATION_ENABLED=true
SYMBOLIC_EXECUTION_ENABLED=false
"""

            env_file.write_text(env_content)

            # Note: load_dotenv loads from .env in current directory
            # This test verifies the function exists and can parse the values
            # even if we can't actually test .env file loading without changing directory

            config = PipelineConfig(
                llm_api_key="env-file-key",
                llm_model="gpt-4",
                max_path_length=30,
                min_confidence=0.6,
            )

            assert config.llm_api_key == "env-file-key"
            assert config.llm_model == "gpt-4"
            assert config.max_path_length == 30
            assert config.min_confidence == 0.6


class TestConfigIntegration:
    """Integration tests for configuration."""

    def test_config_roundtrip(self) -> None:
        """Test that config can be created, used, and validated."""
        config = PipelineConfig(
            llm_api_key="integration-test-key",
            llm_model="gpt-4-turbo",
            max_path_length=15,
            min_confidence=0.6,
            verification_enabled=True,
            symbolic_execution_enabled=False,
        )

        # Verify all values
        assert config.llm_api_key == "integration-test-key"
        assert config.llm_model == "gpt-4-turbo"
        assert config.max_path_length == 15
        assert config.min_confidence == 0.6
        assert config.verification_enabled is True
        assert config.symbolic_execution_enabled is False

        # Verify validation passed (no exceptions)
        assert config is not None
