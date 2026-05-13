"""Unit tests for LLM client factory."""

import pytest
from unittest.mock import patch, MagicMock

from src.stage1_llm_inference.client_factory import create_llm_client, LLMProvider
from src.stage1_llm_inference.openai_client import OpenAIClient
from src.stage1_llm_inference.ollama_client import OllamaClient
from src.core.config import PipelineConfig


class TestClientFactory:
    """Test suite for create_llm_client factory function."""

    def test_create_openai_client(self):
        """Test factory creates OpenAI client."""
        config = PipelineConfig(
            llm_provider="openai",
            llm_api_key="sk-test123",
            llm_model="gpt-4",
        )

        client = create_llm_client(config)

        assert isinstance(client, OpenAIClient)
        assert client.model == "gpt-4"

    def test_create_openai_client_missing_api_key(self):
        """Test config validation fails when OpenAI API key missing."""
        # Validation happens in PipelineConfig.__post_init__, not in factory
        with pytest.raises(ValueError, match="llm_api_key is required"):
            PipelineConfig(
                llm_provider="openai",
                llm_api_key=None,
                llm_model="gpt-4",
            )

    def test_create_openai_client_empty_api_key(self):
        """Test config validation fails when OpenAI API key empty."""
        # Validation happens in PipelineConfig.__post_init__, not in factory
        with pytest.raises(ValueError, match="llm_api_key is required"):
            PipelineConfig(
                llm_provider="openai",
                llm_api_key="",
                llm_model="gpt-4",
            )

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    def test_create_ollama_client(self, mock_ollama):
        """Test factory creates Ollama client."""
        mock_ollama.AsyncClient = MagicMock()

        config = PipelineConfig(
            llm_provider="ollama",
            llm_model="llama3:latest",
            ollama_base_url="http://localhost:11434",
        )

        client = create_llm_client(config)

        assert isinstance(client, OllamaClient)
        assert client.model == "llama3:latest"
        assert client.base_url == "http://localhost:11434"

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    def test_create_ollama_client_custom_url(self, mock_ollama):
        """Test factory creates Ollama client with custom URL."""
        mock_ollama.AsyncClient = MagicMock()

        config = PipelineConfig(
            llm_provider="ollama",
            llm_model="mistral:latest",
            ollama_base_url="http://custom-host:8080",
        )

        client = create_llm_client(config)

        assert isinstance(client, OllamaClient)
        assert client.base_url == "http://custom-host:8080"

    def test_create_client_unsupported_provider(self):
        """Test config validation fails with unsupported provider."""
        # Validation happens in PipelineConfig.__post_init__, not in factory
        with pytest.raises(ValueError, match="llm_provider must be"):
            PipelineConfig(
                llm_provider="unknown",
                llm_api_key="test",
                llm_model="test",
            )

    def test_create_client_case_insensitive(self):
        """Test factory handles provider names case-insensitively."""
        config = PipelineConfig(
            llm_provider="OPENAI",
            llm_api_key="sk-test123",
            llm_model="gpt-4",
        )

        client = create_llm_client(config)

        assert isinstance(client, OpenAIClient)

    def test_llm_provider_enum_values(self):
        """Test LLMProvider enum has correct values."""
        assert LLMProvider.OPENAI == "openai"
        assert LLMProvider.OLLAMA == "ollama"

    def test_llm_provider_enum_completeness(self):
        """Test all LLMProvider values are handled by factory."""
        # Test that factory can handle all enum values
        for provider in LLMProvider:
            if provider == LLMProvider.OPENAI:
                config = PipelineConfig(
                    llm_provider=provider.value,
                    llm_api_key="sk-test",
                    llm_model="gpt-4",
                )
                client = create_llm_client(config)
                assert isinstance(client, OpenAIClient)
            elif provider == LLMProvider.OLLAMA:
                with patch("src.stage1_llm_inference.ollama_client.ollama") as mock_ollama:
                    mock_ollama.AsyncClient = MagicMock()
                    config = PipelineConfig(
                        llm_provider=provider.value,
                        llm_model="llama3:latest",
                    )
                    client = create_llm_client(config)
                    assert isinstance(client, OllamaClient)
