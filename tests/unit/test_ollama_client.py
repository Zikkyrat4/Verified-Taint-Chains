"""Unit tests for OllamaClient."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.stage1_llm_inference.ollama_client import OllamaClient
from src.core.exceptions import LLMError


@pytest.mark.asyncio
class TestOllamaClient:
    """Test suite for OllamaClient."""

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    def test_initialization_success(self, mock_ollama):
        """Test successful client initialization."""
        mock_ollama.AsyncClient = MagicMock()

        client = OllamaClient(model="llama3:latest", base_url="http://localhost:11434")

        assert client.model == "llama3:latest"
        assert client.base_url == "http://localhost:11434"
        mock_ollama.AsyncClient.assert_called_once_with(host="http://localhost:11434")

    @patch("src.stage1_llm_inference.ollama_client.ollama", None)
    def test_initialization_missing_package(self):
        """Test initialization fails when ollama package not installed."""
        with pytest.raises(ImportError, match="ollama package is required"):
            OllamaClient()

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    def test_initialization_empty_base_url(self, mock_ollama):
        """Test initialization fails with empty base URL."""
        with pytest.raises(ValueError, match="base_url cannot be empty"):
            OllamaClient(base_url="")

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    def test_initialization_default_values(self, mock_ollama):
        """Test initialization with default values."""
        mock_ollama.AsyncClient = MagicMock()

        client = OllamaClient()

        assert client.model == "llama3:latest"
        assert client.base_url == "http://localhost:11434"

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    async def test_verify_connection_success(self, mock_ollama):
        """Test successful connection verification."""
        mock_client = AsyncMock()
        mock_client.list = AsyncMock(
            return_value={"models": [{"name": "llama3:latest"}, {"name": "mistral:latest"}]}
        )
        mock_ollama.AsyncClient = MagicMock(return_value=mock_client)

        client = OllamaClient(model="llama3:latest")
        await client._verify_connection()

        mock_client.list.assert_called_once()

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    async def test_verify_connection_model_not_found(self, mock_ollama):
        """Test connection verification warns when model not available."""
        mock_client = AsyncMock()
        mock_client.list = AsyncMock(return_value={"models": [{"name": "mistral:latest"}]})
        mock_ollama.AsyncClient = MagicMock(return_value=mock_client)

        client = OllamaClient(model="llama3:latest")

        # Should log warning but not raise exception
        await client._verify_connection()

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    async def test_verify_connection_failure(self, mock_ollama):
        """Test connection verification handles errors gracefully."""
        mock_client = AsyncMock()
        mock_client.list = AsyncMock(side_effect=Exception("Connection refused"))
        mock_ollama.AsyncClient = MagicMock(return_value=mock_client)

        client = OllamaClient()

        # Should log warning but not raise exception
        await client._verify_connection()

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    async def test_make_api_call_success(self, mock_ollama):
        """Test successful Ollama API call."""
        mock_client = AsyncMock()
        mock_client.chat = AsyncMock(
            return_value={"message": {"content": "test response from ollama"}}
        )
        mock_ollama.AsyncClient = MagicMock(return_value=mock_client)

        client = OllamaClient()

        messages = [{"role": "user", "content": "test"}]
        result = await client._make_api_call(messages, temperature=0.5, max_tokens=200)

        assert result == "test response from ollama"
        mock_client.chat.assert_called_once_with(
            model="llama3:latest",
            messages=messages,
            options={"temperature": 0.5, "num_predict": 200},
            format="json",
        )

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    async def test_make_api_call_empty_response(self, mock_ollama):
        """Test API call fails with empty response."""
        mock_client = AsyncMock()
        mock_client.chat = AsyncMock(return_value={"message": {"content": ""}})
        mock_ollama.AsyncClient = MagicMock(return_value=mock_client)

        client = OllamaClient()

        messages = [{"role": "user", "content": "test"}]

        with pytest.raises(LLMError, match="Ollama returned empty response"):
            await client._make_api_call(messages, temperature=0.0, max_tokens=100)

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    async def test_make_api_call_connection_error(self, mock_ollama):
        """Test API call handles connection errors."""
        mock_client = AsyncMock()
        mock_client.chat = AsyncMock(side_effect=Exception("Connection refused"))
        mock_ollama.AsyncClient = MagicMock(return_value=mock_client)

        client = OllamaClient()

        messages = [{"role": "user", "content": "test"}]

        with pytest.raises(LLMError, match="Ollama API call failed"):
            await client._make_api_call(messages, temperature=0.0, max_tokens=100)

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    def test_should_retry_connection_error(self, mock_ollama):
        """Test retry logic for connection errors."""
        mock_ollama.AsyncClient = MagicMock()
        client = OllamaClient()

        error = Exception("connection refused")
        assert client._should_retry(error) is True

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    def test_should_retry_timeout_error(self, mock_ollama):
        """Test retry logic for timeout errors."""
        mock_ollama.AsyncClient = MagicMock()
        client = OllamaClient()

        error = Exception("timeout occurred")
        assert client._should_retry(error) is True

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    def test_should_retry_unavailable_error(self, mock_ollama):
        """Test retry logic for service unavailable errors."""
        mock_ollama.AsyncClient = MagicMock()
        client = OllamaClient()

        error = Exception("503 service unavailable")
        assert client._should_retry(error) is True

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    def test_should_retry_status_code_503(self, mock_ollama):
        """Test retry logic for errors with status_code attribute."""
        mock_ollama.AsyncClient = MagicMock()
        client = OllamaClient()

        error = Exception("Service unavailable")
        error.status_code = 503
        assert client._should_retry(error) is True

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    def test_should_retry_status_code_429(self, mock_ollama):
        """Test retry logic for rate limit errors."""
        mock_ollama.AsyncClient = MagicMock()
        client = OllamaClient()

        error = Exception("Too many requests")
        error.status_code = 429
        assert client._should_retry(error) is True

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    def test_should_retry_other_error(self, mock_ollama):
        """Test retry logic for non-retryable errors."""
        mock_ollama.AsyncClient = MagicMock()
        client = OllamaClient()

        error = ValueError("Model not found")
        assert client._should_retry(error) is False

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    async def test_chat_completion_with_retry(self, mock_ollama):
        """Test chat completion retries on connection error."""
        mock_client = AsyncMock()
        mock_client.chat = AsyncMock(
            side_effect=[
                Exception("connection refused"),
                {"message": {"content": "success after retry"}},
            ]
        )
        mock_ollama.AsyncClient = MagicMock(return_value=mock_client)

        client = OllamaClient()

        messages = [{"role": "user", "content": "test"}]
        result = await client.chat_completion(messages, max_retries=3)

        assert result == "success after retry"
        assert mock_client.chat.call_count == 2

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    async def test_analyze_code_full_flow(self, mock_ollama):
        """Test full analyze_code flow with Ollama."""
        mock_client = AsyncMock()
        mock_client.chat = AsyncMock(
            return_value={"message": {"content": '{"issues": ["XSS vulnerability"]}'}}
        )
        mock_ollama.AsyncClient = MagicMock(return_value=mock_client)

        client = OllamaClient(model="codellama:latest")

        result = await client.analyze_code("<script>alert('xss')</script>", "Analyze security")

        assert result == {"issues": ["XSS vulnerability"]}
        assert mock_client.chat.call_count == 1

        # Verify system message is included
        call_args = mock_client.chat.call_args[1]
        messages = call_args["messages"]
        assert any(msg["role"] == "system" for msg in messages)

    @patch("src.stage1_llm_inference.ollama_client.ollama")
    async def test_make_api_call_passes_json_format(self, mock_ollama):
        """Test that format='json' is passed to Ollama chat call."""
        mock_client = AsyncMock()
        mock_client.chat = AsyncMock(
            return_value={"message": {"content": '{"result": "ok"}'}}
        )
        mock_ollama.AsyncClient = MagicMock(return_value=mock_client)

        client = OllamaClient()

        messages = [{"role": "user", "content": "test"}]
        await client._make_api_call(messages, temperature=0.0, max_tokens=100)

        # Verify format="json" is in the call
        call_kwargs = mock_client.chat.call_args[1]
        assert call_kwargs["format"] == "json"
