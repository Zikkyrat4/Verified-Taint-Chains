"""Unit tests for LLM client.

Tests for SimpleLLMClient (deprecated, maintained for backward compatibility).
"""

import json
import pytest
import warnings
from unittest.mock import AsyncMock, MagicMock, patch

from src.stage1_llm_inference.llm_client import SimpleLLMClient
from src.stage1_llm_inference.openai_client import OpenAIClient
from src.core.exceptions import LLMError, ParsingError


class TestSimpleLLMClientDeprecation:
    """Tests for SimpleLLMClient deprecation."""

    def test_deprecation_warning_shown(self) -> None:
        """Test that SimpleLLMClient shows deprecation warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            client = SimpleLLMClient(api_key="test-key-123")

            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "SimpleLLMClient is deprecated" in str(w[0].message)
            assert "OpenAIClient" in str(w[0].message)

    def test_inherits_from_openai_client(self) -> None:
        """Test that SimpleLLMClient inherits from OpenAIClient."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key-123")

            assert isinstance(client, OpenAIClient)


class TestSimpleLLMClientInit:
    """Tests for SimpleLLMClient initialization."""

    def test_init_with_valid_credentials(self) -> None:
        """Test initializing with valid API key and model."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key-123", model="gpt-4")
            assert client.model == "gpt-4"

    def test_init_with_default_model(self) -> None:
        """Test that default model is gpt-4-turbo."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key-123")
            assert client.model == "gpt-4-turbo"

    def test_init_with_empty_api_key(self) -> None:
        """Test that empty API key raises ValueError."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with pytest.raises(ValueError, match="api_key cannot be empty"):
                SimpleLLMClient(api_key="")

    def test_init_stores_client(self) -> None:
        """Test that AsyncOpenAI client is stored."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key")
            assert client.client is not None


class TestChatCompletion:
    """Tests for chat_completion method."""

    @pytest.mark.asyncio
    async def test_chat_completion_with_empty_messages(self) -> None:
        """Test that empty messages list raises ValueError."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key")
            with pytest.raises(ValueError, match="messages list cannot be empty"):
                await client.chat_completion([])

    @pytest.mark.asyncio
    async def test_chat_completion_success(self) -> None:
        """Test successful chat completion."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key")
            messages = [{"role": "user", "content": "Hello"}]

            # Mock the API response
            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content="Hello back"))]

            with patch.object(client.client.chat.completions, "create", new_callable=AsyncMock) as mock_create:
                mock_create.return_value = mock_response
                result = await client.chat_completion(messages)

            assert result == "Hello back"
            mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_chat_completion_empty_response(self) -> None:
        """Test handling of empty response."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key")
            messages = [{"role": "user", "content": "Hello"}]

            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content=None))]

            with patch.object(client.client.chat.completions, "create", new_callable=AsyncMock) as mock_create:
                mock_create.return_value = mock_response
                with pytest.raises(LLMError, match="content is empty"):
                    await client.chat_completion(messages)

            assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_chat_completion_with_custom_params(self) -> None:
        """Test chat completion with custom temperature and max_tokens."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key")
            messages = [{"role": "user", "content": "Test"}]

            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content="Response"))]

            with patch.object(client.client.chat.completions, "create", new_callable=AsyncMock) as mock_create:
                mock_create.return_value = mock_response
                result = await client.chat_completion(
                    messages, temperature=0.7, max_tokens=1000
                )

            assert result == "Response"
            mock_create.assert_called_once()
            call_kwargs = mock_create.call_args.kwargs
            assert call_kwargs["temperature"] == 0.7
            assert call_kwargs["max_tokens"] == 1000


class TestAnalyzeCode:
    """Tests for analyze_code method."""

    @pytest.mark.asyncio
    async def test_analyze_code_empty_code(self) -> None:
        """Test that empty code raises ValueError."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key")
            with pytest.raises(ValueError, match="code cannot be empty"):
                await client.analyze_code("", "analyze this")

    @pytest.mark.asyncio
    async def test_analyze_code_empty_prompt(self) -> None:
        """Test that empty prompt raises ValueError."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key")
            with pytest.raises(ValueError, match="prompt cannot be empty"):
                await client.analyze_code("x = 1", "")

    @pytest.mark.asyncio
    async def test_analyze_code_success(self) -> None:
        """Test successful code analysis with JSON response."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key")
            code = "x = request.args.get('q')"
            prompt = "Find sources"

            response_data = {"sources": [{"name": "x", "type": "user_input"}]}
            response_json = json.dumps(response_data)

            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content=response_json))]

            with patch.object(client.client.chat.completions, "create", new_callable=AsyncMock) as mock_create:
                mock_create.return_value = mock_response
                result = await client.analyze_code(code, prompt)

            assert result == response_data
            assert "sources" in result

    @pytest.mark.asyncio
    async def test_analyze_code_json_in_markdown(self) -> None:
        """Test code analysis with JSON wrapped in markdown code blocks."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key")
            code = "x = 1"
            prompt = "analyze"

            response_data = {"result": "analyzed"}
            response_text = f"```json\n{json.dumps(response_data)}\n```"

            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content=response_text))]

            with patch.object(client.client.chat.completions, "create", new_callable=AsyncMock) as mock_create:
                mock_create.return_value = mock_response
                result = await client.analyze_code(code, prompt)

            assert result == response_data

    @pytest.mark.asyncio
    async def test_analyze_code_invalid_json(self) -> None:
        """Test that invalid JSON response raises ParsingError."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key")
            code = "x = 1"
            prompt = "analyze"

            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content="Not JSON"))]

            with patch.object(client.client.chat.completions, "create", new_callable=AsyncMock) as mock_create:
                mock_create.return_value = mock_response
                with pytest.raises(ParsingError):
                    await client.analyze_code(code, prompt)


class TestRetryLogic:
    """Tests for retry logic with exponential backoff."""

    @pytest.mark.asyncio
    async def test_retry_on_rate_limit(self) -> None:
        """Test that rate limit errors trigger retries."""
        from openai import RateLimitError

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key")
            messages = [{"role": "user", "content": "Test"}]

            # First attempt fails with rate limit, second succeeds
            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content="Success"))]

            with patch.object(
                client.client.chat.completions, "create", new_callable=AsyncMock
            ) as mock_create:
                mock_create.side_effect = [
                    RateLimitError("Rate limited", response=MagicMock(), body=None),
                    mock_response,
                ]

                result = await client.chat_completion(messages, max_retries=2)

            assert result == "Success"
            assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_retry_exhaustion(self) -> None:
        """Test that exhausted retries raise LLMError."""
        from openai import RateLimitError

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client = SimpleLLMClient(api_key="test-key")
            messages = [{"role": "user", "content": "Test"}]

            with patch.object(
                client.client.chat.completions, "create", new_callable=AsyncMock
            ) as mock_create:
                mock_create.side_effect = RateLimitError(
                    "Rate limited", response=MagicMock(), body=None
                )

                with pytest.raises(LLMError):
                    await client.chat_completion(messages, max_retries=2)

            assert mock_create.call_count == 2
