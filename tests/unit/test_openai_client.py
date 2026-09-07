"""Unit tests for OpenAIClient."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from openai import RateLimitError, APITimeoutError

from src.stage1_llm_inference.openai_client import OpenAIClient
from src.core.exceptions import (
    EmptyLLMResponseError,
    LLMError,
    TruncatedLLMResponseError,
)


@pytest.mark.asyncio
class TestOpenAIClient:
    """Test suite for OpenAIClient."""

    def test_initialization_success(self):
        """Test successful client initialization."""
        client = OpenAIClient(api_key="sk-test123", model="gpt-4")
        assert client.model == "gpt-4"
        assert client.client is not None

    def test_initialization_empty_api_key(self):
        """Test initialization fails with empty API key."""
        with pytest.raises(ValueError, match="api_key cannot be empty"):
            OpenAIClient(api_key="")

    def test_initialization_default_model(self):
        """Test initialization with default model."""
        client = OpenAIClient(api_key="sk-test123")
        assert client.model == "gpt-4-turbo"

    def test_initialization_default_base_url(self):
        """Without an override, the official OpenAI endpoint is used."""
        client = OpenAIClient(api_key="sk-test123")
        assert client.base_url is None
        assert "api.openai.com" in str(client.client.base_url)

    def test_initialization_custom_base_url(self):
        """A custom base_url is forwarded to the underlying AsyncOpenAI client."""
        client = OpenAIClient(
            api_key="sk-test123", base_url="https://proxy.example.com/v1"
        )
        assert client.base_url == "https://proxy.example.com/v1"
        assert "proxy.example.com" in str(client.client.base_url)

    def test_initialization_blank_base_url_falls_back(self):
        """An empty base_url is treated as unset (default endpoint)."""
        client = OpenAIClient(api_key="sk-test123", base_url="")
        assert client.base_url is None
        assert "api.openai.com" in str(client.client.base_url)

    async def test_make_api_call_success(self):
        """Test successful OpenAI API call."""
        client = OpenAIClient(api_key="sk-test123")

        # Mock OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "test response"

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response

            messages = [{"role": "user", "content": "test"}]
            result = await client._make_api_call(messages, temperature=0.0, max_tokens=100)

            assert result == "test response"
            mock_create.assert_called_once_with(
                model="gpt-4-turbo",
                messages=messages,
                temperature=0.0,
                max_tokens=100,
                response_format={"type": "json_object"},
            )

    async def test_glm_disables_thinking_by_default(self):
        client = OpenAIClient(api_key="sk-test123", model="glm-5.3-flash")
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "{}"

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response
            await client._make_api_call([], temperature=0.0, max_tokens=100)

        assert mock_create.call_args.kwargs["extra_body"] == {
            "chat_template_kwargs": {"enable_thinking": False}
        }

    async def test_make_api_call_empty_response(self):
        """Test API call with empty response content."""
        client = OpenAIClient(api_key="sk-test123")

        # Mock OpenAI response with None content
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = None

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response

            messages = [{"role": "user", "content": "test"}]
            with pytest.raises(EmptyLLMResponseError, match="content is empty"):
                await client._make_api_call(
                    messages, temperature=0.0, max_tokens=100
                )

    async def test_make_api_call_uses_json_from_reasoning_content(self):
        client = OpenAIClient(api_key="sk-test123")
        message = MagicMock()
        message.content = None
        message.reasoning_content = 'analysis... {"sources": [], "sinks": []}'
        message.model_extra = {}
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=message)]

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response
            result = await client._make_api_call(
                [{"role": "user", "content": "test"}], 0.0, 100
            )

        assert result == '{"sources": [], "sinks": []}'

    async def test_truncated_response_is_not_retried(self):
        client = OpenAIClient(api_key="sk-test123")
        message = MagicMock(content=None, reasoning_content=None, model_extra={})
        choice = MagicMock(message=message, finish_reason="length")
        mock_response = MagicMock(choices=[choice], usage=None)

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response
            with pytest.raises(LLMError, match="exceeded max_tokens"):
                await client.chat_completion(
                    [{"role": "user", "content": "test"}], max_retries=3
                )

        assert mock_create.call_count == 1
        assert client._should_retry(
            TruncatedLLMResponseError("truncated")
        ) is False

    async def test_nonempty_truncated_response_is_rejected(self):
        client = OpenAIClient(api_key="sk-test123")
        message = MagicMock(content='{"sources": [', reasoning_content=None)
        choice = MagicMock(message=message, finish_reason="length")
        mock_response = MagicMock(choices=[choice])

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response
            with pytest.raises(TruncatedLLMResponseError, match="max_tokens=100"):
                await client._make_api_call(
                    [{"role": "user", "content": "test"}], 0.0, 100
                )

    def test_should_retry_rate_limit(self):
        """Test retry logic for RateLimitError."""
        client = OpenAIClient(api_key="sk-test123")

        error = RateLimitError("Rate limit exceeded", response=MagicMock(), body=None)
        assert client._should_retry(error) is True

    def test_should_retry_timeout(self):
        """Test retry logic for APITimeoutError."""
        client = OpenAIClient(api_key="sk-test123")

        error = APITimeoutError(request=MagicMock())
        assert client._should_retry(error) is True

    def test_should_retry_other_error(self):
        """Test retry logic for non-retryable errors."""
        client = OpenAIClient(api_key="sk-test123")

        error = ValueError("Invalid request")
        assert client._should_retry(error) is False

    async def test_chat_completion_with_rate_limit_retry(self):
        """Test chat completion retries on rate limit."""
        client = OpenAIClient(api_key="sk-test123")

        # Mock response for successful retry
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "success"

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            # First call fails with rate limit, second succeeds
            mock_create.side_effect = [
                RateLimitError("Rate limit", response=MagicMock(), body=None),
                mock_response,
            ]

            messages = [{"role": "user", "content": "test"}]
            result = await client.chat_completion(messages, max_retries=3)

            assert result == "success"
            assert mock_create.call_count == 2

    async def test_chat_completion_with_timeout_retry(self):
        """Test chat completion retries on timeout."""
        client = OpenAIClient(api_key="sk-test123")

        # Mock response for successful retry
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "success"

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            # First call times out, second succeeds
            mock_create.side_effect = [
                APITimeoutError(request=MagicMock()),
                mock_response,
            ]

            messages = [{"role": "user", "content": "test"}]
            result = await client.chat_completion(messages, max_retries=3)

            assert result == "success"
            assert mock_create.call_count == 2

    async def test_chat_completion_retry_exhausted(self):
        """Test chat completion fails after max retries."""
        client = OpenAIClient(api_key="sk-test123")

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            # All calls fail with rate limit
            mock_create.side_effect = RateLimitError(
                "Rate limit", response=MagicMock(), body=None
            )

            messages = [{"role": "user", "content": "test"}]

            with pytest.raises(LLMError, match="API call failed after 3 retries"):
                await client.chat_completion(messages, max_retries=3)

            assert mock_create.call_count == 3

    async def test_analyze_code_full_flow(self):
        """Test full analyze_code flow with OpenAI."""
        client = OpenAIClient(api_key="sk-test123")

        # Mock OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"vulnerabilities": ["SQL Injection"]}'

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response

            result = await client.analyze_code("SELECT * FROM users", "Find vulnerabilities")

            assert result == {"vulnerabilities": ["SQL Injection"]}
            assert mock_create.call_count == 1

            # Verify system message is included
            call_args = mock_create.call_args[1]
            messages = call_args["messages"]
            assert any(msg["role"] == "system" for msg in messages)
