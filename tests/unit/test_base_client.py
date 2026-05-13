"""Unit tests for BaseLLMClient abstract class."""

import pytest
from typing import List
from unittest.mock import AsyncMock, patch

from src.stage1_llm_inference.base_client import BaseLLMClient
from src.core.exceptions import LLMError


class MockLLMClient(BaseLLMClient):
    """Mock implementation of BaseLLMClient for testing."""

    def __init__(self, model: str = "test-model", should_retry: bool = True):
        super().__init__(model=model)
        self.should_retry_value = should_retry
        self.api_call_count = 0

    async def _make_api_call(
        self,
        messages: List[dict],
        temperature: float,
        max_tokens: int,
    ) -> str:
        self.api_call_count += 1
        # Will be mocked in tests
        return "mock response"

    def _should_retry(self, error: Exception) -> bool:
        return self.should_retry_value


@pytest.mark.asyncio
class TestBaseLLMClient:
    """Test suite for BaseLLMClient."""

    def test_initialization(self):
        """Test client initialization."""
        client = MockLLMClient(model="test-model")
        assert client.model == "test-model"

    def test_initialization_empty_model(self):
        """Test initialization fails with empty model."""
        with pytest.raises(ValueError, match="model cannot be empty"):
            MockLLMClient(model="")

    async def test_chat_completion_success(self):
        """Test successful chat completion."""
        client = MockLLMClient()

        with patch.object(client, "_make_api_call", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = "test response"

            messages = [{"role": "user", "content": "test"}]
            result = await client.chat_completion(messages)

            assert result == "test response"
            mock_call.assert_called_once()

    async def test_chat_completion_empty_messages(self):
        """Test chat completion with empty messages list."""
        client = MockLLMClient()

        with pytest.raises(ValueError, match="messages list cannot be empty"):
            await client.chat_completion([])

    async def test_chat_completion_retry_success(self):
        """Test retry logic succeeds after transient error."""
        client = MockLLMClient(should_retry=True)

        with patch.object(client, "_make_api_call", new_callable=AsyncMock) as mock_call:
            # First call fails, second succeeds
            mock_call.side_effect = [
                Exception("Transient error"),
                "success response",
            ]

            messages = [{"role": "user", "content": "test"}]
            result = await client.chat_completion(messages, max_retries=3)

            assert result == "success response"
            assert mock_call.call_count == 2

    async def test_chat_completion_retry_exhausted(self):
        """Test retry logic fails after max retries."""
        client = MockLLMClient(should_retry=True)

        with patch.object(client, "_make_api_call", new_callable=AsyncMock) as mock_call:
            # All calls fail
            mock_call.side_effect = Exception("Persistent error")

            messages = [{"role": "user", "content": "test"}]

            with pytest.raises(LLMError, match="API call failed after 3 retries"):
                await client.chat_completion(messages, max_retries=3)

            assert mock_call.call_count == 3

    async def test_chat_completion_non_retryable_error(self):
        """Test non-retryable error fails immediately."""
        client = MockLLMClient(should_retry=False)

        with patch.object(client, "_make_api_call", new_callable=AsyncMock) as mock_call:
            mock_call.side_effect = Exception("Auth error")

            messages = [{"role": "user", "content": "test"}]

            with pytest.raises(LLMError, match="API call failed"):
                await client.chat_completion(messages, max_retries=3)

            # Should only be called once (no retries)
            assert mock_call.call_count == 1

    async def test_analyze_code_success(self):
        """Test successful code analysis with JSON response."""
        client = MockLLMClient()

        json_response = '{"result": "test"}'

        with patch.object(client, "chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = json_response

            result = await client.analyze_code("code", "prompt")

            assert result == {"result": "test"}
            mock_chat.assert_called_once()

    async def test_analyze_code_with_markdown_json(self):
        """Test code analysis extracts JSON from markdown blocks."""
        client = MockLLMClient()

        json_response = '```json\n{"result": "test"}\n```'

        with patch.object(client, "chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = json_response

            result = await client.analyze_code("code", "prompt")

            assert result == {"result": "test"}

    async def test_analyze_code_with_generic_markdown(self):
        """Test code analysis extracts JSON from generic code blocks."""
        client = MockLLMClient()

        json_response = '```\n{"result": "test"}\n```'

        with patch.object(client, "chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = json_response

            result = await client.analyze_code("code", "prompt")

            assert result == {"result": "test"}

    async def test_analyze_code_empty_code(self):
        """Test analyze_code fails with empty code."""
        client = MockLLMClient()

        with pytest.raises(ValueError, match="code cannot be empty"):
            await client.analyze_code("", "prompt")

    async def test_analyze_code_empty_prompt(self):
        """Test analyze_code fails with empty prompt."""
        client = MockLLMClient()

        with pytest.raises(ValueError, match="prompt cannot be empty"):
            await client.analyze_code("code", "")

    async def test_analyze_code_invalid_json(self):
        """Test analyze_code fails with invalid JSON."""
        client = MockLLMClient()

        with patch.object(client, "chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = "not valid json"

            with pytest.raises(Exception):  # ParsingError
                await client.analyze_code("code", "prompt")

    def test_extract_json_from_response_plain(self):
        """Test JSON extraction from plain text."""
        result = BaseLLMClient._extract_json_from_response('{"key": "value"}')
        assert result == '{"key": "value"}'

    def test_extract_json_from_response_json_block(self):
        """Test JSON extraction from ```json block."""
        response = '```json\n{"key": "value"}\n```'
        result = BaseLLMClient._extract_json_from_response(response)
        assert result == '{"key": "value"}'

    def test_extract_json_from_response_generic_block(self):
        """Test JSON extraction from generic ``` block."""
        response = '```\n{"key": "value"}\n```'
        result = BaseLLMClient._extract_json_from_response(response)
        assert result == '{"key": "value"}'

    def test_extract_json_from_response_with_text(self):
        """Test JSON extraction ignores surrounding text."""
        response = 'Here is the result:\n```json\n{"key": "value"}\n```\nDone.'
        result = BaseLLMClient._extract_json_from_response(response)
        assert result == '{"key": "value"}'

    async def test_chat_with_json_prompt_success(self):
        """Test successful chat_with_json_prompt call."""
        client = MockLLMClient()

        json_response = '{"sources": [{"line": 1, "variable": "x", "type": "user_input"}]}'

        with patch.object(client, "chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = json_response

            result = await client.chat_with_json_prompt("Analyze this code for sources")

            assert result == {"sources": [{"line": 1, "variable": "x", "type": "user_input"}]}
            mock_chat.assert_called_once()

    async def test_chat_with_json_prompt_empty_prompt(self):
        """Test chat_with_json_prompt fails with empty prompt."""
        client = MockLLMClient()

        with pytest.raises(ValueError, match="prompt cannot be empty"):
            await client.chat_with_json_prompt("")

    async def test_chat_with_json_prompt_invalid_json(self):
        """Test chat_with_json_prompt fails with invalid JSON response."""
        client = MockLLMClient()

        with patch.object(client, "chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = "not valid json"

            with pytest.raises(Exception):  # ParsingError
                await client.chat_with_json_prompt("test prompt")

    async def test_chat_with_json_prompt_with_markdown(self):
        """Test chat_with_json_prompt extracts JSON from markdown blocks."""
        client = MockLLMClient()

        json_response = '```json\n{"result": "test"}\n```'

        with patch.object(client, "chat_completion", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = json_response

            result = await client.chat_with_json_prompt("test prompt")

            assert result == {"result": "test"}
