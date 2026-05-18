"""Integration tests for Stage 1 (LLM Inference) components."""

import json
import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch
from openai import RateLimitError, APITimeoutError

from src.stage1_llm_inference.llm_client import SimpleLLMClient


def _make_rate_limit_error(msg: str = "Rate limited") -> RateLimitError:
    """Create a RateLimitError with required response and body."""
    mock_response = httpx.Response(
        status_code=429,
        request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions"),
    )
    return RateLimitError(msg, response=mock_response, body=None)
from src.stage1_llm_inference.specification_extractor import SimpleSpecificationExtractor
from src.core.exceptions import LLMError, ParsingError
from src.core.models import VulnerabilityType


class TestLLMClientBasicCall:
    """Integration tests for basic LLM client functionality."""

    @pytest.mark.asyncio
    async def test_llm_client_basic_call(self) -> None:
        """Test successful API call to OpenAI."""
        client = SimpleLLMClient(api_key="test-key", model="gpt-4-turbo")

        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is 2+2?"},
        ]

        # Mock the OpenAI API response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="4"))]

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response

            response = await client.chat_completion(messages)

        assert response == "4"
        mock_create.assert_called_once()

        # Verify the API was called with correct parameters
        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs["model"] == "gpt-4-turbo"
        assert call_kwargs["temperature"] == 0.0
        assert call_kwargs["max_tokens"] == 4000

    @pytest.mark.asyncio
    async def test_llm_client_with_custom_parameters(self) -> None:
        """Test API call with custom temperature and max_tokens."""
        client = SimpleLLMClient(api_key="test-key")

        messages = [{"role": "user", "content": "Test"}]

        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Response"))]

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response

            response = await client.chat_completion(
                messages, temperature=0.7, max_tokens=500
            )

        assert response == "Response"

        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs["temperature"] == 0.7
        assert call_kwargs["max_tokens"] == 500


class TestLLMClientRetryLogic:
    """Integration tests for retry logic and error handling."""

    @pytest.mark.asyncio
    async def test_llm_client_retry_on_rate_limit(self) -> None:
        """Test that rate limit errors trigger retries with exponential backoff."""
        client = SimpleLLMClient(api_key="test-key")

        messages = [{"role": "user", "content": "Test"}]

        # Setup: First attempt fails with rate limit, second succeeds
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Success"))]

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            # First call raises RateLimitError, second succeeds
            mock_create.side_effect = [
                _make_rate_limit_error("Rate limited"),
                mock_response,
            ]

            response = await client.chat_completion(messages, max_retries=2)

        assert response == "Success"
        # Should have been called twice (initial + 1 retry)
        assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_llm_client_retry_on_timeout(self) -> None:
        """Test that timeout errors trigger retries."""
        client = SimpleLLMClient(api_key="test-key")

        messages = [{"role": "user", "content": "Test"}]

        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Success after timeout"))]

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            # First call times out, second succeeds
            mock_create.side_effect = [
                APITimeoutError("Timeout"),
                mock_response,
            ]

            response = await client.chat_completion(messages, max_retries=2)

        assert response == "Success after timeout"
        assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_llm_client_exhausts_retries(self) -> None:
        """Test that LLMError is raised after max retries exhausted."""
        client = SimpleLLMClient(api_key="test-key")

        messages = [{"role": "user", "content": "Test"}]

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            # All attempts fail with rate limit
            mock_create.side_effect = _make_rate_limit_error("Rate limited")

            with pytest.raises(LLMError, match="API call failed"):
                await client.chat_completion(messages, max_retries=2)

            # Should have attempted max_retries times
            assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_llm_client_multiple_retries(self) -> None:
        """Test exponential backoff across multiple retries."""
        client = SimpleLLMClient(api_key="test-key")

        messages = [{"role": "user", "content": "Test"}]

        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Final success"))]

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            # Fail twice, succeed on third
            mock_create.side_effect = [
                _make_rate_limit_error("Rate limited"),
                _make_rate_limit_error("Rate limited again"),
                mock_response,
            ]

            response = await client.chat_completion(messages, max_retries=3)

        assert response == "Final success"
        assert mock_create.call_count == 3


class TestLLMClientCodeAnalysis:
    """Integration tests for code analysis functionality."""

    @pytest.mark.asyncio
    async def test_llm_client_analyze_code_json_response(self) -> None:
        """Test analyze_code with valid JSON response."""
        client = SimpleLLMClient(api_key="test-key")

        code = "String x = request.getParameter('q');"
        prompt = "Find sources"

        response_data = {
            "sources": [
                {"line": 1, "variable": "x", "type": "user_input", "confidence": 0.9}
            ]
        }

        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content=json.dumps(response_data)))
        ]

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response

            result = await client.analyze_code(code, prompt)

        assert result == response_data
        assert "sources" in result

    @pytest.mark.asyncio
    async def test_llm_client_analyze_code_markdown_json(self) -> None:
        """Test analyze_code handles JSON wrapped in markdown."""
        client = SimpleLLMClient(api_key="test-key")

        code = "String x = 1;"
        prompt = "analyze"

        response_data = {"result": "analyzed"}
        response_text = f"Here's the analysis:\n```json\n{json.dumps(response_data)}\n```"

        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content=response_text))]

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response

            result = await client.analyze_code(code, prompt)

        assert result == response_data

    @pytest.mark.asyncio
    async def test_llm_client_analyze_code_invalid_json(self) -> None:
        """Test analyze_code with invalid JSON response."""
        client = SimpleLLMClient(api_key="test-key")

        code = "String x = 1;"
        prompt = "analyze"

        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content="This is not JSON"))
        ]

        with patch.object(
            client.client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response

            with pytest.raises(ParsingError):
                await client.analyze_code(code, prompt)


class TestSpecificationExtractorWithMocks:
    """Integration tests for specification extractor with mocked LLM."""

    @pytest.mark.asyncio
    async def test_specification_extractor_simple_code(self) -> None:
        """Test extraction from simple vulnerable Java code."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client, confidence_threshold=0.5)

        code = """public void searchUsers(HttpServletRequest request) {
            String searchTerm = request.getParameter("search");
            String query = "SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'";
            ResultSet rs = db.executeQuery(query);
        }"""

        # Mock LLM response (single combined call per function)
        combined_response = {
            "sources": [
                {
                    "line": 2,
                    "variable": "searchTerm",
                    "type": "user_input",
                    "confidence": 0.95,
                }
            ],
            "sinks": [
                {
                    "line": 4,
                    "variable": "query",
                    "type": "sql_query",
                    "vulnerability_type": "sql_injection",
                    "confidence": 0.92,
                }
            ],
        }

        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = combined_response

            spec = await extractor.extract(code, "SearchService.java")

        # Verify extraction results
        assert len(spec.sources) == 1
        assert len(spec.sinks) == 1
        assert spec.sources[0].variable_name == "searchTerm"
        assert spec.sinks[0].variable_name == "query"
        assert spec.sinks[0].vulnerability_type == VulnerabilityType.SQL_INJECTION

    @pytest.mark.asyncio
    async def test_specification_extractor_multiple_functions(self) -> None:
        """Test extraction from code with multiple functions."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """public void processInput(HttpServletRequest request) {
            String input = request.getParameter("data");
            execute(input);
        }

        public void execute(String cmd) {
            Runtime.getRuntime().exec(cmd);
        }"""

        # Combined response for first function
        combined_response_1 = {
            "sources": [
                {
                    "line": 2,
                    "variable": "input",
                    "type": "user_input",
                    "confidence": 0.9,
                }
            ],
            "sinks": [],
        }

        # Combined response for second function
        combined_response_2 = {
            "sources": [],
            "sinks": [
                {
                    "line": 7,
                    "variable": "cmd",
                    "type": "command_exec",
                    "vulnerability_type": "command_injection",
                    "confidence": 0.95,
                }
            ],
        }

        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as mock_analyze:
            mock_analyze.side_effect = [
                combined_response_1,
                combined_response_2,
            ]

            spec = await extractor.extract(code, "ExecutorService.java")

        assert len(spec.sources) == 1
        assert len(spec.sinks) == 1

    @pytest.mark.asyncio
    async def test_specification_extractor_empty_results(self) -> None:
        """Test extraction when no sources or sinks found."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """public void safeOperation() {
            int x = 5;
            System.out.println(x);
        }"""

        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = {"sources": [], "sinks": []}
            spec = await extractor.extract(code, "SafeService.java")

        assert len(spec.sources) == 0
        assert len(spec.sinks) == 0
        # The function is non-trivial (it makes a call), so it IS sent to the
        # LLM — detection is prioritization, not keyword exclusion. Emptiness
        # comes from the model's verdict, not from skipping the code.
        mock_analyze.assert_called_once()

    @pytest.mark.asyncio
    async def test_specification_extractor_confidence_filtering(self) -> None:
        """Test that low-confidence items are filtered."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client, confidence_threshold=0.8)

        code = "String x = request.getParameter('q');"

        combined_response = {
            "sources": [
                {
                    "line": 1,
                    "variable": "x",
                    "type": "user_input",
                    "confidence": 0.9,
                },  # Above threshold
                {
                    "line": 1,
                    "variable": "y",
                    "type": "user_input",
                    "confidence": 0.7,
                },  # Below threshold
            ],
            "sinks": [],
        }

        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = combined_response

            spec = await extractor.extract(code, "FilterTest.java")

        # Only high-confidence source should be included
        assert len(spec.sources) == 1
        assert spec.sources[0].variable_name == "x"


class TestParseSourcesAndSinks:
    """Tests for parsing LLM responses into Source/Sink objects."""

    def test_parse_sources_creates_proper_objects(self) -> None:
        """Test that parsed sources have correct attributes."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sources": [
                {
                    "line": 10,
                    "variable": "userInput",
                    "type": "user_input",
                    "confidence": 0.95,
                    "reasoning": "Comes from HTTP request parameter",
                }
            ]
        }

        sources = extractor._parse_llm_sources(response, "Test.java")

        assert len(sources) == 1
        source = sources[0]
        assert source.variable_name == "userInput"
        assert source.type == "user_input"
        assert source.confidence == 0.95
        assert source.location.file_path == "Test.java"
        assert source.location.line_number == 10
        assert source.reasoning == "Comes from HTTP request parameter"

    def test_parse_sinks_creates_proper_objects(self) -> None:
        """Test that parsed sinks have correct attributes."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sinks": [
                {
                    "line": 20,
                    "variable": "query",
                    "type": "sql_query",
                    "vulnerability_type": "sql_injection",
                    "confidence": 0.98,
                    "reasoning": "Direct string concatenation in SQL query",
                }
            ]
        }

        sinks = extractor._parse_llm_sinks(response, "Database.java")

        assert len(sinks) == 1
        sink = sinks[0]
        assert sink.variable_name == "query"
        assert sink.type == "sql_query"
        assert sink.confidence == 0.98
        assert sink.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert sink.location.file_path == "Database.java"
        assert sink.location.line_number == 20

    def test_parse_sources_multiple_items(self) -> None:
        """Test parsing multiple sources from response."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sources": [
                {
                    "line": 5,
                    "variable": "param1",
                    "type": "user_input",
                    "confidence": 0.9,
                },
                {
                    "line": 6,
                    "variable": "param2",
                    "type": "user_input",
                    "confidence": 0.85,
                },
                {
                    "line": 8,
                    "variable": "fileContent",
                    "type": "file_read",
                    "confidence": 0.92,
                },
            ]
        }

        sources = extractor._parse_llm_sources(response, "MultiSource.java")

        assert len(sources) == 3
        assert sources[0].variable_name == "param1"
        assert sources[1].variable_name == "param2"
        assert sources[2].variable_name == "fileContent"
        assert sources[2].type == "file_read"

    def test_parse_sinks_vulnerability_type_mapping(self) -> None:
        """Test that vulnerability types are correctly mapped to enums."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sinks": [
                {
                    "line": 10,
                    "variable": "x",
                    "type": "sql",
                    "vulnerability_type": "sql_injection",
                    "confidence": 0.9,
                },
                {
                    "line": 11,
                    "variable": "y",
                    "type": "command",
                    "vulnerability_type": "command_injection",
                    "confidence": 0.9,
                },
                {
                    "line": 12,
                    "variable": "z",
                    "type": "path",
                    "vulnerability_type": "path_traversal",
                    "confidence": 0.9,
                },
            ]
        }

        sinks = extractor._parse_llm_sinks(response, "VulnTypes.java")

        assert sinks[0].vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert sinks[1].vulnerability_type == VulnerabilityType.COMMAND_INJECTION
        assert sinks[2].vulnerability_type == VulnerabilityType.PATH_TRAVERSAL


class TestEndToEndFlow:
    """End-to-end integration tests for complete workflows."""

    @pytest.mark.asyncio
    async def test_complete_analysis_workflow(self) -> None:
        """Test complete workflow from code to specification."""
        client = SimpleLLMClient(api_key="test-key", model="gpt-4-turbo")
        extractor = SimpleSpecificationExtractor(client, confidence_threshold=0.6)

        # Realistic vulnerable code
        code = """
        public class UserController {
            @PostMapping("/login")
            public String login(HttpServletRequest request) {
                String username = request.getParameter("username");
                String password = request.getParameter("password");

                String query = "SELECT * FROM users WHERE username='" + username +
                              "' AND password='" + password + "'";
                return db.executeQuery(query);
            }
        }
        """

        # Mock the LLM response (single combined call per function)
        combined_response = {
            "sources": [
                {
                    "line": 5,
                    "variable": "username",
                    "type": "user_input",
                    "confidence": 0.98,
                },
                {
                    "line": 6,
                    "variable": "password",
                    "type": "user_input",
                    "confidence": 0.98,
                },
            ],
            "sinks": [
                {
                    "line": 9,
                    "variable": "query",
                    "type": "sql_query",
                    "vulnerability_type": "sql_injection",
                    "confidence": 0.99,
                }
            ],
        }

        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = combined_response

            spec = await extractor.extract(code, "UserController.java")

        # Verify complete specification
        assert spec.llm_model == "gpt-4-turbo"
        assert len(spec.sources) == 2
        assert len(spec.sinks) == 1
        assert spec.sinks[0].vulnerability_type == VulnerabilityType.SQL_INJECTION

        # Verify data consistency
        assert all(s.confidence > 0.6 for s in spec.sources)
        assert all(s.confidence > 0.6 for s in spec.sinks)
