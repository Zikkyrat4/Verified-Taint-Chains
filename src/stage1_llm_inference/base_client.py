"""Base abstract class for LLM clients with common retry and parsing logic."""

import asyncio
import inspect
import json
from abc import ABC, abstractmethod
from typing import List, Optional

from src.core.exceptions import LLMError, ParsingError
from src.utils.logger import get_logger

logger = get_logger()


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients.

    Provides common functionality:
    - Exponential backoff retry logic
    - JSON parsing with markdown block support
    - Standardized error handling and logging

    Subclasses must implement provider-specific API calls and error handling.

    Attributes:
        model: Name of the model to use for API calls.
    """

    def __init__(
        self,
        model: str,
        default_max_tokens: int = 4000,
        default_max_retries: int = 3,
    ) -> None:
        """Initialize the base LLM client.

        Args:
            model: Model identifier to use for API calls.

        Raises:
            ValueError: If model is empty.
        """
        if not model:
            raise ValueError("model cannot be empty")

        self.model = model
        self.default_max_tokens = default_max_tokens
        self.default_max_retries = default_max_retries
        logger.info(f"Initialized {self.__class__.__name__} with model: {model}")

    @abstractmethod
    async def _make_api_call(
        self,
        messages: List[dict],
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Make provider-specific API call.

        This method must be implemented by subclasses to handle
        the actual API communication with the LLM provider.

        Args:
            messages: List of message dicts with 'role' and 'content' keys.
            temperature: Sampling temperature (0.0 = deterministic).
            max_tokens: Maximum tokens in response.

        Returns:
            The response text content from the LLM.

        Raises:
            Exception: Provider-specific exceptions that may trigger retries.
        """
        pass

    @abstractmethod
    def _should_retry(self, error: Exception) -> bool:
        """Determine if an error should trigger a retry.

        Subclasses implement provider-specific logic to decide
        which errors are transient and worth retrying.

        Args:
            error: The exception that occurred during API call.

        Returns:
            True if the error is retryable (rate limits, timeouts),
            False for permanent errors (auth failures, invalid requests).
        """
        pass

    async def aclose(self) -> None:
        """Close a provider's persistent async transport when it exposes one."""
        close = getattr(getattr(self, "client", None), "close", None)
        if close is None:
            return
        result = close()
        if inspect.isawaitable(result):
            await result

    async def chat_completion(
        self,
        messages: List[dict],
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        max_retries: Optional[int] = None,
    ) -> str:
        """Make a chat completion API call with exponential backoff retry logic.

        This method provides unified retry logic for all LLM providers.
        Provider-specific behavior is delegated to _make_api_call() and _should_retry().

        Args:
            messages: List of message dicts with 'role' and 'content' keys.
            temperature: Sampling temperature (0.0 = deterministic).
            max_tokens: Maximum tokens in response.
            max_retries: Maximum number of retry attempts.

        Returns:
            The response text content from the LLM.

        Raises:
            LLMError: If API call fails after retries or encounters non-retryable error.
            ValueError: If messages list is empty.
        """
        if not messages:
            raise ValueError("messages list cannot be empty")

        max_tokens = max_tokens or self.default_max_tokens
        max_retries = max_retries or self.default_max_retries

        last_error = None

        for attempt in range(max_retries):
            try:
                logger.debug(
                    f"API call attempt {attempt + 1}/{max_retries} with {len(messages)} messages"
                )

                response_text = await self._make_api_call(
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )

                logger.debug(f"API call succeeded on attempt {attempt + 1}")
                return response_text

            except Exception as e:
                last_error = e

                # Check if error is retryable
                if self._should_retry(e):
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        logger.warning(
                            f"Retryable error: {str(e)}. "
                            f"Retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})"
                        )
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        logger.error(
                            f"Retryable error after {max_retries} retries: {str(e)}"
                        )
                        raise LLMError(
                            f"API call failed after {max_retries} retries: {str(e)}"
                        ) from e
                else:
                    # Non-retryable error, fail immediately
                    logger.error(f"Non-retryable error: {str(e)}")
                    raise LLMError(f"API call failed: {str(e)}") from e

        # Should not reach here, but just in case
        raise LLMError(
            f"Failed to complete API call after {max_retries} retries"
        ) from last_error

    async def chat_with_json_prompt(
        self, prompt: str, max_tokens: Optional[int] = None
    ) -> dict:
        """Send a ready-made prompt and parse JSON response.

        Unlike analyze_code(), this does not wrap the prompt with additional
        code context, avoiding duplication when the prompt already contains code.

        Args:
            prompt: Complete prompt to send to the LLM.
            max_tokens: Maximum tokens in response.

        Returns:
            Parsed JSON response as dictionary.

        Raises:
            ValueError: If prompt is empty.
            ParsingError: If response is not valid JSON.
            LLMError: If API call fails.
        """
        if not prompt:
            raise ValueError("prompt cannot be empty")

        messages = [
            {
                "role": "system",
                "content": "You are a security analysis expert. Respond with valid JSON only.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ]

        try:
            logger.info("Starting LLM analysis with ready-made prompt")
            response_text = await self.chat_completion(messages, max_tokens=max_tokens)
            logger.debug(f"Received response of length {len(response_text)}")

            json_str = self._extract_json_from_response(response_text)
            try:
                parsed = json.loads(json_str)
            except json.JSONDecodeError:
                # Try to repair common LLM JSON issues
                repaired = self._repair_json(json_str)
                try:
                    parsed = json.loads(repaired)
                    logger.info("Parsed JSON after repair")
                except json.JSONDecodeError:
                    # Strip problematic "pattern" fields (often garbled code)
                    # Strip from original json_str (before repair balanced braces
                    # in wrong order due to garbled content)
                    stripped = self._strip_pattern_fields(json_str)
                    stripped = self._repair_json(stripped)
                    try:
                        parsed = json.loads(stripped)
                        logger.info("Parsed JSON after stripping pattern fields")
                    except json.JSONDecodeError as strip_err:
                        logger.debug(
                            f"Strip pattern fields still failed: {strip_err} "
                            f"({len(stripped)} characters)"
                        )
                        # Last resort: truncate and salvage partial data
                        parsed = self._try_truncated_parse(stripped)
                        logger.info("Parsed JSON after truncation salvage")
            logger.info("Successfully parsed JSON response from LLM")
            return parsed

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {str(e)}")
            logger.debug(
                f"Discarding malformed LLM response ({len(response_text)} characters)"
            )
            raise ParsingError(f"Invalid JSON in LLM response: {str(e)}") from e
        except Exception as e:
            logger.error(f"LLM analysis failed: {str(e)}")
            raise

    async def analyze_code(self, code: str, prompt: str) -> dict:
        """Analyze code using LLM and parse JSON response.

        Constructs a message with the code and prompt, calls chat_completion,
        and parses the response as JSON. Handles markdown code blocks.

        Args:
            code: Source code to analyze.
            prompt: Analysis prompt/instructions.

        Returns:
            Parsed JSON response as dictionary.

        Raises:
            ValueError: If code or prompt is empty.
            ParsingError: If response is not valid JSON.
            LLMError: If API call fails.
        """
        if not code:
            raise ValueError("code cannot be empty")
        if not prompt:
            raise ValueError("prompt cannot be empty")

        messages = [
            {
                "role": "system",
                "content": "You are a security analysis expert. Respond with valid JSON only.",
            },
            {
                "role": "user",
                "content": f"Analyze the following code:\n\n{code}\n\nRequest: {prompt}",
            },
        ]

        try:
            logger.info("Starting code analysis with LLM")
            response_text = await self.chat_completion(messages)
            logger.debug(f"Received response of length {len(response_text)}")

            # Extract JSON from response (handles markdown code blocks)
            json_str = self._extract_json_from_response(response_text)

            parsed = json.loads(json_str)
            logger.info("Successfully parsed JSON response from LLM")
            return parsed

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {str(e)}")
            raise ParsingError(f"Invalid JSON in LLM response: {str(e)}") from e
        except Exception as e:
            logger.error(f"Code analysis failed: {str(e)}")
            raise

    @staticmethod
    def _repair_json(text: str) -> str:
        """Attempt to repair common LLM JSON formatting issues.

        Handles:
        - Trailing commas before } or ]
        - Missing closing braces/brackets
        - JavaScript-style comments
        - Unescaped quotes inside string values (e.g. getParameter("x"))

        Args:
            text: Malformed JSON string.

        Returns:
            Repaired JSON string (may still fail to parse).
        """
        import re as _re

        # Remove single-line comments (// ...)
        text = _re.sub(r'//[^\n]*', '', text)
        # Remove multi-line comments (/* ... */)
        text = _re.sub(r'/\*.*?\*/', '', text, flags=_re.DOTALL)
        # Fix unescaped quotes in patterns like getParameter("username")
        # LLMs often output: "pattern": "request.getParameter("username")"
        # which has unescaped inner quotes
        text = _re.sub(r'\("(\w+)"\)', r'(\\"' r'\1' r'\\")', text)
        # Remove trailing commas before } or ]
        text = _re.sub(r',\s*([}\]])', r'\1', text)
        # Balance braces/brackets using a stack to preserve nesting order
        text = text.rstrip()
        stack: list = []
        in_string = False
        escape = False
        for ch in text:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == '"':
                in_string = not in_string
            elif not in_string:
                if ch in ('{', '['):
                    stack.append(ch)
                elif ch == '}' and stack and stack[-1] == '{':
                    stack.pop()
                elif ch == ']' and stack and stack[-1] == '[':
                    stack.pop()
        # Close unclosed structures in reverse nesting order
        for opener in reversed(stack):
            text += ']' if opener == '[' else '}'

        return text

    @staticmethod
    def _strip_pattern_fields(text: str) -> str:
        """Remove 'pattern' key-value entries that often contain raw code.

        LLMs frequently place raw source code in the ``"pattern"`` field,
        introducing unescaped quotes and multi-line garbled text.  Since
        this field is optional for the pipeline, removing it allows the
        rest of the JSON to parse correctly.

        Uses line-based heuristics to handle multi-line garbled values.

        Args:
            text: JSON string.

        Returns:
            JSON string with ``"pattern"`` entries removed.
        """
        lines = text.split("\n")
        result: list[str] = []
        skip = False
        for line in lines:
            stripped = line.strip()
            if '"pattern"' in stripped and ":" in stripped:
                skip = True
                continue
            if skip:
                # Resume when we hit a new JSON key or closing structure
                if stripped.startswith('"') and ":" in stripped:
                    skip = False
                elif stripped in ("}", "},", "]", "],"):
                    skip = False
                else:
                    continue
            result.append(line)
        return "\n".join(result)

    @staticmethod
    def _try_truncated_parse(text: str) -> dict:
        """Salvage partial data from malformed JSON by truncating at the error.

        When the LLM generates a valid start (e.g. complete "sources" array)
        but garbles a later field, this method backtracks to the last
        successfully closed object/array and parses whatever is recoverable.

        Args:
            text: JSON string that failed standard parsing.

        Returns:
            Parsed dictionary with whatever data could be salvaged.

        Raises:
            json.JSONDecodeError: If no valid JSON can be extracted.
        """
        # Try parsing progressively shorter substrings
        # by finding the last valid closing structure
        for end_char in ('}', ']'):
            pos = text.rfind(end_char)
            while pos > 0:
                candidate = text[:pos + 1]
                # Balance the candidate
                open_braces = candidate.count('{') - candidate.count('}')
                open_brackets = candidate.count('[') - candidate.count(']')
                candidate += '}' * max(0, open_braces)
                candidate += ']' * max(0, open_brackets)
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    pass
                pos = text.rfind(end_char, 0, pos)

        # Nothing salvageable
        raise json.JSONDecodeError("No valid JSON found after truncation", text, 0)

    @staticmethod
    def _extract_json_from_response(response_text: str) -> str:
        """Extract JSON string from LLM response.

        Handles responses wrapped in markdown code blocks:
        - ```json ... ```
        - ``` ... ```

        Args:
            response_text: Raw response text from LLM.

        Returns:
            Extracted JSON string.
        """
        # Try extracting from ```json code block
        if "```json" in response_text:
            return response_text.split("```json")[1].split("```")[0].strip()

        # Try extracting from generic ``` code block
        if "```" in response_text:
            return response_text.split("```")[1].split("```")[0].strip()

        # Return as-is if no code blocks found
        return response_text.strip()
