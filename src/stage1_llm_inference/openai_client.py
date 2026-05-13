"""OpenAI-specific LLM client implementation."""

from typing import List

from openai import AsyncOpenAI, RateLimitError, APITimeoutError

from src.stage1_llm_inference.base_client import BaseLLMClient
from src.utils.logger import get_logger

logger = get_logger()


class OpenAIClient(BaseLLMClient):
    """LLM client for OpenAI API.

    Provides OpenAI-specific implementation of the BaseLLMClient interface,
    handling authentication, API calls, and error types specific to OpenAI.

    Attributes:
        client: AsyncOpenAI client instance.
        model: Name of the OpenAI model to use.
    """

    def __init__(self, api_key: str, model: str = "gpt-4-turbo") -> None:
        """Initialize the OpenAI client.

        Args:
            api_key: OpenAI API key for authentication.
            model: OpenAI model identifier (default: gpt-4-turbo).

        Raises:
            ValueError: If api_key is empty.
        """
        if not api_key:
            raise ValueError("api_key cannot be empty")

        # Initialize base class
        super().__init__(model=model)

        # Initialize OpenAI client
        self.client = AsyncOpenAI(api_key=api_key)
        logger.debug("OpenAI client initialized successfully")

    async def _make_api_call(
        self,
        messages: List[dict],
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Make OpenAI API call.

        Args:
            messages: List of message dicts with 'role' and 'content' keys.
            temperature: Sampling temperature (0.0 = deterministic).
            max_tokens: Maximum tokens in response.

        Returns:
            The response text content from OpenAI.

        Raises:
            RateLimitError: If rate limit is exceeded.
            APITimeoutError: If request times out.
            Exception: Other OpenAI API errors.
        """
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        return response.choices[0].message.content or ""

    def _should_retry(self, error: Exception) -> bool:
        """Determine if an OpenAI error should trigger a retry.

        OpenAI-specific retryable errors:
        - RateLimitError: Rate limit exceeded
        - APITimeoutError: Request timeout

        Args:
            error: The exception that occurred during API call.

        Returns:
            True if error is retryable, False otherwise.
        """
        return isinstance(error, (RateLimitError, APITimeoutError))
