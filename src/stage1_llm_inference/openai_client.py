"""OpenAI-specific LLM client implementation."""

from typing import List, Optional

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

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4-turbo",
        base_url: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """Initialize the OpenAI client.

        Args:
            api_key: OpenAI API key for authentication.
            model: OpenAI model identifier (default: gpt-4-turbo).
            base_url: Optional override for the API base URL. Lets you point at
                an OpenAI-compatible endpoint (Azure OpenAI, a local proxy,
                LiteLLM, vLLM, etc.). When ``None`` the official OpenAI URL is
                used.
            user_agent: Optional override for the ``User-Agent`` header. Some
                third-party OpenAI-compatible proxies reject the openai SDK's
                default ``User-Agent`` (``OpenAI/Python``) as automated traffic
                ("Your request was blocked"). When a custom ``base_url`` is set
                and no ``user_agent`` is given, a neutral one is sent so such
                proxies work out of the box. Ignored for the official OpenAI
                endpoint unless explicitly provided.

        Raises:
            ValueError: If api_key is empty.
        """
        if not api_key:
            raise ValueError("api_key cannot be empty")

        # Initialize base class
        super().__init__(model=model)

        # Initialize OpenAI client. Passing base_url=None lets the SDK fall back
        # to the default OpenAI endpoint, so we only forward a non-empty value.
        self.base_url = base_url or None

        # Resolve the User-Agent. For a custom (third-party) base_url, default to
        # a neutral UA so proxies that fingerprint-block the openai SDK accept
        # the request; for the official endpoint, leave the SDK default intact.
        effective_ua = user_agent or (None if not self.base_url else "vtc/1.0")
        self.user_agent = effective_ua
        default_headers = {"User-Agent": effective_ua} if effective_ua else None

        client_kwargs: dict = {"api_key": api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        if default_headers:
            client_kwargs["default_headers"] = default_headers

        self.client = AsyncOpenAI(**client_kwargs)
        logger.debug(
            f"OpenAI client initialized (base_url={self.base_url or 'default'}, "
            f"user_agent={effective_ua or 'sdk-default'})"
        )

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
