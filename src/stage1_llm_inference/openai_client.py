"""OpenAI-specific LLM client implementation."""

import json
from typing import Any, List, Optional
from urllib.parse import urlparse

from openai import AsyncOpenAI, RateLimitError, APITimeoutError

from src.stage1_llm_inference.base_client import BaseLLMClient
from src.core.exceptions import EmptyLLMResponseError, TruncatedLLMResponseError
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
        timeout: float = 60.0,
        json_mode: bool = True,
        thinking: Optional[str] = None,
        max_retries: int = 2,
        max_tokens: int = 4000,
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
        super().__init__(
            model=model,
            default_max_tokens=max_tokens,
            default_max_retries=max_retries,
        )

        # Initialize OpenAI client. Passing base_url=None lets the SDK fall back
        # to the default OpenAI endpoint, so we only forward a non-empty value.
        self.base_url = base_url or None
        self.json_mode = json_mode
        self.thinking = thinking or (
            "disabled" if model.lower().startswith("glm-") else None
        )
        hostname = (urlparse(self.base_url).hostname or "") if self.base_url else ""
        self.native_glm_endpoint = hostname.endswith("z.ai") or hostname.endswith(
            "bigmodel.cn"
        )

        # Resolve the User-Agent. For a custom (third-party) base_url, default to
        # a neutral UA so proxies that fingerprint-block the openai SDK accept
        # the request; for the official endpoint, leave the SDK default intact.
        effective_ua = user_agent or (None if not self.base_url else "vtc/1.0")
        self.user_agent = effective_ua
        default_headers = {"User-Agent": effective_ua} if effective_ua else None

        # SDK retries are disabled because BaseLLMClient owns retry/backoff.
        # Otherwise each logical attempt can fan out into several hidden HTTP calls.
        client_kwargs: dict = {
            "api_key": api_key,
            "timeout": timeout,
            "max_retries": 0,
        }
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        else:
            # Do not let an ambient OPENAI_BASE_URL silently redirect a client
            # that was explicitly constructed without a custom endpoint.
            client_kwargs["base_url"] = "https://api.openai.com/v1"
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
        request_kwargs: dict = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if self.json_mode:
            request_kwargs["response_format"] = {"type": "json_object"}
        if self.thinking:
            if self.model.lower().startswith("glm-") and not self.native_glm_endpoint:
                request_kwargs["extra_body"] = {
                    "chat_template_kwargs": {
                        "enable_thinking": self.thinking == "enabled"
                    }
                }
            else:
                request_kwargs["extra_body"] = {
                    "thinking": {"type": self.thinking}
                }

        response = await self.client.chat.completions.create(**request_kwargs)

        if not response.choices:
            raise EmptyLLMResponseError("OpenAI response contains no choices")

        choice = response.choices[0]
        message = choice.message
        content = self._content_to_text(getattr(message, "content", None)).strip()

        # A provider may return a non-empty *partial* JSON document together
        # with finish_reason="length". Passing it to the generic JSON repair
        # path obscures the real failure and can salvage an incomplete security
        # specification. Treat any length stop as truncation instead.
        finish_reason = getattr(choice, "finish_reason", None)
        if finish_reason == "length":
            raise TruncatedLLMResponseError(
                f"OpenAI response exceeded max_tokens={max_tokens}"
            )

        # Some OpenAI-compatible reasoning endpoints put the final JSON in a
        # non-standard reasoning_content field and leave content empty.
        if not content:
            extra = getattr(message, "model_extra", None) or {}
            reasoning = getattr(message, "reasoning_content", None)
            if reasoning is None and isinstance(extra, dict):
                reasoning = extra.get("reasoning_content")
            reasoning_text = self._content_to_text(reasoning).strip()
            content = self._extract_json_object(reasoning_text) or ""

        if not content:
            usage = getattr(response, "usage", None)
            logger.warning(
                "OpenAI-compatible endpoint returned empty content "
                f"(finish_reason={finish_reason!r}, usage={usage!r})"
            )
            raise EmptyLLMResponseError(
                f"OpenAI response content is empty (finish_reason={finish_reason!r})"
            )

        return content

    @staticmethod
    def _content_to_text(content: Any) -> str:
        """Normalize string and multipart response content."""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: List[str] = []
            for item in content:
                if isinstance(item, dict):
                    value = item.get("text") or item.get("content")
                else:
                    value = getattr(item, "text", None)
                if value:
                    parts.append(str(value))
            return "\n".join(parts)
        return ""

    @staticmethod
    def _extract_json_object(text: str) -> Optional[str]:
        """Return a complete JSON object embedded in provider reasoning."""
        if not text:
            return None
        decoder = json.JSONDecoder()
        for index, char in enumerate(text):
            if char != "{":
                continue
            try:
                value, end = decoder.raw_decode(text[index:])
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return text[index:index + end]
        return None

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
        return isinstance(
            error, (RateLimitError, APITimeoutError, EmptyLLMResponseError)
        )
