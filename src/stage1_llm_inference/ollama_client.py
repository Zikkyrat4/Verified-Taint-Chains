"""Ollama-specific LLM client implementation for local models."""

from typing import List
import asyncio

try:
    import ollama
except ImportError:
    ollama = None

from src.stage1_llm_inference.base_client import BaseLLMClient
from src.core.exceptions import LLMError
from src.utils.logger import get_logger

logger = get_logger()


class OllamaClient(BaseLLMClient):
    """LLM client for Ollama local models.

    Provides Ollama-specific implementation for running LLMs locally.
    No API key required. Connects to local Ollama server.

    Attributes:
        client: Ollama AsyncClient instance.
        model: Name of the Ollama model to use.
        base_url: URL of the Ollama server.
    """

    def __init__(
        self,
        model: str = "llama3:latest",
        base_url: str = "http://localhost:11434",
    ) -> None:
        """Initialize the Ollama client.

        Args:
            model: Ollama model name (default: llama3:latest).
                   Common options: llama3:latest, mistral:latest,
                   codellama:latest, deepseek-coder:latest
            base_url: URL of the Ollama server (default: http://localhost:11434).

        Raises:
            ImportError: If ollama package is not installed.
            ValueError: If base_url is invalid.
        """
        if ollama is None:
            raise ImportError(
                "ollama package is required for OllamaClient. "
                "Install it with: pip install ollama"
            )

        if not base_url:
            raise ValueError("base_url cannot be empty")

        # Initialize base class
        super().__init__(model=model)

        # Store base URL
        self.base_url = base_url

        # Initialize Ollama client
        self.client = ollama.AsyncClient(host=base_url)
        logger.debug(f"Ollama client initialized with base_url: {base_url}")

        # Note: Connection verification is done lazily on first API call
        # to avoid issues with event loop not being available during __init__
        self._connection_verified = False

    async def _verify_connection(self) -> None:
        """Verify connection to Ollama server and check model availability.

        Runs in background during initialization. Logs warnings if:
        - Cannot connect to server
        - Specified model is not available

        Does not raise exceptions to avoid blocking initialization.
        """
        try:
            # List available models
            models_response = await self.client.list()
            available_models = [m["name"] for m in models_response.get("models", [])]

            logger.info(
                f"Connected to Ollama server. Available models: {', '.join(available_models)}"
            )

            # Check if requested model is available
            if self.model not in available_models:
                logger.warning(
                    f"Model '{self.model}' not found in available models. "
                    f"You may need to run: ollama pull {self.model}"
                )
            else:
                logger.info(f"Model '{self.model}' is available")

        except Exception as e:
            logger.warning(
                f"Could not verify Ollama connection: {str(e)}. "
                f"Make sure Ollama is running at {self.base_url}"
            )

    async def _make_api_call(
        self,
        messages: List[dict],
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Make Ollama API call.

        Args:
            messages: List of message dicts with 'role' and 'content' keys.
            temperature: Sampling temperature (0.0 = deterministic).
            max_tokens: Maximum tokens in response.

        Returns:
            The response text content from Ollama.

        Raises:
            ollama.ResponseError: If Ollama returns an error response.
            Exception: Connection or other errors.
        """
        # Verify connection on first call (lazy initialization)
        if not self._connection_verified:
            await self._verify_connection()
            self._connection_verified = True

        # Ollama uses 'num_predict' instead of 'max_tokens'
        options = {
            "temperature": temperature,
            "num_predict": max_tokens,
        }

        try:
            response = await self.client.chat(
                model=self.model,
                messages=messages,
                options=options,
                format="json",
            )

            # Extract content from response
            content = response.get("message", {}).get("content", "")

            if not content:
                raise LLMError("Ollama returned empty response")

            return content

        except Exception as e:
            # Add context to error message
            raise LLMError(
                f"Ollama API call failed: {str(e)}. "
                f"Make sure Ollama is running at {self.base_url} "
                f"and model '{self.model}' is available."
            ) from e

    def _should_retry(self, error: Exception) -> bool:
        """Determine if an Ollama error should trigger a retry.

        Ollama-specific retryable errors:
        - Connection errors (server not reachable)
        - Timeout errors
        - ResponseError with status 503 (service unavailable)

        Args:
            error: The exception that occurred during API call.

        Returns:
            True if error is retryable, False otherwise.
        """
        # Check for connection-related errors
        error_str = str(error).lower()
        connection_keywords = [
            "connection",
            "timeout",
            "refused",
            "unavailable",
            "503",
        ]

        # Retry on connection issues
        if any(keyword in error_str for keyword in connection_keywords):
            return True

        # Check for Ollama-specific ResponseError
        if hasattr(error, "status_code"):
            # Retry on 503 (service unavailable) or 429 (too many requests)
            return error.status_code in (503, 429)

        # Don't retry on other errors (model not found, invalid request, etc.)
        return False
