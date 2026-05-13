"""Simple LLM client for OpenAI API with async support.

DEPRECATED: This module is deprecated. Use OpenAIClient instead.
Maintained for backward compatibility.
"""

import warnings
from src.stage1_llm_inference.openai_client import OpenAIClient


class SimpleLLMClient(OpenAIClient):
    """DEPRECATED: Use OpenAIClient instead.

    This class is maintained for backward compatibility only.
    New code should use OpenAIClient directly.

    SimpleLLMClient now inherits from OpenAIClient and issues a deprecation
    warning when instantiated.
    """

    def __init__(self, api_key: str, model: str = "gpt-4-turbo") -> None:
        """Initialize the LLM client.

        DEPRECATED: Use OpenAIClient instead.

        Args:
            api_key: OpenAI API key for authentication.
            model: Model identifier (default: gpt-4-turbo).

        Raises:
            ValueError: If api_key is empty.
        """
        warnings.warn(
            "SimpleLLMClient is deprecated and will be removed in a future version. "
            "Use OpenAIClient instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(api_key=api_key, model=model)
