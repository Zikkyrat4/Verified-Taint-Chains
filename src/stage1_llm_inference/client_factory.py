"""Factory for creating LLM client instances based on configuration."""

from enum import Enum
from typing import TYPE_CHECKING

from src.stage1_llm_inference.base_client import BaseLLMClient
from src.stage1_llm_inference.openai_client import OpenAIClient
from src.stage1_llm_inference.ollama_client import OllamaClient
from src.utils.logger import get_logger

if TYPE_CHECKING:
    from src.core.config import PipelineConfig

logger = get_logger()


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    OLLAMA = "ollama"


def create_llm_client(config: "PipelineConfig") -> BaseLLMClient:
    """Create an LLM client based on the pipeline configuration.

    Factory function that instantiates the appropriate LLM client
    (OpenAI or Ollama) based on the provider specified in config.

    Args:
        config: Pipeline configuration containing LLM settings.

    Returns:
        Initialized LLM client instance (OpenAIClient or OllamaClient).

    Raises:
        ValueError: If provider is unsupported or required config is missing.

    Example:
        >>> config = PipelineConfig(llm_provider="openai", llm_api_key="sk-...")
        >>> client = create_llm_client(config)
        >>> # Returns OpenAIClient instance
    """
    provider = config.llm_provider.lower()

    logger.info(f"Creating LLM client for provider: {provider}")

    if provider == LLMProvider.OPENAI:
        # Validate OpenAI-specific config
        if not config.llm_api_key:
            raise ValueError(
                "llm_api_key is required when using OpenAI provider. "
                "Set OPENAI_API_KEY environment variable or provide in config."
            )

        client = OpenAIClient(
            api_key=config.llm_api_key,
            model=config.llm_model,
        )
        logger.info(f"Created OpenAI client with model: {config.llm_model}")
        return client

    elif provider == LLMProvider.OLLAMA:
        # Ollama doesn't require API key
        client = OllamaClient(
            model=config.llm_model,
            base_url=config.ollama_base_url,
        )
        logger.info(
            f"Created Ollama client with model: {config.llm_model} "
            f"at {config.ollama_base_url}"
        )
        return client

    else:
        raise ValueError(
            f"Unsupported LLM provider: {provider}. "
            f"Supported providers: {', '.join([p.value for p in LLMProvider])}"
        )
