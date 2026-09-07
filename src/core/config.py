"""Pipeline configuration management."""

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv

from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class PipelineConfig:
    """Configuration for the taint analysis pipeline.

    Attributes:
        llm_provider: LLM provider to use - "openai" or "ollama" (default: "openai").
        llm_api_key: API key for LLM provider (required for OpenAI, not needed for Ollama).
        llm_model: LLM model name (default depends on provider).
        ollama_base_url: URL of Ollama server (default: http://localhost:11434).
        max_path_length: Maximum taint chain path length (default: 15).
        min_confidence: Minimum confidence threshold (0.0-1.0, default: 0.5).
        verification_enabled: Whether to verify chains (default: True).
        symbolic_execution_enabled: Whether to use symbolic execution (default: False).
        verification_level: Verification level - "cfg", "symbolic", or "both" (default: "cfg").
        symbolic_timeout: Timeout for symbolic execution in seconds (default: 60).
        use_joern: Whether to use Joern for PDG analysis (default: False).
        use_semantic_heuristic: Whether to use semantic heuristic in A* (default: True).
        use_astar: Whether to use A* instead of BFS (default: True).
        pathfinding_algorithm: Algorithm choice "astar" or "bfs" (default: "astar").
    """

    llm_provider: str = "openai"
    llm_api_key: Optional[str] = None
    llm_model: str = ""  # Will be set based on provider in __post_init__
    openai_base_url: Optional[str] = None  # override for OpenAI-compatible endpoints
    openai_user_agent: Optional[str] = None  # override User-Agent (proxies that block the SDK UA)
    openai_timeout: float = 60.0
    openai_json_mode: bool = True
    openai_thinking: Optional[str] = None
    llm_max_retries: int = 2
    llm_max_tokens: int = 4000
    llm_batch_max_chars: int = 8000
    analysis_backend: str = "llm"
    llm_analysis_mode: str = "targeted"
    ollama_base_url: str = "http://localhost:11434"
    max_path_length: int = 15
    min_confidence: float = 0.6
    verification_enabled: bool = True
    symbolic_execution_enabled: bool = False
    verification_level: str = "cfg"  # "cfg", "symbolic", or "both"
    symbolic_timeout: int = 60  # seconds
    use_joern: bool = False
    use_semantic_heuristic: bool = True
    use_astar: bool = True
    pathfinding_algorithm: str = "astar"  # "astar" or "bfs" (default: astar)
    max_concurrent_files: int = 4  # max concurrent Stage 1 extractions
    max_concurrent_functions: int = 2  # max concurrent functions within one file
    max_files: int = 0  # max files for project mode (0 = unlimited)
    use_llm_graph_builder: bool = True  # use LLM-driven graph builder (AST + LLM enrichment)
    llm_graph_enrichment_enabled: bool = False
    llm_graph_enrichment_confidence: float = 0.7  # min confidence for LLM-inferred edges
    # Persistent Stage 1 cache — turns weeks-long restarts into seconds. See
    # src/stage1_llm_inference/spec_cache.py. Defaults: enabled, dir resolved
    # at pipeline-init time to ``<source_path>/.vtc-cache``.
    cache_enabled: bool = True
    cache_read_enabled: bool = True
    cache_dir: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate configuration values."""
        # Normalize provider to lowercase
        self.llm_provider = self.llm_provider.lower()

        # Validate provider
        if self.llm_provider not in ("openai", "ollama"):
            raise ValueError("llm_provider must be 'openai' or 'ollama'")

        if self.analysis_backend not in ("llm", "static", "hybrid"):
            raise ValueError(
                "analysis_backend must be 'llm', 'static', or 'hybrid'"
            )

        # A static baseline must be runnable without configuring an LLM.
        if (
            self.analysis_backend != "static"
            and self.llm_provider == "openai"
            and not self.llm_api_key
        ):
            raise ValueError(
                "llm_api_key is required when using OpenAI provider. "
                "Set OPENAI_API_KEY environment variable."
            )

        # Set default model based on provider if not specified
        if not self.llm_model:
            self.llm_model = (
                "gpt-4-turbo" if self.llm_provider == "openai" else "llama3:latest"
            )

        if not 0.0 <= self.min_confidence <= 1.0:
            raise ValueError("min_confidence must be between 0.0 and 1.0")

        if self.max_path_length < 1:
            raise ValueError("max_path_length must be at least 1")

        if self.pathfinding_algorithm not in ("astar", "bfs"):
            raise ValueError("pathfinding_algorithm must be 'astar' or 'bfs'")

        if self.verification_level not in ("cfg", "symbolic", "both"):
            raise ValueError("verification_level must be 'cfg', 'symbolic', or 'both'")

        if self.symbolic_timeout < 1:
            raise ValueError("symbolic_timeout must be at least 1 second")

        if self.max_concurrent_files < 1:
            raise ValueError("max_concurrent_files must be at least 1")

        if self.max_concurrent_functions < 1:
            raise ValueError("max_concurrent_functions must be at least 1")

        if self.openai_timeout <= 0:
            raise ValueError("openai_timeout must be positive")

        if self.openai_thinking not in (None, "enabled", "disabled"):
            raise ValueError("openai_thinking must be 'enabled', 'disabled', or None")

        if self.llm_max_retries < 1:
            raise ValueError("llm_max_retries must be at least 1")

        if self.llm_max_tokens < 1:
            raise ValueError("llm_max_tokens must be at least 1")

        if self.llm_batch_max_chars < 0:
            raise ValueError("llm_batch_max_chars must be non-negative")

        if self.llm_analysis_mode not in ("targeted", "exhaustive"):
            raise ValueError(
                "llm_analysis_mode must be 'targeted' or 'exhaustive'"
            )

        if self.analysis_backend == "static" and self.llm_graph_enrichment_enabled:
            raise ValueError(
                "llm_graph_enrichment_enabled is incompatible with analysis_backend='static'"
            )

        if self.max_files < 0:
            raise ValueError("max_files must be non-negative (0 = unlimited)")

        if not 0.0 <= self.llm_graph_enrichment_confidence <= 1.0:
            raise ValueError("llm_graph_enrichment_confidence must be between 0.0 and 1.0")

        # Sync symbolic_execution_enabled with verification_level for backwards compatibility
        if self.verification_level in ("symbolic", "both"):
            self.symbolic_execution_enabled = True
        elif self.verification_level == "cfg":
            self.symbolic_execution_enabled = False

        logger.debug(
            f"PipelineConfig initialized: provider={self.llm_provider}, "
            f"model={self.llm_model}, "
            f"min_confidence={self.min_confidence}, "
            f"verification_enabled={self.verification_enabled}, "
            f"verification_level={self.verification_level}, "
            f"pathfinding_algorithm={self.pathfinding_algorithm}"
        )


def load_config_from_env(
    *,
    analysis_backend_override: Optional[str] = None,
    llm_analysis_mode_override: Optional[str] = None,
) -> PipelineConfig:
    """Load pipeline configuration from environment variables.

    Uses python-dotenv to load from .env file. Environment variables take
    precedence over .env file values.

    Expected environment variables:
        LLM_PROVIDER (optional): LLM provider 'openai' or 'ollama' (default: openai)
        OPENAI_API_KEY (required for OpenAI): OpenAI API key
        OPENAI_BASE_URL (optional): Override API base URL for OpenAI-compatible
            endpoints (Azure OpenAI, LiteLLM/vLLM proxy, ...). Default: official OpenAI.
        OPENAI_MODEL (optional): Model name (deprecated, use LLM_MODEL)
        LLM_MODEL (optional): Model name (default depends on provider)
        OLLAMA_BASE_URL (optional): Ollama server URL (default: http://localhost:11434)
        MAX_PATH_LENGTH (optional): Maximum path length (default: 15)
        MIN_CONFIDENCE (optional): Minimum confidence threshold (default: 0.5)
        VERIFICATION_ENABLED (optional): Enable verification (default: true)
        SYMBOLIC_EXECUTION_ENABLED (optional): Enable symbolic execution (default: false)
        VERIFICATION_LEVEL (optional): Verification level 'cfg', 'symbolic', or 'both' (default: cfg)
        SYMBOLIC_TIMEOUT (optional): Symbolic execution timeout in seconds (default: 60)
        USE_JOERN (optional): Use Joern for PDG analysis (default: false)
        USE_ASTAR (optional): Use A* pathfinding (default: true)
        USE_SEMANTIC_HEURISTIC (optional): Use semantic heuristic in A* (default: true)
        PATHFINDING_ALGORITHM (optional): Algorithm choice 'astar' or 'bfs' (default: astar)
        MAX_CONCURRENT_FILES (optional): Max concurrent file extractions (default: 4)
        MAX_FILES (optional): Maximum files to analyze in project mode (default: 0 = unlimited)

    Returns:
        PipelineConfig instance with values from environment.

    Raises:
        ValueError: If required variables are missing or invalid.
    """
    # Load from .env file if it exists
    load_dotenv()

    # Extract provider (default to openai for backwards compatibility)
    provider = os.getenv("LLM_PROVIDER", "openai").lower()

    # Extract API key (only required for OpenAI)
    api_key = os.getenv("OPENAI_API_KEY")

    # Optional base URL override for OpenAI-compatible endpoints
    # (Azure OpenAI, LiteLLM/vLLM proxies, self-hosted gateways, ...).
    # Empty string is treated as "unset" so a blank .env line falls back to the
    # official OpenAI endpoint.
    openai_base_url = os.getenv("OPENAI_BASE_URL") or None

    # Optional User-Agent override. Some third-party proxies block the openai
    # SDK's default UA ("Your request was blocked"); set this to anything
    # neutral. Empty string = unset.
    openai_user_agent = os.getenv("OPENAI_USER_AGENT") or None

    openai_json_mode = os.getenv("OPENAI_JSON_MODE", "true").lower() in (
        "true", "1", "yes", "on"
    )
    openai_thinking = os.getenv("OPENAI_THINKING") or None
    if openai_thinking:
        openai_thinking = openai_thinking.lower()

    try:
        openai_timeout = float(os.getenv("OPENAI_TIMEOUT", "60"))
    except ValueError:
        logger.warning("Invalid OPENAI_TIMEOUT, using default 60")
        openai_timeout = 60.0

    try:
        llm_max_retries = int(os.getenv("LLM_MAX_RETRIES", "2"))
    except ValueError:
        logger.warning("Invalid LLM_MAX_RETRIES, using default 2")
        llm_max_retries = 2

    try:
        llm_max_tokens = int(os.getenv("LLM_MAX_TOKENS", "4000"))
    except ValueError:
        logger.warning("Invalid LLM_MAX_TOKENS, using default 4000")
        llm_max_tokens = 4000

    try:
        llm_batch_max_chars = int(os.getenv("LLM_BATCH_MAX_CHARS", "8000"))
    except ValueError:
        logger.warning("Invalid LLM_BATCH_MAX_CHARS, using default 8000")
        llm_batch_max_chars = 8000

    analysis_backend = (
        analysis_backend_override or os.getenv("ANALYSIS_BACKEND", "llm")
    ).lower()
    llm_analysis_mode = (
        llm_analysis_mode_override or os.getenv("LLM_ANALYSIS_MODE", "targeted")
    ).lower()

    # Extract model (check both LLM_MODEL and legacy OPENAI_MODEL)
    # Default depends on provider, will be set in __post_init__ if not specified
    model = os.getenv("LLM_MODEL") or os.getenv("OPENAI_MODEL", "")

    try:
        max_path_length = int(os.getenv("MAX_PATH_LENGTH", "15"))
    except ValueError:
        logger.warning("Invalid MAX_PATH_LENGTH, using default 15")
        max_path_length = 15

    try:
        min_confidence = float(os.getenv("MIN_CONFIDENCE", "0.6"))
    except ValueError:
        logger.warning("Invalid MIN_CONFIDENCE, using default 0.6")
        min_confidence = 0.6

    verification_enabled = os.getenv("VERIFICATION_ENABLED", "true").lower() == "true"
    symbolic_execution_enabled = (
        os.getenv("SYMBOLIC_EXECUTION_ENABLED", "false").lower() == "true"
    )
    use_joern = os.getenv("USE_JOERN", "false").lower() == "true"
    use_semantic_heuristic = os.getenv("USE_SEMANTIC_HEURISTIC", "true").lower() == "true"
    use_astar = os.getenv("USE_ASTAR", "true").lower() == "true"

    pathfinding_algorithm = os.getenv("PATHFINDING_ALGORITHM", "astar").lower()
    if pathfinding_algorithm not in ("astar", "bfs"):
        logger.warning(
            f"Invalid PATHFINDING_ALGORITHM '{pathfinding_algorithm}', using 'astar'"
        )
        pathfinding_algorithm = "astar"

    verification_level = os.getenv("VERIFICATION_LEVEL", "cfg").lower()
    if verification_level not in ("cfg", "symbolic", "both"):
        logger.warning(
            f"Invalid VERIFICATION_LEVEL '{verification_level}', using 'cfg'"
        )
        verification_level = "cfg"

    try:
        symbolic_timeout = int(os.getenv("SYMBOLIC_TIMEOUT", "60"))
    except ValueError:
        logger.warning("Invalid SYMBOLIC_TIMEOUT, using default 60")
        symbolic_timeout = 60

    try:
        max_concurrent_files = int(os.getenv("MAX_CONCURRENT_FILES", "4"))
    except ValueError:
        logger.warning("Invalid MAX_CONCURRENT_FILES, using default 4")
        max_concurrent_files = 4

    try:
        max_concurrent_functions = int(os.getenv("MAX_CONCURRENT_FUNCTIONS", "2"))
    except ValueError:
        logger.warning("Invalid MAX_CONCURRENT_FUNCTIONS, using default 2")
        max_concurrent_functions = 2

    try:
        max_files = int(os.getenv("MAX_FILES", "0"))
    except ValueError:
        logger.warning("Invalid MAX_FILES, using default 0 (unlimited)")
        max_files = 0

    use_llm_graph_builder = os.getenv("USE_LLM_GRAPH_BUILDER", "true").lower() == "true"
    llm_graph_enrichment_enabled = os.getenv(
        "LLM_GRAPH_ENRICHMENT_ENABLED", "false"
    ).lower() in ("true", "1", "yes", "on")

    try:
        llm_graph_enrichment_confidence = float(
            os.getenv("LLM_GRAPH_ENRICHMENT_CONFIDENCE", "0.7")
        )
    except ValueError:
        logger.warning("Invalid LLM_GRAPH_ENRICHMENT_CONFIDENCE, using default 0.7")
        llm_graph_enrichment_confidence = 0.7

    cache_enabled = os.getenv("VTC_CACHE_ENABLED", "true").lower() in (
        "true", "1", "yes", "on"
    )
    cache_dir = os.getenv("VTC_CACHE_DIR") or None

    # Extract Ollama-specific settings
    ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    logger.info(f"Configuration loaded from environment variables (provider: {provider})")
    logger.debug(
        f"Config: provider={provider}, model={model}, max_path_length={max_path_length}, "
        f"min_confidence={min_confidence}, use_joern={use_joern}, "
        f"use_astar={use_astar}, use_semantic_heuristic={use_semantic_heuristic}, "
        f"pathfinding_algorithm={pathfinding_algorithm}, "
        f"verification_level={verification_level}, symbolic_timeout={symbolic_timeout}"
    )

    return PipelineConfig(
        llm_provider=provider,
        llm_api_key=api_key,
        llm_model=model,
        openai_base_url=openai_base_url,
        openai_user_agent=openai_user_agent,
        openai_timeout=openai_timeout,
        openai_json_mode=openai_json_mode,
        openai_thinking=openai_thinking,
        llm_max_retries=llm_max_retries,
        llm_max_tokens=llm_max_tokens,
        llm_batch_max_chars=llm_batch_max_chars,
        analysis_backend=analysis_backend,
        llm_analysis_mode=llm_analysis_mode,
        ollama_base_url=ollama_base_url,
        max_path_length=max_path_length,
        min_confidence=min_confidence,
        verification_enabled=verification_enabled,
        symbolic_execution_enabled=symbolic_execution_enabled,
        verification_level=verification_level,
        symbolic_timeout=symbolic_timeout,
        use_joern=use_joern,
        use_semantic_heuristic=use_semantic_heuristic,
        use_astar=use_astar,
        pathfinding_algorithm=pathfinding_algorithm,
        max_concurrent_files=max_concurrent_files,
        max_concurrent_functions=max_concurrent_functions,
        max_files=max_files,
        use_llm_graph_builder=use_llm_graph_builder,
        llm_graph_enrichment_enabled=llm_graph_enrichment_enabled,
        llm_graph_enrichment_confidence=llm_graph_enrichment_confidence,
        cache_enabled=cache_enabled,
        cache_dir=cache_dir,
    )
