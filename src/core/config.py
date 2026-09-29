"""Typed configuration for the VTC analysis pipeline."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from src.core.config_loader import load_config_document, read_config_file

_TRUE_VALUES = frozenset({"true", "1", "yes", "on"})
_FALSE_VALUES = frozenset({"false", "0", "no", "off"})

# One schema rejects misspellings instead of silently benchmarking with defaults.
CONFIG_SCHEMA: dict[str, frozenset[str]] = {
    "llm": frozenset(
        {
            "provider",
            "model",
            "max_retries",
            "max_tokens",
            "truncation_max_tokens",
            "batch_max_chars",
        }
    ),
    "openai": frozenset({"base_url", "user_agent", "timeout", "json_mode", "thinking"}),
    "ollama": frozenset({"base_url", "min_num_predict", "seed", "json_format"}),
    "analysis": frozenset({"backend", "llm_mode", "min_confidence", "max_files", "fast_prefilter"}),
    "performance": frozenset(
        {
            "max_concurrent_files",
            "max_concurrent_functions",
            "max_concurrent_llm_requests",
        }
    ),
    "graph": frozenset(
        {
            "pathfinding_algorithm",
            "max_path_length",
            "max_candidate_chains",
            "use_joern",
            "use_semantic_heuristic",
            "use_codebert",
            "builder",
            "llm_enrichment_enabled",
            "llm_enrichment_confidence",
        }
    ),
    "verification": frozenset({"enabled", "level", "symbolic_timeout"}),
    "cache": frozenset({"enabled", "directory"}),
    "logging": frozenset({"level", "file"}),
    "benchmark": frozenset({"directory"}),
}


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError("expected true or false")


def _parse_optional_string(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _parse_optional_seed(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, str) and value.strip().lower() in {
        "",
        "none",
        "off",
        "false",
    }:
        return None
    return int(value)


def _parse_graph_builder(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized == "enhanced":
        return True
    if normalized == "regex":
        return False
    try:
        return _parse_bool(value)
    except ValueError as error:
        raise ValueError("expected 'enhanced' or 'regex'") from error


def _validate_document(document: Mapping[str, Any]) -> None:
    for section, values in document.items():
        if section not in CONFIG_SCHEMA:
            raise ValueError(f"Unknown configuration section [{section}]")
        if not isinstance(values, Mapping):
            raise ValueError(f"Configuration section [{section}] must be a table")
        unknown = set(values) - CONFIG_SCHEMA[section]
        if unknown:
            names = ", ".join(sorted(unknown))
            raise ValueError(f"Unknown option(s) in [{section}]: {names}")


def _validate_config_file(path: Path | None) -> None:
    """Validate base settings and every profile, including unselected ones."""
    if path is None:
        return
    raw = read_config_file(path)
    base = {
        key: value for key, value in raw.items() if key not in {"version", "profile", "profiles"}
    }
    _validate_document(base)
    profiles = raw.get("profiles", {})
    if not isinstance(profiles, Mapping):
        raise ValueError(f"'profiles' must be a TOML table in {path}")
    for name, values in profiles.items():
        if not isinstance(values, Mapping):
            raise ValueError(f"Profile {name!r} must be a TOML table in {path}")
        try:
            _validate_document(values)
        except ValueError as error:
            raise ValueError(f"Invalid profile {name!r}: {error}") from error


@dataclass
class PipelineConfig:
    """Complete, validated configuration consumed by the analysis pipeline."""

    llm_provider: str = "openai"
    llm_api_key: str | None = None
    llm_model: str = ""
    openai_base_url: str | None = None
    openai_user_agent: str | None = None
    openai_timeout: float = 300.0
    openai_json_mode: bool = True
    openai_thinking: str | None = None
    llm_max_retries: int = 2
    llm_max_tokens: int = 4000
    llm_truncation_max_tokens: int = 16000
    llm_batch_max_chars: int = 8000
    analysis_backend: str = "llm"
    llm_analysis_mode: str = "targeted"
    ollama_base_url: str = "http://localhost:11434"
    ollama_min_num_predict: int = 4096
    ollama_seed: int | None = 42
    ollama_json_format: bool = True
    max_path_length: int = 15
    max_candidate_chains: int = 10000
    min_confidence: float = 0.6
    verification_enabled: bool = True
    symbolic_execution_enabled: bool = False
    verification_level: str = "cfg"
    symbolic_timeout: int = 60
    use_joern: bool = False
    use_semantic_heuristic: bool = True
    use_codebert: bool = False
    use_astar: bool = True
    pathfinding_algorithm: str = "astar"
    max_concurrent_files: int = 4
    max_concurrent_functions: int = 2
    max_concurrent_llm_requests: int = 5
    max_files: int = 0
    fast_prefilter: bool = False
    use_llm_graph_builder: bool = True
    llm_graph_enrichment_enabled: bool = False
    llm_graph_enrichment_confidence: float = 0.7
    cache_enabled: bool = True
    cache_read_enabled: bool = True
    cache_dir: str | None = None
    log_level: str = "INFO"
    log_file: str | None = None
    benchmark_dir: str = ".vtc-benchmarks"
    require_credentials: bool = field(default=True, repr=False, compare=False)
    config_file: str | None = field(default=None, init=False)
    config_profile: str | None = field(default=None, init=False)
    value_sources: dict[str, str] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        self.llm_provider = self.llm_provider.lower()
        self.analysis_backend = self.analysis_backend.lower()
        self.llm_analysis_mode = self.llm_analysis_mode.lower()
        self.pathfinding_algorithm = self.pathfinding_algorithm.lower()
        self.verification_level = self.verification_level.lower()
        self.log_level = self.log_level.upper()
        if self.openai_thinking:
            self.openai_thinking = self.openai_thinking.lower()

        if self.llm_provider not in ("openai", "ollama"):
            raise ValueError("llm_provider must be 'openai' or 'ollama'")
        if self.analysis_backend not in ("llm", "static", "hybrid"):
            raise ValueError("analysis_backend must be 'llm', 'static', or 'hybrid'")
        if (
            self.require_credentials
            and self.analysis_backend != "static"
            and self.llm_provider == "openai"
            and not self.llm_api_key
        ):
            raise ValueError(
                "llm_api_key is required when using OpenAI provider. "
                "Set OPENAI_API_KEY environment variable."
            )
        if not self.llm_model:
            self.llm_model = "gpt-4-turbo" if self.llm_provider == "openai" else "llama3:latest"
        if not 0.0 <= self.min_confidence <= 1.0:
            raise ValueError("min_confidence must be between 0.0 and 1.0")
        if self.max_path_length < 1:
            raise ValueError("max_path_length must be at least 1")
        if self.max_candidate_chains < 1:
            raise ValueError("max_candidate_chains must be at least 1")
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
        if self.max_concurrent_llm_requests < 1:
            raise ValueError("max_concurrent_llm_requests must be at least 1")
        if self.openai_timeout <= 0:
            raise ValueError("openai_timeout must be positive")
        if self.openai_thinking not in (None, "enabled", "disabled"):
            raise ValueError("openai_thinking must be 'enabled', 'disabled', or None")
        if self.llm_max_retries < 1:
            raise ValueError("llm_max_retries must be at least 1")
        if self.llm_max_tokens < 1:
            raise ValueError("llm_max_tokens must be at least 1")
        if self.llm_truncation_max_tokens < self.llm_max_tokens:
            raise ValueError("llm_truncation_max_tokens must be at least llm_max_tokens")
        if self.llm_batch_max_chars < 0:
            raise ValueError("llm_batch_max_chars must be non-negative")
        if self.llm_analysis_mode not in ("targeted", "exhaustive"):
            raise ValueError("llm_analysis_mode must be 'targeted' or 'exhaustive'")
        if self.ollama_min_num_predict < 1:
            raise ValueError("ollama_min_num_predict must be at least 1")
        if self.analysis_backend == "static" and self.llm_graph_enrichment_enabled:
            raise ValueError(
                "llm_graph_enrichment_enabled is incompatible with " "analysis_backend='static'"
            )
        if self.max_files < 0:
            raise ValueError("max_files must be non-negative (0 = unlimited)")
        if not 0.0 <= self.llm_graph_enrichment_confidence <= 1.0:
            raise ValueError("llm_graph_enrichment_confidence must be between 0.0 and 1.0")
        if self.log_level not in {
            "TRACE",
            "DEBUG",
            "INFO",
            "SUCCESS",
            "WARNING",
            "ERROR",
            "CRITICAL",
        }:
            raise ValueError("log_level must be a valid Loguru level")

        self.use_astar = self.pathfinding_algorithm == "astar"
        self.symbolic_execution_enabled = self.verification_level in (
            "symbolic",
            "both",
        )

    def stage1_cache_identity(self) -> str:
        """Return output-affecting LLM options for the Stage 1 cache key."""
        return ";".join(
            (
                f"max_tokens={self.llm_max_tokens}",
                f"truncation_max_tokens={self.llm_truncation_max_tokens}",
                f"openai_base_url={self.openai_base_url or ''}",
                f"openai_json_mode={self.openai_json_mode}",
                f"openai_thinking={self.openai_thinking or 'auto'}",
                f"ollama_min_num_predict={self.ollama_min_num_predict}",
                f"ollama_seed={self.ollama_seed}",
                f"ollama_json_format={self.ollama_json_format}",
            )
        )

    def validate(self) -> None:
        """Normalize and validate values after an explicit runtime override."""
        self.__post_init__()


@dataclass(frozen=True)
class _Setting:
    field_name: str
    section: str
    key: str
    env_names: tuple[str, ...]
    default: Any
    parser: Callable[[Any], Any]


_SETTINGS = (
    _Setting("llm_provider", "llm", "provider", ("LLM_PROVIDER",), "openai", str),
    _Setting("llm_model", "llm", "model", ("LLM_MODEL", "OPENAI_MODEL"), "", str),
    _Setting(
        "openai_base_url", "openai", "base_url", ("OPENAI_BASE_URL",), None, _parse_optional_string
    ),
    _Setting(
        "openai_user_agent",
        "openai",
        "user_agent",
        ("OPENAI_USER_AGENT",),
        None,
        _parse_optional_string,
    ),
    _Setting("openai_timeout", "openai", "timeout", ("OPENAI_TIMEOUT",), 300.0, float),
    _Setting("openai_json_mode", "openai", "json_mode", ("OPENAI_JSON_MODE",), True, _parse_bool),
    _Setting(
        "openai_thinking", "openai", "thinking", ("OPENAI_THINKING",), None, _parse_optional_string
    ),
    _Setting("llm_max_retries", "llm", "max_retries", ("LLM_MAX_RETRIES",), 2, int),
    _Setting("llm_max_tokens", "llm", "max_tokens", ("LLM_MAX_TOKENS",), 4000, int),
    _Setting(
        "llm_truncation_max_tokens",
        "llm",
        "truncation_max_tokens",
        ("LLM_TRUNCATION_MAX_TOKENS",),
        16000,
        int,
    ),
    _Setting("llm_batch_max_chars", "llm", "batch_max_chars", ("LLM_BATCH_MAX_CHARS",), 8000, int),
    _Setting("analysis_backend", "analysis", "backend", ("ANALYSIS_BACKEND",), "llm", str),
    _Setting("llm_analysis_mode", "analysis", "llm_mode", ("LLM_ANALYSIS_MODE",), "targeted", str),
    _Setting("min_confidence", "analysis", "min_confidence", ("MIN_CONFIDENCE",), 0.6, float),
    _Setting("max_files", "analysis", "max_files", ("MAX_FILES",), 0, int),
    _Setting(
        "fast_prefilter", "analysis", "fast_prefilter", ("VTC_FAST_PREFILTER",), False, _parse_bool
    ),
    _Setting(
        "ollama_base_url", "ollama", "base_url", ("OLLAMA_BASE_URL",), "http://localhost:11434", str
    ),
    _Setting(
        "ollama_min_num_predict",
        "ollama",
        "min_num_predict",
        ("OLLAMA_MIN_NUM_PREDICT",),
        4096,
        int,
    ),
    _Setting("ollama_seed", "ollama", "seed", ("OLLAMA_SEED",), 42, _parse_optional_seed),
    _Setting(
        "ollama_json_format", "ollama", "json_format", ("OLLAMA_JSON_FORMAT",), True, _parse_bool
    ),
    _Setting("max_path_length", "graph", "max_path_length", ("MAX_PATH_LENGTH",), 15, int),
    _Setting(
        "max_candidate_chains",
        "graph",
        "max_candidate_chains",
        ("MAX_CANDIDATE_CHAINS",),
        10000,
        int,
    ),
    _Setting("use_joern", "graph", "use_joern", ("USE_JOERN",), False, _parse_bool),
    _Setting(
        "use_semantic_heuristic",
        "graph",
        "use_semantic_heuristic",
        ("USE_SEMANTIC_HEURISTIC",),
        True,
        _parse_bool,
    ),
    _Setting("use_codebert", "graph", "use_codebert", ("VTC_USE_CODEBERT",), False, _parse_bool),
    _Setting(
        "pathfinding_algorithm",
        "graph",
        "pathfinding_algorithm",
        ("PATHFINDING_ALGORITHM",),
        "astar",
        str,
    ),
    _Setting(
        "use_llm_graph_builder",
        "graph",
        "builder",
        ("USE_LLM_GRAPH_BUILDER",),
        True,
        _parse_graph_builder,
    ),
    _Setting(
        "llm_graph_enrichment_enabled",
        "graph",
        "llm_enrichment_enabled",
        ("LLM_GRAPH_ENRICHMENT_ENABLED",),
        False,
        _parse_bool,
    ),
    _Setting(
        "llm_graph_enrichment_confidence",
        "graph",
        "llm_enrichment_confidence",
        ("LLM_GRAPH_ENRICHMENT_CONFIDENCE",),
        0.7,
        float,
    ),
    _Setting(
        "verification_enabled",
        "verification",
        "enabled",
        ("VERIFICATION_ENABLED",),
        True,
        _parse_bool,
    ),
    _Setting("verification_level", "verification", "level", ("VERIFICATION_LEVEL",), "cfg", str),
    _Setting(
        "symbolic_timeout", "verification", "symbolic_timeout", ("SYMBOLIC_TIMEOUT",), 60, int
    ),
    _Setting(
        "max_concurrent_files",
        "performance",
        "max_concurrent_files",
        ("MAX_CONCURRENT_FILES",),
        4,
        int,
    ),
    _Setting(
        "max_concurrent_functions",
        "performance",
        "max_concurrent_functions",
        ("MAX_CONCURRENT_FUNCTIONS",),
        2,
        int,
    ),
    _Setting(
        "max_concurrent_llm_requests",
        "performance",
        "max_concurrent_llm_requests",
        ("MAX_CONCURRENT_LLM_REQUESTS",),
        5,
        int,
    ),
    _Setting("cache_enabled", "cache", "enabled", ("VTC_CACHE_ENABLED",), True, _parse_bool),
    _Setting("cache_dir", "cache", "directory", ("VTC_CACHE_DIR",), None, _parse_optional_string),
    _Setting("log_level", "logging", "level", ("LOG_LEVEL",), "INFO", str),
    _Setting("log_file", "logging", "file", ("LOG_FILE",), None, _parse_optional_string),
    _Setting(
        "benchmark_dir",
        "benchmark",
        "directory",
        ("VTC_BENCHMARK_DIR",),
        ".vtc-benchmarks",
        str,
    ),
)


def _setting_value(
    setting: _Setting,
    document: Mapping[str, Any],
) -> tuple[Any, str]:
    raw = setting.default
    source = "default"
    section = document.get(setting.section, {})
    if setting.key in section:
        raw = section[setting.key]
        source = f"toml:{setting.section}.{setting.key}"

    for env_name in setting.env_names:
        if env_name in os.environ and os.environ[env_name] != "":
            raw = os.environ[env_name]
            source = f"env:{env_name}"
            break

    try:
        return setting.parser(raw), source
    except (TypeError, ValueError) as error:
        name = source.removeprefix("env:").removeprefix("toml:")
        raise ValueError(f"Invalid value for {name}: {raw!r} ({error})") from error


def load_config(
    *,
    config_path: Path | None = None,
    analysis_backend_override: str | None = None,
    llm_analysis_mode_override: str | None = None,
    require_credentials: bool = True,
) -> PipelineConfig:
    """Load defaults, TOML/profile, `.env`, process ENV, then explicit overrides."""
    load_dotenv()
    document, loaded_path, profile = load_config_document(config_path)
    _validate_config_file(loaded_path)
    _validate_document(document)

    values: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for setting in _SETTINGS:
        value, source = _setting_value(setting, document)
        values[setting.field_name] = value
        sources[setting.field_name] = source

    # API keys intentionally stay outside TOML so configuration can be committed.
    values["llm_api_key"] = os.getenv("OPENAI_API_KEY") or None
    sources["llm_api_key"] = "env:OPENAI_API_KEY" if values["llm_api_key"] else "unset"
    values["require_credentials"] = require_credentials

    if analysis_backend_override:
        values["analysis_backend"] = analysis_backend_override
        sources["analysis_backend"] = "cli"
    if llm_analysis_mode_override:
        values["llm_analysis_mode"] = llm_analysis_mode_override
        sources["llm_analysis_mode"] = "cli"

    # Keep the old boolean as a compatibility alias when no level was supplied.
    if (
        "VERIFICATION_LEVEL" not in os.environ
        and "SYMBOLIC_EXECUTION_ENABLED" in os.environ
        and _parse_bool(os.environ["SYMBOLIC_EXECUTION_ENABLED"])
    ):
        values["verification_level"] = "symbolic"
        sources["verification_level"] = "env:SYMBOLIC_EXECUTION_ENABLED"

    config = PipelineConfig(**values)
    config.config_file = str(loaded_path) if loaded_path else None
    config.config_profile = profile
    config.value_sources = sources
    return config


def load_config_from_env(
    *,
    analysis_backend_override: str | None = None,
    llm_analysis_mode_override: str | None = None,
) -> PipelineConfig:
    """Backward-compatible alias for callers that previously loaded only ENV."""
    return load_config(
        analysis_backend_override=analysis_backend_override,
        llm_analysis_mode_override=llm_analysis_mode_override,
    )


def config_as_dict(config: PipelineConfig, *, include_sources: bool = False) -> dict[str, Any]:
    """Return a redacted, sectioned representation suitable for CLI output."""
    result: dict[str, Any] = {
        "config_file": config.config_file,
        "profile": config.config_profile,
        "llm": {
            "provider": config.llm_provider,
            "model": config.llm_model,
            "api_key": "<set>" if config.llm_api_key else "<unset>",
            "max_retries": config.llm_max_retries,
            "max_tokens": config.llm_max_tokens,
            "truncation_max_tokens": config.llm_truncation_max_tokens,
            "batch_max_chars": config.llm_batch_max_chars,
        },
        "openai": {
            "base_url": config.openai_base_url,
            "user_agent": config.openai_user_agent,
            "timeout": config.openai_timeout,
            "json_mode": config.openai_json_mode,
            "thinking": config.openai_thinking,
        },
        "ollama": {
            "base_url": config.ollama_base_url,
            "min_num_predict": config.ollama_min_num_predict,
            "seed": config.ollama_seed,
            "json_format": config.ollama_json_format,
        },
        "analysis": {
            "backend": config.analysis_backend,
            "llm_mode": config.llm_analysis_mode,
            "min_confidence": config.min_confidence,
            "max_files": config.max_files,
            "fast_prefilter": config.fast_prefilter,
        },
        "performance": {
            "max_concurrent_files": config.max_concurrent_files,
            "max_concurrent_functions": config.max_concurrent_functions,
            "max_concurrent_llm_requests": config.max_concurrent_llm_requests,
        },
        "graph": {
            "pathfinding_algorithm": config.pathfinding_algorithm,
            "max_path_length": config.max_path_length,
            "max_candidate_chains": config.max_candidate_chains,
            "use_joern": config.use_joern,
            "use_semantic_heuristic": config.use_semantic_heuristic,
            "use_codebert": config.use_codebert,
            "builder": "enhanced" if config.use_llm_graph_builder else "regex",
            "llm_enrichment_enabled": config.llm_graph_enrichment_enabled,
            "llm_enrichment_confidence": config.llm_graph_enrichment_confidence,
        },
        "verification": {
            "enabled": config.verification_enabled,
            "level": config.verification_level,
            "symbolic_timeout": config.symbolic_timeout,
        },
        "cache": {"enabled": config.cache_enabled, "directory": config.cache_dir},
        "logging": {"level": config.log_level, "file": config.log_file},
        "benchmark": {"directory": config.benchmark_dir},
    }
    if include_sources:
        result["value_sources"] = dict(config.value_sources)
    return result


DEFAULT_CONFIG_TEMPLATE = """# VTC configuration. Keep API keys in .env or the process environment.
version = 1
profile = "balanced"

[llm]
provider = "openai"
model = "gpt-4-turbo"
max_retries = 2
max_tokens = 4000
truncation_max_tokens = 16000
batch_max_chars = 8000

[openai]
timeout = 300
json_mode = true
# base_url = "http://localhost:8000/v1"
# thinking = "disabled"

[ollama]
base_url = "http://localhost:11434"
min_num_predict = 4096
seed = 42
json_format = true

[analysis]
backend = "llm"
llm_mode = "targeted"
min_confidence = 0.6
max_files = 0
fast_prefilter = false

[performance]
max_concurrent_files = 4
max_concurrent_functions = 2
max_concurrent_llm_requests = 5

[graph]
pathfinding_algorithm = "astar"
max_path_length = 15
max_candidate_chains = 10000
use_joern = false
use_semantic_heuristic = true
use_codebert = false
builder = "enhanced"
llm_enrichment_enabled = false
llm_enrichment_confidence = 0.7

[verification]
enabled = true
level = "cfg"
symbolic_timeout = 60

[cache]
enabled = true
# directory = ".vtc-cache"

[logging]
level = "INFO"
# file = "off"

[benchmark]
directory = ".vtc-benchmarks"

[profiles.fast.analysis]
llm_mode = "targeted"
fast_prefilter = true

[profiles.fast.performance]
max_concurrent_files = 2
max_concurrent_functions = 1
max_concurrent_llm_requests = 2

[profiles.thorough.analysis]
llm_mode = "exhaustive"
fast_prefilter = false

[profiles.thorough.performance]
max_concurrent_llm_requests = 5

[profiles.balanced]
# Uses the base settings above without changes.
"""
