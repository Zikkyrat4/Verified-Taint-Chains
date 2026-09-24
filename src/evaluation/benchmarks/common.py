"""Shared selection, pipeline, serialization, and metrics helpers."""

from __future__ import annotations

import json
import random
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar

from src.core.config import load_config_from_env
from src.evaluation.benchmarks.catalog import BenchmarkError, normalize_cwe

TYPE_TO_CWE = {
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "command_injection": "CWE-78",
    "path_traversal": "CWE-22",
    "xxe": "CWE-611",
    "ssrf": "CWE-918",
    "unsafe_deserialization": "CWE-502",
    "code_injection": "CWE-94",
    "open_redirect": "CWE-601",
}

T = TypeVar("T")


def select_limited(
    items: Sequence[T],
    *,
    limit: int,
    seed: int,
    identity: Callable[[T], str],
) -> list[T]:
    """Apply reproducible sampling only when an explicit limit is requested."""
    selected = list(items)
    if limit <= 0 or limit >= len(selected):
        return sorted(selected, key=identity)
    random.Random(seed).shuffle(selected)
    return sorted(selected[:limit], key=identity)


def build_pipeline_config(
    *,
    backend: str,
    llm_analysis_mode: str,
    cache_dir: Path,
    refresh_specs: bool,
    max_concurrent_files: int | None = None,
    max_concurrent_functions: int | None = None,
    max_concurrent_llm_requests: int | None = None,
) -> Any:
    """Build a benchmark config while preventing an environment-driven file cap."""
    config = load_config_from_env(
        analysis_backend_override=backend,
        llm_analysis_mode_override=llm_analysis_mode,
    )
    if not config.verification_enabled:
        raise BenchmarkError(
            "External benchmarks require VERIFICATION_ENABLED=true; "
            "unverified candidates are not benchmark findings"
        )
    config.max_files = 0
    config.cache_dir = str(cache_dir)
    config.cache_read_enabled = not refresh_specs
    if max_concurrent_files is not None:
        config.max_concurrent_files = max_concurrent_files
    if max_concurrent_functions is not None:
        config.max_concurrent_functions = max_concurrent_functions
    if max_concurrent_llm_requests is not None:
        config.max_concurrent_llm_requests = max_concurrent_llm_requests
    return config


def chain_to_record(chain: Any) -> dict[str, Any]:
    """Convert a chain to a stable, location-preserving benchmark schema."""
    source = chain.source
    sink = chain.sink
    vulnerability_type = chain.vulnerability_type.value
    explicit_cwe = getattr(sink, "cwe_id", None) or ""
    canonical_cwe = TYPE_TO_CWE.get(vulnerability_type)
    verification = getattr(chain, "verification_status", None)
    verification_status = getattr(verification, "value", verification)
    cfg_verification = getattr(chain, "cfg_verification_status", None)
    cfg_verification_status = getattr(cfg_verification, "value", cfg_verification)
    symbolic_verification = getattr(chain, "symbolic_verification_status", None)
    symbolic_verification_status = getattr(
        symbolic_verification, "value", symbolic_verification
    )
    if canonical_cwe is None and explicit_cwe and explicit_cwe.upper() != "CWE-UNKNOWN":
        try:
            canonical_cwe = normalize_cwe(explicit_cwe)
        except BenchmarkError:
            canonical_cwe = ""

    def location_record(node: Any) -> dict[str, Any]:
        location = getattr(node, "location", None)
        return {
            "variable": getattr(node, "variable_name", ""),
            "file": getattr(location, "file_path", "") if location else "",
            "line": getattr(location, "line_number", 0) if location else 0,
            "function": getattr(location, "function_name", "") if location else "",
        }

    return {
        "id": chain.id,
        "type": vulnerability_type,
        "cwe": canonical_cwe or "",
        "source": location_record(source),
        "sink": location_record(sink),
        "path": [location_record(node) for node in chain.path],
        "confidence": chain.confidence,
        "verification_status": verification_status,
        "verification": {
            "status": verification_status,
            "method": getattr(chain, "verification_method", None),
            "details": getattr(chain, "verification_details", None),
            "cfg_status": cfg_verification_status,
            "symbolic_status": symbolic_verification_status,
            "confidence": getattr(chain, "verification_confidence", None),
        },
    }


def confirmed_chain_records(chains: Sequence[Any]) -> list[dict[str, Any]]:
    """Serialize only chains that satisfy the pipeline's verified contract."""
    records = [chain_to_record(chain) for chain in chains]
    invalid = [
        record for record in records
        if record["verification_status"] != "verified"
    ]
    if invalid:
        raise BenchmarkError(
            "Pipeline contract violation: verified_chains contains "
            f"{len(invalid)} non-verified chain(s)"
        )
    return records


def binary_metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, float | int]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if tp + fp + tn + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "specificity": round(specificity, 4),
        "accuracy": round(accuracy, 4),
        "f1": round(f1, 4),
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    temporary.replace(path)
