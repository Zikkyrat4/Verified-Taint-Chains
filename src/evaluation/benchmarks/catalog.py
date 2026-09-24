"""Pinned upstream benchmark catalog and storage layout."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_BENCHMARK_ROOT = ROOT / ".vtc-benchmarks"

# This is the capability declared by VTC's README, not a value inferred from a
# benchmark oracle. Keeping it here prevents adapters from silently cherry-picking
# only cases that the current implementation happens to detect.
DECLARED_SUPPORTED_CWES = frozenset(
    {
        "CWE-22",
        "CWE-78",
        "CWE-79",
        "CWE-89",
        "CWE-94",
        "CWE-502",
        "CWE-601",
        "CWE-611",
        "CWE-918",
    }
)


@dataclass(frozen=True)
class BenchmarkSpec:
    """Immutable description of an external benchmark release."""

    benchmark_id: str
    title: str
    repository: str
    revision: str
    license: str
    scoring_unit: str
    required_paths: tuple[str, ...]
    description: str


BENCHMARKS: dict[str, BenchmarkSpec] = {
    "owasp-java": BenchmarkSpec(
        benchmark_id="owasp-java",
        title="OWASP BenchmarkJava 1.2",
        repository="https://github.com/OWASP-Benchmark/BenchmarkJava.git",
        revision="51f0a7cf8bb9d17ce1f6d72598c1d1c6ce90f661",
        license="GPL-2.0-only",
        scoring_unit="test-case",
        required_paths=(
            "expectedresults-1.2.csv",
            "src/main/java/org/owasp/benchmark/testcode",
        ),
        description="Synthetic Java servlet cases with positive and negative labels.",
    ),
    "cwe-bench-java": BenchmarkSpec(
        benchmark_id="cwe-bench-java",
        title="CWE-Bench-Java (IRIS dataset)",
        repository="https://github.com/iris-sast/iris.git",
        revision="3a12f45750f58135bcc58c7fdf4c20786b600e31",
        license="MIT",
        scoring_unit="CVE",
        required_paths=(
            "data/project_info.csv",
            "data/fix_info.csv",
            "data/fix_info_source_sink.csv",
        ),
        description="Real Java CVEs with vulnerable commits and fix-localization metadata.",
    ),
}


class BenchmarkError(RuntimeError):
    """A benchmark cannot be fetched, validated, prepared, or scored."""


def benchmark_root(override: Path | None = None) -> Path:
    """Resolve the external data root without placing upstream code in Git."""
    if override is not None:
        return override.expanduser().resolve()
    configured = os.getenv("VTC_BENCHMARK_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    return DEFAULT_BENCHMARK_ROOT


def upstream_path(root: Path, benchmark_id: str) -> Path:
    return root / "upstream" / benchmark_id


def case_source_path(root: Path, case_id: int) -> Path:
    # Numeric directories avoid exposing CVE/project labels through file paths
    # supplied to the LLM. The mapping remains only in the scorer's metadata.
    return root / "cases" / "cwe-bench-java" / f"{case_id:04d}"


def normalize_cwe(value: str) -> str:
    """Normalize ``22``, ``CWE-022`` and ``cwe_22`` to ``CWE-22``."""
    match = re.fullmatch(r"(?:CWE[-_ ]?)?0*(\d+)", value.strip(), re.IGNORECASE)
    if not match:
        raise BenchmarkError(f"Invalid CWE identifier: {value!r}")
    return f"CWE-{int(match.group(1))}"
