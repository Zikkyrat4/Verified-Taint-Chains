"""Dispatch and persistence for external benchmark adapters."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from src.evaluation.benchmarks import cwe_bench_java, owasp_java
from src.evaluation.benchmarks.catalog import BENCHMARKS, ROOT, BenchmarkError, upstream_path
from src.evaluation.benchmarks.common import write_json_atomic
from src.evaluation.benchmarks.repository import validate_checkout

RESULTS_ROOT = ROOT / "evaluation" / "benchmarks"


def _output_paths(
    benchmark_id: str,
    backend: str,
    llm_analysis_mode: str,
    phase_label: str | None,
    save: Path | None,
    report_md: Path | None,
    selection: dict[str, Any],
) -> tuple[Path, Path]:
    label = phase_label or (
        backend if backend == "static" else f"{backend}-{llm_analysis_mode}"
    )
    if phase_label is None and selection:
        encoded = json.dumps(selection, sort_keys=True, separators=(",", ":")).encode()
        label += f"-subset-{hashlib.sha256(encoded).hexdigest()[:8]}"
    if not re.fullmatch(r"[A-Za-z0-9._-]+", label):
        raise BenchmarkError(
            "--phase-label may contain only letters, digits, '.', '_' and '-'"
        )
    output_dir = RESULTS_ROOT / benchmark_id
    return save or output_dir / f"{label}.json", report_md or output_dir / f"{label}.md"


def run_benchmark_command(
    benchmark_id: str,
    store_root: Path,
    *,
    backend: str,
    llm_analysis_mode: str,
    cwes: Iterable[str] = (),
    case_ids: Iterable[str] = (),
    all_cwes: bool = False,
    limit: int = 0,
    seed: int = 0,
    batch_size: int = 64,
    include_tests: bool = False,
    refresh_specs: bool = False,
    fail_fast: bool = False,
    retry_errors: bool = False,
    phase_label: str | None = None,
    save: Path | None = None,
    report_md: Path | None = None,
    max_concurrent_files: int | None = None,
    max_concurrent_functions: int | None = None,
    max_concurrent_llm_requests: int | None = None,
) -> dict[str, Any]:
    """Run the selected adapter and persist both machine and human reports."""
    spec = BENCHMARKS[benchmark_id]
    checkout = upstream_path(store_root, benchmark_id)
    validate_checkout(spec, checkout)
    common = {
        "backend": backend,
        "llm_analysis_mode": llm_analysis_mode,
        "cwes": tuple(cwes),
        "case_ids": tuple(case_ids),
        "all_cwes": all_cwes,
        "limit": limit,
        "seed": seed,
        "refresh_specs": refresh_specs,
        "fail_fast": fail_fast,
        "max_concurrent_files": max_concurrent_files,
        "max_concurrent_functions": max_concurrent_functions,
        "max_concurrent_llm_requests": max_concurrent_llm_requests,
    }
    selection = {
        key: value
        for key, value in {
            "cwes": sorted(common["cwes"]),
            "case_ids": sorted(common["case_ids"]),
            "all_cwes": all_cwes or None,
            "limit": limit or None,
            "seed": seed if limit else None,
        }.items()
        if value
    }
    json_path, markdown_path = _output_paths(
        benchmark_id,
        backend,
        llm_analysis_mode,
        phase_label,
        save,
        report_md,
        selection,
    )
    checkpoint_path = json_path.with_suffix(".checkpoint.json")
    if benchmark_id == "owasp-java":
        if retry_errors:
            raise BenchmarkError("--retry-errors is supported only by cwe-bench-java")
        report = asyncio.run(
            owasp_java.run(
                checkout,
                store_root,
                batch_size=batch_size,
                **common,
            )
        )
        markdown = owasp_java.render_markdown(report)
    elif benchmark_id == "cwe-bench-java":
        report = asyncio.run(
            cwe_bench_java.run(
                checkout,
                store_root,
                include_tests=include_tests,
                checkpoint_path=checkpoint_path,
                retry_errors=retry_errors,
                **common,
            )
        )
        markdown = cwe_bench_java.render_markdown(report)
    else:
        raise BenchmarkError(f"No adapter registered for {benchmark_id}")

    write_json_atomic(json_path, report)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = markdown_path.with_suffix(markdown_path.suffix + ".tmp")
    temporary.write_text(markdown, encoding="utf-8")
    temporary.replace(markdown_path)
    if benchmark_id == "cwe-bench-java":
        checkpoint_path.unlink(missing_ok=True)
    print(markdown, end="")
    print(f"[saved] {json_path}")
    print(f"[saved] {markdown_path}")
    return report
