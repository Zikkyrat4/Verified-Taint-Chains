"""OWASP BenchmarkJava adapter and test-case-level scorer."""

from __future__ import annotations

import csv
import time
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from src.evaluation.benchmarks.catalog import (
    BENCHMARKS,
    DECLARED_SUPPORTED_CWES,
    BenchmarkError,
    normalize_cwe,
)
from src.evaluation.benchmarks.common import (
    binary_metrics,
    build_pipeline_config,
    confirmed_chain_records,
    select_limited,
    utc_now,
)
from src.evaluation.engine import analysis_metadata
from src.pipeline.orchestrator import SimplePipeline
from src.utils.logger import get_logger

logger = get_logger()
SPEC = BENCHMARKS["owasp-java"]
ORACLE_FILE = "expectedresults-1.2.csv"
SOURCE_ROOT = "src/main/java/org/owasp/benchmark/testcode"


@dataclass(frozen=True)
class OwaspCase:
    test_name: str
    category: str
    vulnerable: bool
    cwe: str
    source_file: str


def load_cases(checkout: Path) -> list[OwaspCase]:
    """Load the official CSV without copying labels into the analysis tree."""
    cases: list[OwaspCase] = []
    with (checkout / ORACLE_FILE).open(newline="", encoding="utf-8") as handle:
        rows = csv.reader(line for line in handle if not line.lstrip().startswith("#"))
        for row_number, row in enumerate(rows, 2):
            if len(row) < 4:
                raise BenchmarkError(f"Malformed OWASP oracle row {row_number}: {row!r}")
            test_name, category, vulnerable, raw_cwe = (cell.strip() for cell in row[:4])
            if vulnerable.lower() not in {"true", "false"}:
                raise BenchmarkError(
                    f"Malformed vulnerability label at OWASP row {row_number}: {vulnerable!r}"
                )
            cases.append(
                OwaspCase(
                    test_name=test_name,
                    category=category,
                    vulnerable=vulnerable.lower() == "true",
                    cwe=normalize_cwe(raw_cwe),
                    source_file=f"{SOURCE_ROOT}/{test_name}.java",
                )
            )
    if not cases:
        raise BenchmarkError("OWASP oracle contains no cases")
    return cases


def select_cases(
    cases: Sequence[OwaspCase],
    *,
    cwes: Iterable[str] = (),
    case_ids: Iterable[str] = (),
    all_cwes: bool = False,
    limit: int = 0,
    seed: int = 0,
) -> list[OwaspCase]:
    requested_cwes = {normalize_cwe(cwe) for cwe in cwes}
    if requested_cwes and all_cwes:
        raise BenchmarkError("--cwe and --all-cwes are mutually exclusive")
    allowed_cwes = (
        requested_cwes
        if requested_cwes
        else ({case.cwe for case in cases} if all_cwes else DECLARED_SUPPORTED_CWES)
    )
    requested_cases = set()
    for case_id in case_ids:
        normalized = case_id.strip().lower()
        if normalized.isdigit():
            normalized = normalized.lstrip("0") or "0"
        requested_cases.add(normalized)

    def case_requested(case: OwaspCase) -> bool:
        numeric_id = case.test_name.removeprefix("BenchmarkTest").lstrip("0") or "0"
        return not requested_cases or bool(
            {case.test_name.lower(), numeric_id} & requested_cases
        )

    selected = [
        case for case in cases if case.cwe in allowed_cwes and case_requested(case)
    ]
    selected = select_limited(
        selected,
        limit=limit,
        seed=seed,
        identity=lambda case: case.test_name,
    )
    if not selected:
        raise BenchmarkError("OWASP selection contains no test cases")
    return selected


def score_cases(
    cases: Sequence[OwaspCase],
    findings_by_case: Mapping[str, Sequence[dict[str, Any]]],
    errors: Mapping[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Score one binary prediction per test case, never per duplicate finding."""
    errors = errors or {}
    rows: list[dict[str, Any]] = []
    per_cwe_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "errors": 0}
    )
    totals = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    total_findings = 0
    wrong_cwe_findings = 0

    for case in cases:
        findings = list(findings_by_case.get(case.test_name, []))
        total_findings += len(findings)
        matching = [finding for finding in findings if finding.get("cwe") == case.cwe]
        wrong_cwe_findings += len(findings) - len(matching)
        error = errors.get(case.test_name)
        if error:
            classification = "error"
            per_cwe_counts[case.cwe]["errors"] += 1
        else:
            detected = bool(matching)
            if case.vulnerable and detected:
                classification = "tp"
            elif not case.vulnerable and detected:
                classification = "fp"
            elif case.vulnerable:
                classification = "fn"
            else:
                classification = "tn"
            totals[classification] += 1
            per_cwe_counts[case.cwe][classification] += 1

        rows.append(
            {
                **asdict(case),
                "status": classification,
                "detected": bool(matching) if not error else None,
                "matching_finding_count": len(matching),
                "wrong_cwe_finding_count": len(findings) - len(matching),
                "findings": findings,
                "error": error,
            }
        )

    aggregate: dict[str, Any] = binary_metrics(**totals)
    aggregate.update(
        {
            "selected_cases": len(cases),
            "scored_cases": sum(totals.values()),
            "execution_errors": len(errors),
            "total_findings": total_findings,
            "wrong_cwe_findings": wrong_cwe_findings,
        }
    )
    aggregate["per_cwe"] = {
        cwe: {
            **binary_metrics(
                counts["tp"], counts["fp"], counts["tn"], counts["fn"]
            ),
            "errors": counts["errors"],
        }
        for cwe, counts in sorted(per_cwe_counts.items())
    }
    return rows, aggregate


async def run(
    checkout: Path,
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
    refresh_specs: bool = False,
    fail_fast: bool = False,
    max_concurrent_files: int | None = None,
    max_concurrent_functions: int | None = None,
    max_concurrent_llm_requests: int | None = None,
) -> dict[str, Any]:
    if batch_size < 1:
        raise BenchmarkError("--batch-size must be at least 1")
    all_cases = load_cases(checkout)
    cases = select_cases(
        all_cases,
        cwes=cwes,
        case_ids=case_ids,
        all_cwes=all_cwes,
        limit=limit,
        seed=seed,
    )
    missing = [case.source_file for case in cases if not (checkout / case.source_file).is_file()]
    if missing:
        raise BenchmarkError(f"OWASP checkout is missing {len(missing)} selected source files")

    config = build_pipeline_config(
        backend=backend,
        llm_analysis_mode=llm_analysis_mode,
        cache_dir=store_root / "cache" / SPEC.benchmark_id,
        refresh_specs=refresh_specs,
        max_concurrent_files=max_concurrent_files,
        max_concurrent_functions=max_concurrent_functions,
        max_concurrent_llm_requests=max_concurrent_llm_requests,
    )
    pipeline = SimplePipeline(config)
    findings_by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    errors: dict[str, str] = {}
    orphan_findings: list[dict[str, Any]] = []
    known_names = {case.test_name for case in cases}
    started_at = utc_now()
    started = time.monotonic()

    try:
        for offset in range(0, len(cases), batch_size):
            batch = cases[offset : offset + batch_size]
            logger.info(
                f"OWASP batch {offset // batch_size + 1}: "
                f"cases {offset + 1}-{offset + len(batch)} of {len(cases)}"
            )
            paths = [str(checkout / case.source_file) for case in batch]
            try:
                result = await pipeline.run_project(paths, show_progress=False)
            except Exception as error:
                message = f"{type(error).__name__}: {error}"
                for case in batch:
                    errors[case.test_name] = message
                if fail_fast:
                    raise BenchmarkError(message) from error
                continue

            extraction_errors = result.get("metrics", {}).get("extraction_errors", {})
            for path, messages in extraction_errors.items():
                test_name = Path(path).stem
                if test_name in known_names:
                    errors[test_name] = "; ".join(str(message) for message in messages)

            for finding in confirmed_chain_records(
                result.get("verified_chains", [])
            ):
                sink_name = Path(finding["sink"]["file"]).stem
                source_name = Path(finding["source"]["file"]).stem
                test_name = sink_name if sink_name in known_names else source_name
                if test_name in known_names:
                    findings_by_case[test_name].append(finding)
                else:
                    orphan_findings.append(finding)
    finally:
        await pipeline.aclose()

    rows, aggregate = score_cases(cases, findings_by_case, errors)
    selected_cwes = sorted({case.cwe for case in cases})
    available_cwes = sorted({case.cwe for case in all_cases})
    analysis = analysis_metadata(config)
    analysis["evaluation_policy"] = {
        "scoring_unit": "official_testcase",
        "expected_cwe_required": True,
        "one_prediction_per_testcase": True,
        "duplicate_findings_multiply_counts": False,
        "unmatched_findings_count_as_fp": True,
        "precision_defined": True,
    }
    return {
        "schema_version": 1,
        "benchmark": {
            "id": SPEC.benchmark_id,
            "title": SPEC.title,
            "repository": SPEC.repository,
            "revision": SPEC.revision,
            "license": SPEC.license,
            "scoring_unit": SPEC.scoring_unit,
            "oracle": ORACLE_FILE,
        },
        "run": {
            "started_at": started_at,
            "duration_seconds": round(time.monotonic() - started, 3),
            "analysis": analysis,
            "selection": {
                "requested_cwes": [normalize_cwe(cwe) for cwe in cwes],
                "selected_cwes": selected_cwes,
                "all_cwes": all_cwes,
                "case_ids": list(case_ids),
                "limit": limit,
                "seed": seed,
                "batch_size": batch_size,
            },
            "integrity": {
                "oracle_exposed_to_pipeline": False,
                "target_cwe_exposed_to_pipeline": False,
                "public_corpus_pretraining_contamination_possible": True,
            },
        },
        "coverage": {
            "upstream_cases": len(all_cases),
            "available_cwes": available_cwes,
            "declared_supported_cwes": sorted(DECLARED_SUPPORTED_CWES),
            "selected_cases": len(cases),
            "selected_positive": sum(case.vulnerable for case in cases),
            "selected_negative": sum(not case.vulnerable for case in cases),
        },
        "aggregate": aggregate,
        "cases": rows,
        "orphan_findings": orphan_findings,
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    aggregate = report["aggregate"]
    run_info = report["run"]
    lines = [
        "# VTC / OWASP BenchmarkJava",
        "",
        f"- Upstream revision: `{report['benchmark']['revision']}`",
        f"- Backend: `{run_info['analysis']['backend']}`",
        f"- LLM mode: `{run_info['analysis']['llm_analysis_mode']}`",
        f"- Cases scored: {aggregate['scored_cases']} / {aggregate['selected_cases']}",
        "- Unit: one prediction per official test case (duplicate chains do not multiply counts)",
        "",
        "## Aggregate",
        "",
        "| TP | FP | TN | FN | Precision | Recall | Specificity | F1 | Errors |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| {aggregate['tp']} | {aggregate['fp']} | {aggregate['tn']} | "
            f"{aggregate['fn']} | {aggregate['precision']:.2%} | "
            f"{aggregate['recall']:.2%} | {aggregate['specificity']:.2%} | "
            f"{aggregate['f1']:.4f} | {aggregate['execution_errors']} |"
        ),
        "",
        "## Per CWE",
        "",
        "| CWE | TP | FP | TN | FN | Precision | Recall | F1 | Errors |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for cwe, metrics in aggregate["per_cwe"].items():
        lines.append(
            f"| {cwe} | {metrics['tp']} | {metrics['fp']} | {metrics['tn']} | "
            f"{metrics['fn']} | {metrics['precision']:.2%} | "
            f"{metrics['recall']:.2%} | {metrics['f1']:.4f} | {metrics['errors']} |"
        )

    failures = [case for case in report["cases"] if case["status"] in {"fp", "fn", "error"}]
    if failures:
        lines.extend(
            [
                "",
                "## Failures",
                "",
                "| Case | CWE | Expected | Result |",
                "|---|---|---:|---|",
            ]
        )
        for case in failures:
            lines.append(
                f"| {case['test_name']} | {case['cwe']} | "
                f"{'vulnerable' if case['vulnerable'] else 'safe'} | {case['status']} |"
            )
    return "\n".join(lines) + "\n"
