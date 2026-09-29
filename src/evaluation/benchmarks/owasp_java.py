"""OWASP BenchmarkJava adapter and test-case-level scorer."""

from __future__ import annotations

import csv
import time
from collections import Counter, defaultdict
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
    chain_to_record,
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

# BenchmarkJava embeds the intended weakness family in servlet routes and a
# few pieces of test harness text. Those labels are not program semantics and
# would give an LLM the answer to the CWE-classification part of the task.
# Apply every replacement to every case so prompt construction does not itself
# depend on the case's oracle category.
_PROMPT_MARKER_REDACTIONS = {
    '"/pathtraver-': '"/securitycase-',
    '"/cmdi-': '"/securitycase-',
    '"/sqli-': '"/securitycase-',
    '"/xss-': '"/securitycase-',
    '"Problem executing cmdi': '"Problem executing operation',
    '"X-XSS-Protection"': '"X-Security-Protection"',
}


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
    per_cwe: dict[str, dict[str, Any]] = {}
    raw_category_rates: list[tuple[float, float]] = []
    for cwe, counts in sorted(per_cwe_counts.items()):
        metrics = binary_metrics(
            counts["tp"], counts["fp"], counts["tn"], counts["fn"]
        )
        tpr = counts["tp"] / (counts["tp"] + counts["fn"]) if (
            counts["tp"] + counts["fn"]
        ) else 0.0
        fpr = counts["fp"] / (counts["fp"] + counts["tn"]) if (
            counts["fp"] + counts["tn"]
        ) else 0.0
        metrics.update({
            "false_positive_rate": round(fpr, 4),
            "owasp_score": round(tpr - fpr, 4),
            "errors": counts["errors"],
        })
        per_cwe[cwe] = metrics
        raw_category_rates.append((tpr, fpr))
    aggregate["per_cwe"] = per_cwe

    micro_fpr = totals["fp"] / (totals["fp"] + totals["tn"]) if (
        totals["fp"] + totals["tn"]
    ) else 0.0
    micro_tpr = totals["tp"] / (totals["tp"] + totals["fn"]) if (
        totals["tp"] + totals["fn"]
    ) else 0.0
    aggregate.update({
        "false_positive_rate": round(micro_fpr, 4),
        "micro_owasp_score": round(micro_tpr - micro_fpr, 4),
        "macro_true_positive_rate": round(
            sum(tpr for tpr, _ in raw_category_rates)
            / len(raw_category_rates),
            4,
        ) if raw_category_rates else 0.0,
        "macro_false_positive_rate": round(
            sum(fpr for _, fpr in raw_category_rates)
            / len(raw_category_rates),
            4,
        ) if raw_category_rates else 0.0,
        # OWASP gives every vulnerability category equal weight.
        "owasp_score": round(
            sum(tpr - fpr for tpr, fpr in raw_category_rates)
            / len(raw_category_rates),
            4,
        ) if raw_category_rates else 0.0,
    })
    return rows, aggregate


def _finding_case_names(
    finding: Mapping[str, Any], known_names: set[str]
) -> set[str]:
    """Return all official testcase names referenced by a chain."""
    locations = [finding.get("source", {}), finding.get("sink", {})]
    locations.extend(finding.get("path", []))
    return {
        Path(str(location.get("file", ""))).stem
        for location in locations
        if Path(str(location.get("file", ""))).stem in known_names
    }


def _store_isolated_finding(
    finding: dict[str, Any],
    *,
    known_names: set[str],
    findings_by_case: dict[str, list[dict[str, Any]]],
    orphan_findings: list[dict[str, Any]],
) -> None:
    """Attribute a chain to one case and reject cross-case contamination."""
    case_names = _finding_case_names(finding, known_names)
    if len(case_names) > 1:
        raise BenchmarkError(
            "OWASP case-isolation violation: chain "
            f"{finding.get('id', '<unknown>')} references "
            f"{', '.join(sorted(case_names))}"
        )
    if case_names:
        findings_by_case[next(iter(case_names))].append(finding)
    else:
        orphan_findings.append(finding)


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
    candidate_findings_by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    errors: dict[str, str] = {}
    orphan_findings: list[dict[str, Any]] = []
    orphan_candidate_findings: list[dict[str, Any]] = []
    pipeline_totals: Counter[str] = Counter()
    known_names = {case.test_name for case in cases}
    official_sources = {str(checkout / case.source_file) for case in all_cases}
    source_tree = checkout / "src/main/java"
    context_files = [
        str(path)
        for path in sorted(source_tree.rglob("*.java"))
        if str(path) not in official_sources
    ]
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
            prompt_redactions = {
                str(checkout / case.source_file): {
                    case.test_name: "EvaluationCase",
                    **_PROMPT_MARKER_REDACTIONS,
                }
                for case in batch
            }
            try:
                result = await pipeline.run_project(
                    paths,
                    show_progress=False,
                    context_files=context_files,
                    prompt_redactions=prompt_redactions,
                    include_analyzed_files_in_context=False,
                    allow_interfile_bridges=False,
                )
            except Exception as error:
                message = f"{type(error).__name__}: {error}"
                for case in batch:
                    errors[case.test_name] = message
                if fail_fast:
                    raise BenchmarkError(message) from error
                continue

            batch_metrics = result.get("metrics", {})
            integrity_errors = []
            if batch_metrics.get("analyzed_files_in_project_context") != 0:
                integrity_errors.append("analyzed testcase files entered LLM context")
            if batch_metrics.get("interfile_bridges_enabled") is not False:
                integrity_errors.append("cross-testcase graph bridges were enabled")
            if (
                backend in {"llm", "hybrid"}
                and batch_metrics.get("prompt_redacted_files") != len(batch)
            ):
                integrity_errors.append("not every testcase prompt was redacted")
            if integrity_errors:
                raise BenchmarkError(
                    "OWASP pipeline isolation contract violation: "
                    + "; ".join(integrity_errors)
                )

            extraction_errors = batch_metrics.get("extraction_errors", {})
            analysis_errors = batch_metrics.get("analysis_errors", [])
            for key in (
                "sources_found",
                "sinks_found",
                "sanitizers_found",
                "chains_found",
                "chains_verified",
                "chains_unverifiable",
                "chains_rejected",
            ):
                value = batch_metrics.get(key, 0)
                if isinstance(value, int):
                    pipeline_totals[key] += value
            for path, messages in extraction_errors.items():
                test_name = Path(path).stem
                if test_name in known_names:
                    errors[test_name] = "; ".join(str(message) for message in messages)
            if analysis_errors:
                message = "; ".join(str(item) for item in analysis_errors)
                for case in batch:
                    errors.setdefault(case.test_name, message)
            if fail_fast and (extraction_errors or analysis_errors):
                raise BenchmarkError(
                    f"Incomplete OWASP batch {offset // batch_size + 1}: "
                    f"{len(extraction_errors)} extraction error(s), "
                    f"{len(analysis_errors)} analysis error(s)"
                )

            for finding in confirmed_chain_records(
                result.get("verified_chains", [])
            ):
                _store_isolated_finding(
                    finding,
                    known_names=known_names,
                    findings_by_case=findings_by_case,
                    orphan_findings=orphan_findings,
                )
            candidate_chains = [
                *result.get("verified_chains", []),
                *result.get("unverifiable_chains", []),
                *result.get("rejected_chains", []),
            ]
            for finding in map(chain_to_record, candidate_chains):
                _store_isolated_finding(
                    finding,
                    known_names=known_names,
                    findings_by_case=candidate_findings_by_case,
                    orphan_findings=orphan_candidate_findings,
                )
    finally:
        await pipeline.aclose()

    rows, aggregate = score_cases(cases, findings_by_case, errors)
    candidate_rows, candidate_aggregate = score_cases(
        cases, candidate_findings_by_case, errors
    )
    candidate_rows_by_name = {row["test_name"]: row for row in candidate_rows}
    for row in rows:
        candidate_row = candidate_rows_by_name[row["test_name"]]
        row["stage2_candidate"] = {
            "status": candidate_row["status"],
            "detected": candidate_row["detected"],
            "matching_finding_count": candidate_row["matching_finding_count"],
            "wrong_cwe_finding_count": candidate_row["wrong_cwe_finding_count"],
            "findings": candidate_row["findings"],
        }
    selected_cwes = sorted({case.cwe for case in cases})
    available_cwes = sorted({case.cwe for case in all_cases})
    analysis = analysis_metadata(config)
    endpoint_producers = {
        "llm": ["llm"],
        "hybrid": ["llm", "static_rules"],
        "static": ["static_rules"],
    }[backend]
    analysis["evaluation_policy"] = {
        "scoring_unit": "official_testcase",
        "expected_cwe_required": True,
        "one_prediction_per_testcase": True,
        "duplicate_findings_multiply_counts": False,
        "unmatched_findings_count_as_fp": False,
        "unmatched_findings_reported_separately": True,
        "precision_defined": True,
    }
    deterministic_validation = [
        "endpoint_schema_validation",
        "endpoint_location_grounding_and_normalization",
    ]
    if backend == "hybrid":
        deterministic_validation.append(
            "project_local_constant_return_source_rejection"
        )
    return {
        "schema_version": 2,
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
                "public_case_identifiers_exposed_to_llm": False,
                "benchmark_category_markers_exposed_to_llm": False,
                "target_comments_exposed_to_llm": False,
                "analyzed_testcases_share_llm_context": False,
                "cross_testcase_graph_bridges_enabled": False,
                "cross_testcase_chains_rejected": True,
                "pipeline_isolation_metrics_verified": True,
                "public_corpus_pretraining_contamination_possible": True,
            },
            "measurement": {
                "primary": "verified_chain_same_cwe",
                "primary_scope": "end_to_end_llm_backed_analyzer",
                "stage2_diagnostic": "candidate_chain_same_cwe_before_verifier",
                "raw_llm_binary_verdict_scored": False,
                "raw_llm_binary_verdict_reason": (
                    "The model extracts endpoints; it does not emit the "
                    "benchmark's binary testcase verdict."
                ),
                "stage1_endpoint_producers": endpoint_producers,
            },
            "context": {
                "strategy": "resolved_project_methods",
                "context_only_files": len(context_files),
                "context_files_are_scored": False,
                "analyzed_files_in_project_context": 0,
                "comments_removed_from_context": True,
                "comments_removed_from_target_prompt": True,
                "deterministic_validation": deterministic_validation,
            },
            "diagnostics": dict(pipeline_totals),
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
        "stage2_candidate_aggregate": candidate_aggregate,
        "cases": rows,
        "orphan_findings": orphan_findings,
        "orphan_candidate_findings": orphan_candidate_findings,
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    aggregate = report["aggregate"]
    run_info = report["run"]
    analysis = run_info["analysis"]
    integrity = run_info["integrity"]
    prompt_leakage_controls = not any((
        integrity["public_case_identifiers_exposed_to_llm"],
        integrity["target_comments_exposed_to_llm"],
        integrity["benchmark_category_markers_exposed_to_llm"],
    ))
    lines = [
        "# VTC / OWASP BenchmarkJava",
        "",
        f"- Upstream revision: `{report['benchmark']['revision']}`",
        f"- Backend: `{analysis['backend']}`",
        f"- LLM mode: `{analysis['llm_analysis_mode']}`",
        f"- Provider/model: `{analysis['llm_provider']}` / `{analysis['llm_model']}`",
        f"- LLM temperature: `{analysis['llm_temperature']}`",
        (
            f"- Graph: `{analysis['graph_builder']}` "
            f"(LLM enrichment: `{analysis['graph_llm_calls_enabled']}`)"
        ),
        f"- Prompt template version: `{analysis['prompt_template_version']}`",
        f"- Stage 1 cache reads: `{analysis['cache_read_enabled']}`",
        (
            "- Prompt leakage controls: case ids, comments, and benchmark "
            f"category markers hidden: `{prompt_leakage_controls}`"
        ),
        f"- Cases scored: {aggregate['scored_cases']} / {aggregate['selected_cases']}",
        "- Primary metric: end-to-end analyzer; LLM endpoints + graph + verifier",
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
        (
            f"- Official OWASP score (macro TPR - FPR): "
            f"**{aggregate['owasp_score']:.2%}** "
            f"(micro: {aggregate['micro_owasp_score']:.2%})"
        ),
        "",
        "## Stage 2 Candidate Diagnostic",
        "",
        (
            "This diagnostic scores LLM-derived endpoint chains before the "
            "deterministic verifier; it is not the primary benchmark result."
        ),
        "",
        "| TP | FP | TN | FN | Precision | Recall | F1 | Errors |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| {report['stage2_candidate_aggregate']['tp']} | "
            f"{report['stage2_candidate_aggregate']['fp']} | "
            f"{report['stage2_candidate_aggregate']['tn']} | "
            f"{report['stage2_candidate_aggregate']['fn']} | "
            f"{report['stage2_candidate_aggregate']['precision']:.2%} | "
            f"{report['stage2_candidate_aggregate']['recall']:.2%} | "
            f"{report['stage2_candidate_aggregate']['f1']:.4f} | "
            f"{report['stage2_candidate_aggregate']['execution_errors']} |"
        ),
        "",
        "## Per CWE",
        "",
        "| CWE | TP | FP | TN | FN | TPR | FPR | OWASP score | F1 | Errors |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for cwe, metrics in aggregate["per_cwe"].items():
        lines.append(
            f"| {cwe} | {metrics['tp']} | {metrics['fp']} | {metrics['tn']} | "
            f"{metrics['fn']} | {metrics['recall']:.2%} | "
            f"{metrics['false_positive_rate']:.2%} | "
            f"{metrics['owasp_score']:.2%} | {metrics['f1']:.4f} | "
            f"{metrics['errors']} |"
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
