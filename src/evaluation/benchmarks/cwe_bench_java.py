"""CWE-Bench-Java adapter with CVE and annotated-endpoint scoring."""

from __future__ import annotations

import csv
import gc
import hashlib
import json
import shutil
import time
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from src.evaluation.benchmarks.catalog import (
    BENCHMARKS,
    DECLARED_SUPPORTED_CWES,
    BenchmarkError,
    case_source_path,
    normalize_cwe,
)
from src.evaluation.benchmarks.common import (
    build_pipeline_config,
    chain_to_record,
    confirmed_chain_records,
    select_limited,
    utc_now,
    write_json_atomic,
)
from src.evaluation.benchmarks.repository import checkout_revision, validate_revision
from src.evaluation.engine import analysis_metadata
from src.pipeline.orchestrator import SimplePipeline
from src.pipeline.source_discovery import find_java_files, is_test_path
from src.utils.logger import get_logger

logger = get_logger()
SPEC = BENCHMARKS["cwe-bench-java"]
CHECKPOINT_SCHEMA_VERSION = 5


def _optional_int(value: str | None) -> int:
    try:
        return int((value or "").strip())
    except ValueError:
        return 0


def _is_true(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes"}


@dataclass(frozen=True)
class FixTarget:
    file: str
    method: str
    start_line: int
    end_line: int
    commit: str
    signature: str = ""


@dataclass(frozen=True)
class EndpointAnnotation:
    file: str
    source_line: int
    sink_line: int
    source: str
    sink: str


@dataclass(frozen=True)
class CweBenchCase:
    case_id: int
    project_slug: str
    cve: str
    cwe: str
    cwe_name: str
    repository: str
    vulnerable_revision: str
    fixed_revisions: tuple[str, ...]
    fix_targets: tuple[FixTarget, ...] = field(default_factory=tuple)
    annotations: tuple[EndpointAnnotation, ...] = field(default_factory=tuple)

    @property
    def scorable(self) -> bool:
        return bool(self.fix_targets or self.annotations)

    @property
    def preparable(self) -> bool:
        return bool(self.repository and self.vulnerable_revision)

    def fix_targets_in_scope(self, include_tests: bool) -> tuple[FixTarget, ...]:
        return tuple(
            target
            for target in self.fix_targets
            if _oracle_path_in_scope(target.file, include_tests)
        )

    def annotations_in_scope(
        self, include_tests: bool
    ) -> tuple[EndpointAnnotation, ...]:
        return tuple(
            annotation
            for annotation in self.annotations
            if _oracle_path_in_scope(annotation.file, include_tests)
        )

    def scorable_in_scope(self, include_tests: bool) -> bool:
        return bool(
            self.fix_targets_in_scope(include_tests)
            or self.annotations_in_scope(include_tests)
        )


def _oracle_path_in_scope(path: str, include_tests: bool) -> bool:
    if include_tests:
        return True
    parts = PurePosixPath(path.replace("\\", "/")).parts
    return not is_test_path(parts, parts[-1] if parts else "")


def load_cases(checkout: Path) -> list[CweBenchCase]:
    """Join official project, fix-scope, and manually annotated CSV files by CVE."""
    targets_by_cve: dict[str, list[FixTarget]] = defaultdict(list)
    with (checkout / "data/fix_info.csv").open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            cve = (row.get("cve_id") or "").strip()
            file_path = (row.get("file") or "").strip()
            if not cve or not file_path:
                continue
            start = _optional_int(row.get("method_start"))
            end = _optional_int(row.get("method_end"))
            if not start or not end:
                start = _optional_int(row.get("class_start"))
                end = _optional_int(row.get("class_end"))
            targets_by_cve[cve].append(
                FixTarget(
                    file=file_path,
                    method=(row.get("method") or "").strip(),
                    start_line=start,
                    end_line=end,
                    commit=(row.get("commit") or "").strip(),
                    signature=(row.get("signature") or "").strip(),
                )
            )

    annotations_by_cve: dict[str, list[EndpointAnnotation]] = defaultdict(list)
    annotation_path = checkout / "data/fix_info_source_sink.csv"
    with annotation_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if not (_is_true(row.get("Done")) and _is_true(row.get("Check"))):
                continue
            cve = (row.get("cve_id") or "").strip()
            file_path = (row.get("file") or "").strip()
            source_line = _optional_int(row.get("Source Line"))
            sink_line = _optional_int(row.get("Sink Line"))
            if not cve or not file_path or not source_line or not sink_line:
                continue
            annotations_by_cve[cve].append(
                EndpointAnnotation(
                    file=file_path,
                    source_line=source_line,
                    sink_line=sink_line,
                    source=(row.get("Source") or "").strip(),
                    sink=(row.get("Sink") or "").strip(),
                )
            )

    cases: list[CweBenchCase] = []
    with (checkout / "data/project_info.csv").open(newline="", encoding="utf-8") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), 2):
            try:
                case_id = int((row.get("id") or "").strip())
                cve = (row.get("cve_id") or "").strip()
                case = CweBenchCase(
                    case_id=case_id,
                    project_slug=(row.get("project_slug") or "").strip(),
                    cve=cve,
                    cwe=normalize_cwe(row.get("cwe_id") or ""),
                    cwe_name=(row.get("cwe_name") or "").strip(),
                    repository=(row.get("github_url") or "").strip(),
                    vulnerable_revision=(row.get("buggy_commit_id") or "").strip(),
                    fixed_revisions=tuple(
                        commit.strip()
                        for commit in (row.get("fix_commit_ids") or "").split(";")
                        if commit.strip()
                    ),
                    fix_targets=tuple(targets_by_cve.get(cve, [])),
                    annotations=tuple(annotations_by_cve.get(cve, [])),
                )
            except (TypeError, ValueError) as error:
                raise BenchmarkError(
                    f"Malformed CWE-Bench project_info.csv row {row_number}: {error}"
                ) from error
            if not all((case.project_slug, case.cve)):
                raise BenchmarkError(f"Incomplete CWE-Bench project row {row_number}")
            cases.append(case)
    if not cases:
        raise BenchmarkError("CWE-Bench project_info.csv contains no cases")
    return cases


def select_cases(
    cases: Sequence[CweBenchCase],
    *,
    cwes: Iterable[str] = (),
    case_ids: Iterable[str] = (),
    all_cwes: bool = False,
    limit: int = 0,
    seed: int = 0,
) -> list[CweBenchCase]:
    requested_cwes = {normalize_cwe(cwe) for cwe in cwes}
    if requested_cwes and all_cwes:
        raise BenchmarkError("--cwe and --all-cwes are mutually exclusive")
    allowed_cwes = (
        requested_cwes
        if requested_cwes
        else ({case.cwe for case in cases} if all_cwes else DECLARED_SUPPORTED_CWES)
    )
    requested_cases = set()
    for value in case_ids:
        normalized = value.strip().lower()
        if normalized.isdigit():
            normalized = normalized.lstrip("0") or "0"
        requested_cases.add(normalized)

    def case_requested(case: CweBenchCase) -> bool:
        return not requested_cases or bool(
            {str(case.case_id), case.cve.lower(), case.project_slug.lower()} & requested_cases
        )

    selected = [
        case for case in cases if case.cwe in allowed_cwes and case_requested(case)
    ]
    selected = select_limited(
        selected,
        limit=limit,
        seed=seed,
        identity=lambda case: f"{case.case_id:06d}",
    )
    if not selected:
        raise BenchmarkError("CWE-Bench selection contains no cases")
    return selected


def prepare_cases(
    checkout: Path,
    store_root: Path,
    *,
    cwes: Iterable[str] = (),
    case_ids: Iterable[str] = (),
    all_cwes: bool = False,
    limit: int = 0,
    seed: int = 0,
    include_tests: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Fetch exact vulnerable revisions; no build-only IRIS patches are applied."""
    all_cases = load_cases(checkout)
    cases = select_cases(
        all_cases,
        cwes=cwes,
        case_ids=case_ids,
        all_cwes=all_cwes,
        limit=limit,
        seed=seed,
    )
    prepared = []
    skipped_unscored = []
    skipped_out_of_scope = []
    skipped_unavailable = []
    for case in cases:
        if not case.preparable:
            skipped_unavailable.append(case.cve)
            continue
        if not case.scorable:
            skipped_unscored.append(case.cve)
            continue
        if not case.scorable_in_scope(include_tests):
            skipped_out_of_scope.append(case.cve)
            continue
        target = case_source_path(store_root, case.case_id)
        logger.info(f"Preparing CWE-Bench case {case.case_id} ({case.cve})")
        checkout_revision(
            case.repository,
            case.vulnerable_revision,
            target,
            force=force,
        )
        prepared.append(
            {
                "case_id": case.case_id,
                "cve": case.cve,
                "revision": case.vulnerable_revision,
                "path": str(target),
            }
        )
    return {
        "selected": len(cases),
        "prepared": prepared,
        "skipped_without_localization_oracle": skipped_unscored,
        "skipped_with_oracle_out_of_scope": skipped_out_of_scope,
        "skipped_without_vulnerable_revision": skipped_unavailable,
    }


def _file_matches(reported: str, expected: str) -> bool:
    reported_norm = reported.replace("\\", "/").lower().rstrip("/")
    expected_norm = expected.replace("\\", "/").lower().lstrip("/")
    if reported_norm == expected_norm or reported_norm.endswith("/" + expected_norm):
        return True
    parts = PurePosixPath(expected_norm).parts
    without_repo_prefix = "/".join(parts[1:])
    return bool(without_repo_prefix) and reported_norm.endswith("/" + without_repo_prefix)


def _oracle_file_available(expected: str, source_files: Sequence[str]) -> bool:
    """Return whether a fixed-revision oracle path maps to analyzed Java source."""
    if PurePosixPath(expected.replace("\\", "/")).suffix.lower() != ".java":
        return False
    return any(_file_matches(source_file, expected) for source_file in source_files)


def _finding_nodes(finding: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [finding["source"], *finding.get("path", []), finding["sink"]]


def _touches_file(finding: Mapping[str, Any], expected_file: str) -> bool:
    return any(_file_matches(str(node.get("file", "")), expected_file) for node in _finding_nodes(finding))


def _touches_scope(
    finding: Mapping[str, Any], target: FixTarget, tolerance: int = 10
) -> bool:
    for node in _finding_nodes(finding):
        if not _file_matches(str(node.get("file", "")), target.file):
            continue
        function_name = str(node.get("function", "") or "").strip()
        if target.method and function_name:
            if function_name == target.method:
                return True
            continue
        line = int(node.get("line", 0) or 0)
        if not target.start_line or not target.end_line:
            return True
        if line and target.start_line - tolerance <= line <= target.end_line + tolerance:
            return True
    return False


def _matches_annotation(
    finding: Mapping[str, Any], annotation: EndpointAnnotation, tolerance: int = 5
) -> bool:
    source = finding["source"]
    sink = finding["sink"]
    return (
        _file_matches(str(source.get("file", "")), annotation.file)
        and _file_matches(str(sink.get("file", "")), annotation.file)
        and abs(int(source.get("line", 0) or 0) - annotation.source_line) <= tolerance
        and abs(int(sink.get("line", 0) or 0) - annotation.sink_line) <= tolerance
    )


def score_case(
    case: CweBenchCase,
    findings: Sequence[dict[str, Any]],
    *,
    error: str | None = None,
    files_analyzed: int = 0,
    include_tests: bool = False,
    extraction_errors: Mapping[str, Sequence[str]] | None = None,
    analysis_errors: Sequence[str] | None = None,
    source_files: Sequence[str] | None = None,
    candidate_findings: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Score localization only; findings outside the partial oracle stay unscored."""
    same_cwe = [finding for finding in findings if finding.get("cwe") == case.cwe]
    candidate_pool = findings if candidate_findings is None else candidate_findings
    candidate_same_cwe = [
        finding
        for finding in candidate_pool
        if finding.get("cwe") == case.cwe
    ]
    fix_targets = case.fix_targets_in_scope(include_tests)
    annotations = case.annotations_in_scope(include_tests)
    oracle_source_checked = source_files is not None
    unavailable_fix_targets = 0
    unavailable_annotations = 0
    if source_files is not None:
        available_fix_targets = tuple(
            target
            for target in fix_targets
            if _oracle_file_available(target.file, source_files)
        )
        available_annotations = tuple(
            annotation
            for annotation in annotations
            if _oracle_file_available(annotation.file, source_files)
        )
        unavailable_fix_targets = len(fix_targets) - len(available_fix_targets)
        unavailable_annotations = len(annotations) - len(available_annotations)
        fix_targets = available_fix_targets
        annotations = available_annotations
    extraction_errors = dict(extraction_errors or {})
    analysis_errors = list(analysis_errors or ())
    incomplete_reasons = []
    if extraction_errors:
        incomplete_reasons.append(
            f"Incomplete extraction in {len(extraction_errors)} file(s)"
        )
    incomplete_reasons.extend(analysis_errors)
    incomplete_message = "; ".join(incomplete_reasons) or None
    if error:
        status = "error"
        detected = None
    elif not case.preparable:
        status = "unscored_source_revision_missing"
        detected = None
    elif not case.scorable:
        status = "unscored_oracle_missing"
        detected = None
    elif not fix_targets and not annotations:
        status = (
            "unscored_oracle_source_unavailable"
            if oracle_source_checked
            and (unavailable_fix_targets or unavailable_annotations)
            else "unscored_oracle_out_of_scope"
        )
        detected = None
    else:
        detected = any(
            _touches_scope(finding, target)
            for finding in same_cwe
            for target in fix_targets
        )
        if not detected and annotations:
            detected = any(
                _matches_annotation(finding, annotation)
                for finding in same_cwe
                for annotation in annotations
            )
        if detected:
            status = "tp"
        elif extraction_errors or analysis_errors:
            status = "error"
            error = incomplete_message
        else:
            status = "fn"

    target_hits = [
        any(_touches_scope(finding, target) for finding in same_cwe)
        for target in fix_targets
    ]
    annotation_hits = [
        any(_matches_annotation(finding, annotation) for finding in same_cwe)
        for annotation in annotations
    ]
    target_files = {target.file for target in fix_targets}
    target_files.update(annotation.file for annotation in annotations)
    file_localized = any(
        _touches_file(finding, target_file)
        for finding in same_cwe
        for target_file in target_files
    )
    scored_finding_ids = {
        finding["id"]
        for finding in same_cwe
        if any(_touches_scope(finding, target) for target in fix_targets)
        or any(_matches_annotation(finding, annotation) for annotation in annotations)
    }
    candidate_detected = any(
        _touches_scope(finding, target)
        for finding in candidate_same_cwe
        for target in fix_targets
    ) or any(
        _matches_annotation(finding, annotation)
        for finding in candidate_same_cwe
        for annotation in annotations
    )
    oracle_scope_candidates = [
        finding
        for finding in candidate_pool
        if any(_touches_scope(finding, target) for target in fix_targets)
        or any(
            _matches_annotation(finding, annotation)
            for annotation in annotations
        )
    ]
    candidate_scored_finding_ids = sorted({
        finding["id"]
        for finding in oracle_scope_candidates
        if finding.get("cwe") == case.cwe
    })
    return {
        "case_id": case.case_id,
        "project_slug": case.project_slug,
        "cve": case.cve,
        "cwe": case.cwe,
        "status": status,
        "detected": detected,
        "project_cwe_detected": bool(same_cwe),
        "candidate_scope_detected": candidate_detected,
        "oracle_scope_candidates": oracle_scope_candidates,
        "candidate_scored_finding_ids": candidate_scored_finding_ids,
        "target_file_localized": file_localized,
        "files_analyzed": files_analyzed,
        "fix_targets": [asdict(target) for target in fix_targets],
        "excluded_fix_targets": len(case.fix_targets) - len(fix_targets),
        "unavailable_fix_targets": unavailable_fix_targets,
        "fix_target_hits": target_hits,
        "annotations": [asdict(annotation) for annotation in annotations],
        "excluded_annotations": len(case.annotations) - len(annotations),
        "unavailable_annotations": unavailable_annotations,
        "annotation_hits": annotation_hits,
        "findings": list(findings),
        "scored_finding_ids": sorted(scored_finding_ids),
        "unscored_finding_count": len(findings) - len(scored_finding_ids),
        "analysis_complete": (
            not error and not extraction_errors and not analysis_errors
        ),
        "extraction_errors": extraction_errors,
        "analysis_errors": analysis_errors,
        "error": error,
    }


def aggregate_rows(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    tp = sum(row["status"] == "tp" for row in rows)
    fn = sum(row["status"] == "fn" for row in rows)
    errors = sum(row["status"] == "error" for row in rows)
    missing_oracle = sum(row["status"] == "unscored_oracle_missing" for row in rows)
    oracle_out_of_scope = sum(
        row["status"] == "unscored_oracle_out_of_scope" for row in rows
    )
    missing_revision = sum(
        row["status"] == "unscored_source_revision_missing" for row in rows
    )
    unavailable_oracle_source = sum(
        row["status"] == "unscored_oracle_source_unavailable" for row in rows
    )
    denominator = tp + fn
    candidate_scope_hits = sum(
        bool(row.get("candidate_scope_detected"))
        for row in rows
        if row["status"] in {"tp", "fn"}
    )
    per_cwe: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0})
    for row in rows:
        if row["status"] in {"tp", "fn"}:
            per_cwe[str(row["cwe"])][str(row["status"])] += 1

    annotation_total = sum(len(row["annotation_hits"]) for row in rows if not row["error"])
    annotation_hits = sum(sum(row["annotation_hits"]) for row in rows if not row["error"])
    return {
        "selected_cases": len(rows),
        "scored_cves": denominator,
        "cve_tp": tp,
        "cve_fn": fn,
        "cve_recall": round(tp / denominator, 4) if denominator else 0.0,
        "candidate_scope_hits": candidate_scope_hits,
        "candidate_scope_recall": (
            round(candidate_scope_hits / denominator, 4) if denominator else 0.0
        ),
        "execution_errors": errors,
        "incomplete_extraction_projects": sum(
            bool(row.get("extraction_errors")) for row in rows
        ),
        "incomplete_analysis_projects": sum(
            bool(row.get("analysis_errors")) for row in rows
        ),
        "missing_localization_oracle": missing_oracle,
        "localization_oracle_out_of_scope": oracle_out_of_scope,
        "missing_source_revision": missing_revision,
        "oracle_source_unavailable": unavailable_oracle_source,
        "project_cwe_detected": sum(bool(row["project_cwe_detected"]) for row in rows),
        "target_file_localized": sum(bool(row["target_file_localized"]) for row in rows),
        "annotation_pairs": annotation_total,
        "annotation_pairs_hit": annotation_hits,
        "annotation_recall": (
            round(annotation_hits / annotation_total, 4) if annotation_total else None
        ),
        "unscored_findings": sum(int(row["unscored_finding_count"]) for row in rows),
        "precision": None,
        "precision_reason": (
            "Undefined: CWE-Bench labels target CVE locations, not every vulnerability "
            "in each real-world project. Unmatched findings are not valid false positives."
        ),
        "per_cwe": {
            cwe: {
                **counts,
                "recall": round(counts["tp"] / (counts["tp"] + counts["fn"]), 4),
            }
            for cwe, counts in sorted(per_cwe.items())
        },
    }


def _checkpoint_fingerprint(
    cases: Sequence[CweBenchCase],
    analysis: Mapping[str, Any],
    *,
    include_tests: bool,
    fail_fast: bool,
) -> str:
    # Scheduling-only settings do not change prompts, scoring, or cached specs.
    semantic_analysis = {
        key: value
        for key, value in analysis.items()
        if key not in {
            "max_concurrent_files",
            "max_concurrent_functions",
            "max_concurrent_llm_requests",
            "openai_timeout",
            "llm_max_retries",
        }
    }
    identity = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "benchmark_revision": SPEC.revision,
        "cases": [
            [case.case_id, case.cve, case.cwe, case.vulnerable_revision]
            for case in cases
        ],
        "analysis": semantic_analysis,
        "include_tests": include_tests,
        "fail_fast": fail_fast,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _load_checkpoint(
    path: Path | None,
    fingerprint: str,
    selected_case_ids: set[int],
    *,
    retry_errors: bool = False,
) -> tuple[dict[int, dict[str, Any]], str | None, float]:
    if path is None or not path.exists():
        return {}, None, 0.0
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if (
            payload.get("schema_version") != CHECKPOINT_SCHEMA_VERSION
            or payload.get("fingerprint") != fingerprint
        ):
            backup = path.with_name(
                f"{path.name}.incompatible-{int(time.time())}.bak"
            )
            try:
                shutil.copy2(path, backup)
                logger.warning(
                    f"Archived incompatible CWE-Bench checkpoint to {backup}"
                )
            except OSError as error:
                logger.warning(
                    f"Could not archive incompatible CWE-Bench checkpoint at "
                    f"{path}: {error}"
                )
            logger.warning(f"Ignoring incompatible CWE-Bench checkpoint at {path}")
            return {}, None, 0.0
        rows = payload.get("rows")
        if not isinstance(rows, list):
            raise ValueError("rows is not a list")
        restored: dict[int, dict[str, Any]] = {}
        seen_case_ids: set[int] = set()
        retried_errors = 0
        for row in rows:
            case_id = int(row["case_id"])
            if case_id not in selected_case_ids or case_id in seen_case_ids:
                raise ValueError(f"unexpected or duplicate case id {case_id}")
            seen_case_ids.add(case_id)
            if retry_errors and row.get("status") == "error":
                retried_errors += 1
                continue
            restored[case_id] = row
        started_at = payload.get("started_at")
        duration = max(0.0, float(payload.get("duration_seconds", 0.0)))
    except (OSError, TypeError, ValueError, json.JSONDecodeError, KeyError) as error:
        logger.warning(f"Ignoring invalid CWE-Bench checkpoint at {path}: {error}")
        return {}, None, 0.0
    logger.info(
        f"Resuming CWE-Bench from {path}: {len(restored)} completed case(s)"
    )
    if retried_errors:
        logger.info(
            f"Scheduled {retried_errors} checkpoint error case(s) for retry"
        )
    return restored, str(started_at) if started_at else None, duration


def _write_checkpoint(
    path: Path | None,
    fingerprint: str,
    started_at: str,
    duration_seconds: float,
    rows: Sequence[Mapping[str, Any]],
) -> None:
    if path is None:
        return
    write_json_atomic(
        path,
        {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "fingerprint": fingerprint,
            "started_at": started_at,
            "duration_seconds": round(duration_seconds, 3),
            "rows": list(rows),
        },
    )


def _merge_checkpoint_rows(
    cases: Sequence[CweBenchCase],
    restored: Mapping[int, Mapping[str, Any]],
    current_rows: Sequence[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    """Merge current retry results without dropping later restored cases."""
    rows_by_id = dict(restored)
    rows_by_id.update((int(row["case_id"]), row) for row in current_rows)
    return [
        rows_by_id[case.case_id]
        for case in cases
        if case.case_id in rows_by_id
    ]


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
    include_tests: bool = False,
    refresh_specs: bool = False,
    fail_fast: bool = False,
    retry_errors: bool = False,
    checkpoint_path: Path | None = None,
    max_concurrent_files: int | None = None,
    max_concurrent_functions: int | None = None,
    max_concurrent_llm_requests: int | None = None,
) -> dict[str, Any]:
    all_cases = load_cases(checkout)
    cases = select_cases(
        all_cases,
        cwes=cwes,
        case_ids=case_ids,
        all_cwes=all_cwes,
        limit=limit,
        seed=seed,
    )
    runnable_cases = [
        case
        for case in cases
        if case.preparable and case.scorable_in_scope(include_tests)
    ]
    missing_sources = []
    for case in runnable_cases:
        source_root = case_source_path(store_root, case.case_id)
        try:
            validate_revision(source_root, case.vulnerable_revision, case.cve)
        except BenchmarkError:
            missing_sources.append(case)
    if missing_sources:
        examples = ", ".join(case.cve for case in missing_sources[:5])
        suffix = "..." if len(missing_sources) > 5 else ""
        raise BenchmarkError(
            f"{len(missing_sources)} selected CWE-Bench source checkout(s) are missing "
            f"or stale ({examples}{suffix}); run `vtc benchmark prepare cwe-bench-java` "
            "with the same selection options"
        )

    config = build_pipeline_config(
        backend=backend,
        llm_analysis_mode=llm_analysis_mode,
        cache_dir=store_root / "cache" / SPEC.benchmark_id,
        refresh_specs=refresh_specs,
        max_concurrent_files=max_concurrent_files,
        max_concurrent_functions=max_concurrent_functions,
        max_concurrent_llm_requests=max_concurrent_llm_requests,
    )
    analysis = analysis_metadata(config)
    analysis["evaluation_policy"] = {
        "scoring_unit": "target_cve_at_official_fix_scope",
        "target_cwe_required": True,
        "official_fix_scope_required": True,
        "curated_endpoint_pairs_secondary": True,
        "unmatched_findings_count_as_fp": False,
        "precision_defined": False,
    }
    fingerprint = _checkpoint_fingerprint(
        cases,
        analysis,
        include_tests=include_tests,
        fail_fast=fail_fast,
    )
    restored, checkpoint_started_at, accumulated_duration = _load_checkpoint(
        checkpoint_path,
        fingerprint,
        {case.case_id for case in cases},
        retry_errors=retry_errors,
    )
    pipeline = SimplePipeline(config) if runnable_cases else None
    rows: list[dict[str, Any]] = []
    started_at = checkpoint_started_at or utc_now()
    started = time.monotonic()

    def checkpoint() -> None:
        # A retry may target an error near the start of the selection. Preserve
        # restored rows later in selection order until the loop reaches them;
        # otherwise the first retry checkpoint would discard valid completed
        # work that has not yet been appended to ``rows``.
        _write_checkpoint(
            checkpoint_path,
            fingerprint,
            started_at,
            accumulated_duration + time.monotonic() - started,
            _merge_checkpoint_rows(cases, restored, rows),
        )

    # Replace an incompatible checkpoint before the first potentially long case,
    # so external status readers never report stale rows from an older contract.
    checkpoint()

    try:
        for index, case in enumerate(cases, 1):
            if case.case_id in restored:
                rows.append(restored[case.case_id])
                continue
            if not case.preparable or not case.scorable_in_scope(include_tests):
                rows.append(score_case(case, [], include_tests=include_tests))
                checkpoint()
                continue
            source_root = case_source_path(store_root, case.case_id)
            java_files = find_java_files(source_root, include_tests=include_tests)
            if not java_files:
                rows.append(score_case(case, [], error="No Java application sources found"))
                checkpoint()
                continue
            logger.info(
                f"CWE-Bench case {index}/{len(cases)}: {case.cve}, "
                f"{len(java_files)} Java files"
            )
            try:
                assert pipeline is not None
                result = await pipeline.run_project(java_files, show_progress=False)
                metrics = result.get("metrics", {})
                extraction_errors = metrics.get("extraction_errors", {})
                analysis_errors = metrics.get("analysis_errors", [])
                findings = confirmed_chain_records(
                    result.get("verified_chains", [])
                )
                candidate_findings = [
                    chain_to_record(chain)
                    for chain in [
                        *result.get("verified_chains", []),
                        *result.get("unverifiable_chains", []),
                        *result.get("rejected_chains", []),
                    ]
                ]
                rows.append(
                    score_case(
                        case,
                        findings,
                        files_analyzed=len(java_files),
                        include_tests=include_tests,
                        extraction_errors=extraction_errors,
                        analysis_errors=analysis_errors,
                        source_files=java_files,
                        candidate_findings=candidate_findings,
                    )
                )
                if (extraction_errors or analysis_errors) and fail_fast:
                    raise BenchmarkError(
                        "; ".join(
                            [
                                f"Incomplete extraction in "
                                f"{len(extraction_errors)} file(s)"
                            ]
                            + list(analysis_errors)
                        )
                    )
                checkpoint()
                del result, findings, candidate_findings
            except BenchmarkError:
                raise
            except Exception as error:
                message = f"{type(error).__name__}: {error}"
                rows.append(
                    score_case(
                        case,
                        [],
                        error=message,
                        files_analyzed=len(java_files),
                        include_tests=include_tests,
                    )
                )
                if fail_fast:
                    raise BenchmarkError(message) from error
                checkpoint()
            finally:
                assert pipeline is not None
                pipeline.release_run_state()
                gc.collect()
    finally:
        if pipeline is not None:
            await pipeline.aclose()

    aggregate = aggregate_rows(rows)
    return {
        "schema_version": 1,
        "benchmark": {
            "id": SPEC.benchmark_id,
            "title": SPEC.title,
            "repository": SPEC.repository,
            "revision": SPEC.revision,
            "license": SPEC.license,
            "scoring_unit": SPEC.scoring_unit,
            "oracles": [
                "data/project_info.csv",
                "data/fix_info.csv",
                "data/fix_info_source_sink.csv",
            ],
        },
        "run": {
            "started_at": started_at,
            "duration_seconds": round(
                accumulated_duration + time.monotonic() - started, 3
            ),
            "analysis": analysis,
            "selection": {
                "requested_cwes": [normalize_cwe(cwe) for cwe in cwes],
                "selected_cwes": sorted({case.cwe for case in cases}),
                "all_cwes": all_cwes,
                "case_ids": list(case_ids),
                "limit": limit,
                "seed": seed,
                "include_tests": include_tests,
            },
            "integrity": {
                "oracle_exposed_to_pipeline": False,
                "target_cwe_exposed_to_pipeline": False,
                "cve_hidden_from_checkout_path": True,
                "public_corpus_pretraining_contamination_possible": True,
            },
        },
        "coverage": {
            "upstream_cases": len(all_cases),
            "available_cwes": sorted({case.cwe for case in all_cases}),
            "declared_supported_cwes": sorted(DECLARED_SUPPORTED_CWES),
            "upstream_cases_with_localization_oracle": sum(case.scorable for case in all_cases),
            "upstream_cases_with_vulnerable_revision": sum(
                case.preparable for case in all_cases
            ),
            "selected_cases": len(cases),
            "selected_cases_with_localization_oracle": sum(case.scorable for case in cases),
            "selected_cases_with_oracle_in_scope": sum(
                case.scorable_in_scope(include_tests) for case in cases
            ),
            "selected_runnable_cases": len(runnable_cases),
        },
        "aggregate": aggregate,
        "cases": rows,
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    aggregate = report["aggregate"]
    run_info = report["run"]
    annotation_recall = aggregate["annotation_recall"]
    annotation_value = "n/a" if annotation_recall is None else f"{annotation_recall:.2%}"
    lines = [
        "# VTC / CWE-Bench-Java",
        "",
        f"- Upstream revision: `{report['benchmark']['revision']}`",
        f"- Backend: `{run_info['analysis']['backend']}`",
        f"- LLM mode: `{run_info['analysis']['llm_analysis_mode']}`",
        f"- CVEs scored: {aggregate['scored_cves']} / {aggregate['selected_cases']}",
        "- Primary unit: target CWE finding localized to an official fix method/scope",
        "- Precision: undefined because the dataset does not label every finding in each project",
        "",
        "## Aggregate",
        "",
        "| CVE TP | CVE FN | Verified recall | Candidate recall | File localized | Annotated endpoints | Errors | Incomplete extraction/analysis | Missing oracle/scope/source/revision |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| {aggregate['cve_tp']} | {aggregate['cve_fn']} | "
            f"{aggregate['cve_recall']:.2%} | "
            f"{aggregate['candidate_scope_recall']:.2%} | "
            f"{aggregate['target_file_localized']} | "
            f"{aggregate['annotation_pairs_hit']} / {aggregate['annotation_pairs']} "
            f"({annotation_value}) | {aggregate['execution_errors']} | "
            f"{aggregate['incomplete_extraction_projects']} / "
            f"{aggregate['incomplete_analysis_projects']} | "
            f"{aggregate['missing_localization_oracle']} / "
            f"{aggregate['localization_oracle_out_of_scope']} / "
            f"{aggregate['oracle_source_unavailable']} / "
            f"{aggregate['missing_source_revision']} |"
        ),
        "",
        "## Per CWE",
        "",
        "| CWE | CVE TP | CVE FN | Recall |",
        "|---|---:|---:|---:|",
    ]
    for cwe, metrics in aggregate["per_cwe"].items():
        lines.append(
            f"| {cwe} | {metrics['tp']} | {metrics['fn']} | {metrics['recall']:.2%} |"
        )

    failures = [case for case in report["cases"] if case["status"] != "tp"]
    if failures:
        lines.extend(
            [
                "",
                "## Not detected or unscored",
                "",
                "| Case | CVE | CWE | Result |",
                "|---:|---|---|---|",
            ]
        )
        for case in failures:
            lines.append(
                f"| {case['case_id']} | {case['cve']} | {case['cwe']} | {case['status']} |"
            )
    return "\n".join(lines) + "\n"
