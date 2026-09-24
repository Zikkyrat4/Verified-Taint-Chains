"""Offline integrity checks for pinned benchmark metadata and source corpora."""

from __future__ import annotations

import csv
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.evaluation.benchmarks.catalog import BenchmarkError
from src.evaluation.benchmarks.cwe_bench_java import (
    load_cases as load_cwe_cases,
)
from src.evaluation.benchmarks.cwe_bench_java import (
    select_cases as select_cwe_cases,
)
from src.evaluation.benchmarks.owasp_java import SOURCE_ROOT
from src.evaluation.benchmarks.owasp_java import (
    load_cases as load_owasp_cases,
)
from src.evaluation.benchmarks.owasp_java import (
    select_cases as select_owasp_cases,
)

_SHA_PATTERN = re.compile(r"[0-9a-fA-F]{40}")
_GIT_REVISION_PATTERN = re.compile(r"[0-9a-fA-F]{7,40}")


@dataclass(frozen=True)
class ValidationResult:
    benchmark_id: str
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    statistics: dict[str, Any]

    @property
    def valid(self) -> bool:
        return not self.errors


def _duplicates(values: list[str | int]) -> list[str | int]:
    return sorted(value for value, count in Counter(values).items() if count > 1)


def validate_owasp_data(checkout: Path) -> ValidationResult:
    cases = load_owasp_cases(checkout)
    errors: list[str] = []
    duplicate_ids = _duplicates([case.test_name for case in cases])
    if duplicate_ids:
        errors.append(f"duplicate testcase ids: {len(duplicate_ids)}")

    oracle_names = {case.test_name for case in cases}
    source_names = {
        path.stem for path in (checkout / SOURCE_ROOT).glob("BenchmarkTest*.java")
    }
    missing_sources = oracle_names - source_names
    sources_without_oracle = source_names - oracle_names
    if missing_sources:
        errors.append(f"oracle cases without source: {len(missing_sources)}")
    if sources_without_oracle:
        errors.append(f"source files without oracle: {len(sources_without_oracle)}")

    selected = select_owasp_cases(cases)
    per_cwe = Counter(case.cwe for case in cases)
    return ValidationResult(
        benchmark_id="owasp-java",
        errors=tuple(errors),
        warnings=(),
        statistics={
            "cases": len(cases),
            "positive": sum(case.vulnerable for case in cases),
            "negative": sum(not case.vulnerable for case in cases),
            "cwes": dict(sorted(per_cwe.items())),
            "default_supported_cases": len(selected),
            "default_supported_cwes": sorted({case.cwe for case in selected}),
            "default_supported_positive": sum(case.vulnerable for case in selected),
            "default_supported_negative": sum(not case.vulnerable for case in selected),
        },
    )


def validate_cwe_data(checkout: Path) -> ValidationResult:
    cases = load_cwe_cases(checkout)
    errors: list[str] = []
    warnings: list[str] = []

    for label, values in (
        ("case ids", [case.case_id for case in cases]),
        ("project slugs", [case.project_slug for case in cases]),
        ("CVEs", [case.cve for case in cases]),
    ):
        duplicates = _duplicates(values)
        if duplicates:
            errors.append(f"duplicate {label}: {len(duplicates)}")

    invalid_revisions = [
        case.case_id
        for case in cases
        if case.vulnerable_revision
        and not _SHA_PATTERN.fullmatch(case.vulnerable_revision)
    ]
    invalid_revisions.extend(
        case.case_id
        for case in cases
        for revision in case.fixed_revisions
        if not _GIT_REVISION_PATTERN.fullmatch(revision)
    )
    invalid_revisions.extend(
        case.case_id
        for case in cases
        for target in case.fix_targets
        if target.commit and not _GIT_REVISION_PATTERN.fullmatch(target.commit)
    )
    if invalid_revisions:
        errors.append(f"cases with malformed Git revisions: {len(set(invalid_revisions))}")

    invalid_repositories = [
        case.case_id
        for case in cases
        if case.repository and not case.repository.startswith("https://github.com/")
    ]
    if invalid_repositories:
        errors.append(
            f"cases with unsupported repository URLs: {len(invalid_repositories)}"
        )

    invalid_ranges = [
        (case.case_id, target.file)
        for case in cases
        for target in case.fix_targets
        if target.start_line < 0
        or target.end_line < 0
        or (target.start_line and target.end_line and target.start_line > target.end_line)
    ]
    if invalid_ranges:
        errors.append(f"invalid fix target line ranges: {len(invalid_ranges)}")

    missing_revision = sum(not case.preparable for case in cases)
    missing_oracle = sum(not case.scorable for case in cases)
    test_only_oracle = sum(
        case.scorable and not case.scorable_in_scope(False) for case in cases
    )

    project_cves = {case.cve for case in cases}
    with (checkout / "data/fix_info.csv").open(newline="", encoding="utf-8") as handle:
        raw_fix_rows = list(csv.DictReader(handle))
    orphan_fix_rows = [
        row
        for row in raw_fix_rows
        if (row.get("cve_id") or "").strip() not in project_cves
    ]

    with (checkout / "data/fix_info_source_sink.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        raw_annotation_rows = list(csv.DictReader(handle))
    curated_annotation_rows = [
        row
        for row in raw_annotation_rows
        if (row.get("Done") or "").strip().lower() in {"1", "true", "yes"}
        and (row.get("Check") or "").strip().lower() in {"1", "true", "yes"}
    ]
    malformed_annotations = [
        row
        for row in curated_annotation_rows
        if not (
            (row.get("cve_id") or "").strip()
            and (row.get("file") or "").strip()
            and (row.get("Source Line") or "").strip().isdigit()
            and int((row.get("Source Line") or "0").strip()) > 0
            and (row.get("Sink Line") or "").strip().isdigit()
            and int((row.get("Sink Line") or "0").strip()) > 0
        )
    ]
    orphan_annotations = [
        row
        for row in curated_annotation_rows
        if (row.get("cve_id") or "").strip() not in project_cves
    ]
    if missing_revision:
        warnings.append(f"cases without vulnerable revision: {missing_revision}")
    if missing_oracle:
        warnings.append(f"cases without localization oracle: {missing_oracle}")
    if test_only_oracle:
        warnings.append(f"cases with test-only localization oracle: {test_only_oracle}")
    if orphan_fix_rows:
        orphan_fix_cves = {
            (row.get("cve_id") or "").strip() for row in orphan_fix_rows
        }
        warnings.append(
            "fix rows ignored because project metadata is absent: "
            f"{len(orphan_fix_rows)} rows / {len(orphan_fix_cves)} CVEs"
        )
    if malformed_annotations:
        warnings.append(
            "curated source/sink rows without a usable endpoint pair: "
            f"{len(malformed_annotations)}"
        )
    if orphan_annotations:
        warnings.append(
            "curated source/sink rows ignored because project metadata is absent: "
            f"{len(orphan_annotations)}"
        )

    selected = select_cwe_cases(cases)
    return ValidationResult(
        benchmark_id="cwe-bench-java",
        errors=tuple(errors),
        warnings=tuple(warnings),
        statistics={
            "cases": len(cases),
            "cwes": len({case.cwe for case in cases}),
            "preparable_cases": sum(case.preparable for case in cases),
            "cases_with_oracle": sum(case.scorable for case in cases),
            "fix_scope_rows_loaded": sum(len(case.fix_targets) for case in cases),
            "source_sink_pairs_loaded": sum(len(case.annotations) for case in cases),
            "runnable_cases_without_tests": sum(
                case.preparable and case.scorable_in_scope(False) for case in cases
            ),
            "default_supported_cases": len(selected),
            "default_supported_cwes": sorted({case.cwe for case in selected}),
            "default_runnable_without_tests": sum(
                case.preparable and case.scorable_in_scope(False) for case in selected
            ),
        },
    )


def validate_benchmark_data(benchmark_id: str, checkout: Path) -> ValidationResult:
    if benchmark_id == "owasp-java":
        return validate_owasp_data(checkout)
    if benchmark_id == "cwe-bench-java":
        return validate_cwe_data(checkout)
    raise BenchmarkError(f"No validator registered for {benchmark_id}")
