"""Tests for pinned external benchmark adapters and their scoring contracts."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from src.evaluation.benchmarks.catalog import BenchmarkError, case_source_path, normalize_cwe
from src.evaluation.benchmarks.common import (
    build_pipeline_config,
    confirmed_chain_records,
)
from src.evaluation.benchmarks.cwe_bench_java import (
    CweBenchCase,
    EndpointAnnotation,
    FixTarget,
    _checkpoint_fingerprint,
    _load_checkpoint,
    _merge_checkpoint_rows,
    _write_checkpoint,
    aggregate_rows,
)
from src.evaluation.benchmarks.cwe_bench_java import (
    load_cases as load_cwe_cases,
)
from src.evaluation.benchmarks.cwe_bench_java import (
    score_case as score_cwe_case,
)
from src.evaluation.benchmarks.owasp_java import (
    OwaspCase,
)
from src.evaluation.benchmarks.owasp_java import (
    load_cases as load_owasp_cases,
)
from src.evaluation.benchmarks.owasp_java import (
    score_cases as score_owasp_cases,
)
from src.evaluation.benchmarks.owasp_java import (
    select_cases as select_owasp_cases,
)
from src.evaluation.benchmarks.runner import _output_paths
from src.evaluation.benchmarks.validation import validate_owasp_data
from src.pipeline.main import cli


def _finding(
    *,
    finding_id: str = "finding-1",
    cwe: str = "CWE-22",
    file: str = "/checkout/src/main/java/acme/Target.java",
    source_line: int = 10,
    sink_line: int = 20,
    function: str = "",
) -> dict:
    return {
        "id": finding_id,
        "type": "path_traversal",
        "cwe": cwe,
        "source": {
            "variable": "input",
            "file": file,
            "line": source_line,
            "function": function,
        },
        "sink": {
            "variable": "path",
            "file": file,
            "line": sink_line,
            "function": function,
        },
        "path": [],
        "confidence": 0.9,
    }


def test_benchmark_rejects_non_verified_pipeline_contract() -> None:
    chain = MagicMock()
    chain.id = "candidate"
    chain.vulnerability_type.value = "path_traversal"
    chain.sink.cwe_id = "CWE-22"
    chain.source.variable_name = "input"
    chain.source.location.file_path = "Target.java"
    chain.source.location.line_number = 10
    chain.source.location.function_name = "run"
    chain.sink.variable_name = "path"
    chain.sink.location.file_path = "Target.java"
    chain.sink.location.line_number = 20
    chain.sink.location.function_name = "run"
    chain.path = []
    chain.confidence = 0.7
    chain.verification_status.value = "unverifiable"

    with pytest.raises(BenchmarkError, match="non-verified"):
        confirmed_chain_records([chain])


@patch("src.evaluation.benchmarks.common.load_config_from_env")
def test_benchmark_requires_verification(mock_load: MagicMock, tmp_path: Path) -> None:
    mock_load.return_value.verification_enabled = False

    with pytest.raises(BenchmarkError, match="VERIFICATION_ENABLED=true"):
        build_pipeline_config(
            backend="llm",
            llm_analysis_mode="targeted",
            cache_dir=tmp_path,
            refresh_specs=False,
        )


def test_normalize_cwe_accepts_official_variants() -> None:
    assert normalize_cwe("22") == "CWE-22"
    assert normalize_cwe("CWE-022") == "CWE-22"
    assert normalize_cwe("cwe_00089") == "CWE-89"


def test_cwe_case_checkout_path_does_not_expose_cve_or_slug(tmp_path: Path) -> None:
    path = case_source_path(tmp_path, 17)

    assert path == tmp_path / "cases/cwe-bench-java/0017"
    assert "CVE" not in str(path)


def test_load_and_select_owasp_cases(tmp_path: Path) -> None:
    (tmp_path / "expectedresults-1.2.csv").write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "BenchmarkTest00002,hash,false,328\n"
        "BenchmarkTest00003,sqli,false,89\n",
        encoding="utf-8",
    )

    cases = load_owasp_cases(tmp_path)
    selected = select_owasp_cases(cases)

    assert len(cases) == 3
    assert [case.test_name for case in selected] == [
        "BenchmarkTest00001",
        "BenchmarkTest00003",
    ]
    assert select_owasp_cases(cases, all_cwes=True)[1].cwe == "CWE-328"
    assert select_owasp_cases(cases, case_ids=("00001",))[0].test_name.endswith("00001")


def test_owasp_rejects_conflicting_cwe_scope() -> None:
    cases = [OwaspCase("BenchmarkTest00001", "pathtraver", True, "CWE-22", "one.java")]

    with pytest.raises(BenchmarkError, match="mutually exclusive"):
        select_owasp_cases(cases, cwes=("CWE-22",), all_cwes=True)


def test_owasp_validation_checks_complete_source_oracle_mapping(tmp_path: Path) -> None:
    (tmp_path / "expectedresults-1.2.csv").write_text(
        "BenchmarkTest00001,pathtraver,true,22\n", encoding="utf-8"
    )
    source_root = tmp_path / "src/main/java/org/owasp/benchmark/testcode"
    source_root.mkdir(parents=True)
    source = source_root / "BenchmarkTest00001.java"
    source.write_text("class BenchmarkTest00001 {}\n", encoding="utf-8")

    assert validate_owasp_data(tmp_path).valid

    source.unlink()
    result = validate_owasp_data(tmp_path)
    assert not result.valid
    assert result.errors == ("oracle cases without source: 1",)


def test_owasp_scores_one_prediction_per_case_and_excludes_errors() -> None:
    cases = [
        OwaspCase("BenchmarkTest00001", "pathtraver", True, "CWE-22", "one.java"),
        OwaspCase("BenchmarkTest00002", "pathtraver", False, "CWE-22", "two.java"),
        OwaspCase("BenchmarkTest00003", "pathtraver", True, "CWE-22", "three.java"),
    ]
    duplicate_findings = [
        _finding(finding_id="a"),
        _finding(finding_id="b"),
    ]

    rows, aggregate = score_owasp_cases(
        cases,
        {
            "BenchmarkTest00001": duplicate_findings,
            "BenchmarkTest00002": [_finding()],
        },
        {"BenchmarkTest00003": "provider timeout"},
    )

    assert [row["status"] for row in rows] == ["tp", "fp", "error"]
    assert aggregate["tp"] == 1
    assert aggregate["fp"] == 1
    assert aggregate["fn"] == 0
    assert aggregate["scored_cases"] == 2
    assert aggregate["execution_errors"] == 1


def test_load_cwe_cases_joins_oracles_by_cve(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "project_info.csv").write_text(
        "id,project_slug,cve_id,cwe_id,cwe_name,github_username,"
        "github_repository_name,github_tag,github_url,advisory_id,"
        "buggy_commit_id,fix_commit_ids\n"
        "1,new-slug,CVE-2099-0001,CWE-022,Path Traversal,acme,app,v1,"
        "https://github.com/acme/app,GHSA-test,buggy,fixed\n",
        encoding="utf-8",
    )
    (data / "fix_info.csv").write_text(
        "project_slug,cve_id,github_username,github_repository_name,commit,file,"
        "class,class_start,class_end,method,method_start,method_end,signature\n"
        "old-slug,CVE-2099-0001,acme,app,fixed,src/main/java/acme/Target.java,"
        "Target,1,40,read,8,25,read(String)\n",
        encoding="utf-8",
    )
    (data / "fix_info_source_sink.csv").write_text(
        "project_slug,cve_id,file,Done,Check,Source Line,Sink Line,Source,Sink\n"
        "another-slug,CVE-2099-0001,src/main/java/acme/Target.java,1,True,10,20,input,path\n",
        encoding="utf-8",
    )

    cases = load_cwe_cases(tmp_path)

    assert len(cases) == 1
    assert cases[0].cwe == "CWE-22"
    assert cases[0].fix_targets[0].method == "read"
    assert cases[0].annotations[0].sink_line == 20


def test_cwe_scoring_requires_target_localization_and_does_not_invent_fp() -> None:
    case = CweBenchCase(
        case_id=1,
        project_slug="hidden-from-analysis-path",
        cve="CVE-2099-0001",
        cwe="CWE-22",
        cwe_name="Path Traversal",
        repository="https://github.com/acme/app",
        vulnerable_revision="buggy",
        fixed_revisions=("fixed",),
        fix_targets=(
            FixTarget("src/main/java/acme/Target.java", "read", 8, 25, "fixed"),
        ),
        annotations=(
            EndpointAnnotation(
                "src/main/java/acme/Target.java", 10, 20, "input", "path"
            ),
        ),
    )
    unrelated = _finding(file="/checkout/src/main/java/acme/Other.java")
    localized = _finding()

    missed = score_cwe_case(case, [unrelated])
    detected = score_cwe_case(case, [localized])
    aggregate = aggregate_rows([missed, detected])

    assert missed["status"] == "fn"
    assert missed["project_cwe_detected"] is True
    assert missed["unscored_finding_count"] == 1
    assert detected["status"] == "tp"
    assert detected["annotation_hits"] == [True]
    assert aggregate["candidate_scope_hits"] == 1
    assert aggregate["candidate_scope_recall"] == 0.5
    assert aggregate["precision"] is None
    assert "not every vulnerability" in aggregate["precision_reason"]


def test_cwe_report_keeps_oracle_scope_candidate_verification_reason() -> None:
    case = CweBenchCase(
        case_id=1,
        project_slug="case",
        cve="CVE-2099-0001",
        cwe="CWE-22",
        cwe_name="Path Traversal",
        repository="https://github.com/acme/app",
        vulnerable_revision="buggy",
        fixed_revisions=("fixed",),
        fix_targets=(
            FixTarget("src/main/java/acme/Target.java", "read", 8, 25, "fixed"),
        ),
    )
    candidate = _finding(function="read")
    candidate["verification_status"] = "unverifiable"
    candidate["verification"] = {
        "status": "unverifiable",
        "method": "cfg",
        "details": "Lightweight CFG could not establish reachability",
        "cfg_status": "false",
        "symbolic_status": None,
        "confidence": 0.4,
    }

    row = score_cwe_case(case, [], candidate_findings=[candidate])

    assert row["status"] == "fn"
    assert row["candidate_scope_detected"] is True
    assert row["candidate_scored_finding_ids"] == ["finding-1"]
    assert row["oracle_scope_candidates"][0]["verification"]["details"] == (
        "Lightweight CFG could not establish reachability"
    )


def test_cwe_partial_extraction_keeps_hits_and_does_not_count_misses_as_fn() -> None:
    case = CweBenchCase(
        case_id=1,
        project_slug="case",
        cve="CVE-2099-0001",
        cwe="CWE-22",
        cwe_name="Path Traversal",
        repository="https://github.com/acme/app",
        vulnerable_revision="buggy",
        fixed_revisions=("fixed",),
        fix_targets=(
            FixTarget("src/main/java/acme/Target.java", "read", 8, 25, "fixed"),
        ),
    )
    extraction_errors = {"src/main/java/acme/Other.java": ["provider timeout"]}

    detected = score_cwe_case(
        case,
        [_finding(function="read")],
        extraction_errors=extraction_errors,
    )
    unknown = score_cwe_case(case, [], extraction_errors=extraction_errors)
    aggregate = aggregate_rows([detected, unknown])

    assert detected["status"] == "tp"
    assert detected["analysis_complete"] is False
    assert unknown["status"] == "error"
    assert aggregate["cve_tp"] == 1
    assert aggregate["cve_fn"] == 0
    assert aggregate["execution_errors"] == 1
    assert aggregate["incomplete_extraction_projects"] == 2
    incomplete_graph = score_cwe_case(
        case, [], analysis_errors=["Stage 2 graph scope was incomplete"]
    )
    graph_aggregate = aggregate_rows([incomplete_graph])
    assert incomplete_graph["status"] == "error"
    assert incomplete_graph["analysis_complete"] is False
    assert incomplete_graph["analysis_errors"] == [
        "Stage 2 graph scope was incomplete"
    ]
    assert graph_aggregate["cve_fn"] == 0
    assert graph_aggregate["execution_errors"] == 1
    assert graph_aggregate["incomplete_analysis_projects"] == 1


def test_cwe_method_name_survives_fixed_revision_line_shift() -> None:
    case = CweBenchCase(
        case_id=1,
        project_slug="case",
        cve="CVE-2099-0001",
        cwe="CWE-22",
        cwe_name="Path Traversal",
        repository="https://github.com/acme/app",
        vulnerable_revision="buggy",
        fixed_revisions=("fixed",),
        fix_targets=(
            FixTarget("src/main/java/acme/Target.java", "read", 500, 550, "fixed"),
        ),
    )

    row = score_cwe_case(
        case,
        [_finding(source_line=10, sink_line=20, function="read")],
    )

    assert row["status"] == "tp"
    assert row["fix_target_hits"] == [True]


def test_cwe_missing_or_non_java_oracle_source_is_not_counted_as_fn() -> None:
    case = CweBenchCase(
        case_id=1,
        project_slug="case",
        cve="CVE-2099-0001",
        cwe="CWE-94",
        cwe_name="Code Injection",
        repository="https://github.com/acme/app",
        vulnerable_revision="buggy",
        fixed_revisions=("fixed",),
        fix_targets=(
            FixTarget("src/main/groovy/acme/Runner.groovy", "run", 8, 25, "fixed"),
            FixTarget("src/main/java/newpkg/Runner.java", "run", 8, 25, "fixed"),
        ),
    )

    row = score_cwe_case(
        case,
        [],
        source_files=("/checkout/src/main/java/oldpkg/Runner.java",),
    )

    assert row["status"] == "unscored_oracle_source_unavailable"
    assert row["detected"] is None
    assert row["unavailable_fix_targets"] == 2


def test_cwe_test_only_oracle_is_unscored_when_tests_are_excluded() -> None:
    case = CweBenchCase(
        case_id=1,
        project_slug="case",
        cve="CVE-2099-0001",
        cwe="CWE-22",
        cwe_name="Path Traversal",
        repository="https://github.com/acme/app",
        vulnerable_revision="buggy",
        fixed_revisions=("fixed",),
        fix_targets=(
            FixTarget("src/test/java/acme/TargetTest.java", "testRead", 8, 25, "fixed"),
        ),
    )

    excluded = score_cwe_case(case, [])
    included = score_cwe_case(case, [], include_tests=True)

    assert excluded["status"] == "unscored_oracle_out_of_scope"
    assert excluded["excluded_fix_targets"] == 1
    assert included["status"] == "fn"
    assert included["excluded_fix_targets"] == 0


def test_cwe_mixed_oracle_metrics_ignore_excluded_test_targets() -> None:
    case = CweBenchCase(
        case_id=1,
        project_slug="case",
        cve="CVE-2099-0001",
        cwe="CWE-22",
        cwe_name="Path Traversal",
        repository="https://github.com/acme/app",
        vulnerable_revision="buggy",
        fixed_revisions=("fixed",),
        fix_targets=(
            FixTarget("src/main/java/acme/Target.java", "read", 8, 25, "fixed"),
            FixTarget("src/test/java/acme/TargetTest.java", "testRead", 8, 25, "fixed"),
        ),
    )

    row = score_cwe_case(case, [_finding(function="read")])

    assert row["status"] == "tp"
    assert row["fix_target_hits"] == [True]
    assert row["excluded_fix_targets"] == 1


def test_cwe_checkpoint_round_trip_requires_exact_fingerprint(tmp_path: Path) -> None:
    case = CweBenchCase(
        case_id=1,
        project_slug="case",
        cve="CVE-2099-0001",
        cwe="CWE-22",
        cwe_name="Path Traversal",
        repository="https://github.com/acme/app",
        vulnerable_revision="buggy",
        fixed_revisions=("fixed",),
    )
    fingerprint = _checkpoint_fingerprint(
        [case],
        {
            "backend": "llm",
            "llm_model": "test-model",
            "max_concurrent_files": 4,
            "openai_timeout": 60,
            "llm_max_retries": 2,
            "llm_max_tokens": 4000,
        },
        include_tests=False,
        fail_fast=False,
    )
    rescheduled_fingerprint = _checkpoint_fingerprint(
        [case],
        {
            "backend": "llm",
            "llm_model": "test-model",
            "max_concurrent_files": 16,
            "openai_timeout": 300,
            "llm_max_retries": 4,
            "llm_max_tokens": 4000,
        },
        include_tests=False,
        fail_fast=False,
    )
    changed_analysis_fingerprint = _checkpoint_fingerprint(
        [case],
        {
            "backend": "llm",
            "llm_model": "test-model",
            "max_concurrent_files": 4,
            "openai_timeout": 300,
            "llm_max_retries": 2,
            "llm_max_tokens": 8000,
        },
        include_tests=False,
        fail_fast=False,
    )
    checkpoint = tmp_path / "run.checkpoint.json"
    row = {"case_id": 1, "status": "fn"}

    _write_checkpoint(checkpoint, fingerprint, "2026-01-01T00:00:00Z", 12.5, [row])

    restored, started_at, duration = _load_checkpoint(checkpoint, fingerprint, {1})
    incompatible, _, _ = _load_checkpoint(checkpoint, "other", {1})
    assert restored == {1: row}
    assert started_at == "2026-01-01T00:00:00Z"
    assert duration == 12.5
    assert rescheduled_fingerprint == fingerprint
    assert changed_analysis_fingerprint != fingerprint
    assert incompatible == {}
    assert len(list(tmp_path.glob("run.checkpoint.json.incompatible-*.bak"))) == 1


def test_cwe_checkpoint_can_retry_only_error_rows(tmp_path: Path) -> None:
    checkpoint = tmp_path / "run.checkpoint.json"
    rows = [
        {"case_id": 1, "status": "tp"},
        {"case_id": 2, "status": "error"},
        {"case_id": 3, "status": "fn"},
    ]
    _write_checkpoint(checkpoint, "fingerprint", "2026-01-01T00:00:00Z", 5, rows)

    restored, _, duration = _load_checkpoint(
        checkpoint,
        "fingerprint",
        {1, 2, 3},
        retry_errors=True,
    )

    assert set(restored) == {1, 3}
    assert duration == 5


def test_cwe_retry_checkpoint_preserves_later_restored_rows() -> None:
    cases = [
        CweBenchCase(
            case_id=case_id,
            project_slug=f"case-{case_id}",
            cve=f"CVE-2099-{case_id:04d}",
            cwe="CWE-22",
            cwe_name="Path Traversal",
            repository="https://github.com/acme/app",
            vulnerable_revision="buggy",
            fixed_revisions=("fixed",),
        )
        for case_id in (1, 2, 3)
    ]
    restored = {
        1: {"case_id": 1, "status": "tp"},
        3: {"case_id": 3, "status": "fn"},
    }
    retried = [{"case_id": 2, "status": "tp"}]

    merged = _merge_checkpoint_rows(cases, restored, retried)

    assert [row["case_id"] for row in merged] == [1, 2, 3]
    assert merged[2]["status"] == "fn"


def test_benchmark_commands_are_registered() -> None:
    runner = CliRunner()

    top_level = runner.invoke(cli, ["--help"])
    benchmark_help = runner.invoke(cli, ["benchmark", "--help"])

    assert top_level.exit_code == 0
    assert "benchmark" in top_level.output
    assert benchmark_help.exit_code == 0
    assert all(
        command in benchmark_help.output
        for command in ("fetch", "list", "prepare", "run", "validate")
    )


def test_default_subset_reports_do_not_overwrite_full_report() -> None:
    full, _ = _output_paths("owasp-java", "llm", "targeted", None, None, None, {})
    subset, _ = _output_paths(
        "owasp-java",
        "llm",
        "targeted",
        None,
        None,
        None,
        {"limit": 10, "seed": 7},
    )

    assert full.name == "llm-targeted.json"
    assert subset.name.startswith("llm-targeted-subset-")
    assert subset != full


@patch("src.evaluation.benchmarks.cli.run_benchmark_command")
def test_benchmark_run_forwards_explicit_selection(run_command, tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "benchmark",
            "run",
            "owasp-java",
            "--backend",
            "static",
            "--cwe",
            "CWE-22",
            "--limit",
            "4",
            "--seed",
            "7",
            "--max-concurrent-files",
            "12",
            "--max-concurrent-functions",
            "3",
            "--max-concurrent-llm-requests",
            "5",
            "--data-dir",
            str(tmp_path),
        ],
        env={"LOG_FILE": "off"},
    )

    assert result.exit_code == 0
    kwargs = run_command.call_args.kwargs
    assert kwargs["backend"] == "static"
    assert kwargs["cwes"] == ("CWE-22",)
    assert kwargs["limit"] == 4
    assert kwargs["seed"] == 7
    assert kwargs["max_concurrent_files"] == 12
    assert kwargs["max_concurrent_functions"] == 3
    assert kwargs["max_concurrent_llm_requests"] == 5
