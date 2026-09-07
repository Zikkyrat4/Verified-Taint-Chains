"""Regression tests for the real-world evaluation matcher."""

from src.evaluation.engine import (
    EvaluationReport,
    FileEvaluation,
    _analysis_metadata,
    _aggregate,
    _chain_matches_fp_pattern,
    _classify_chains,
    _render_md,
    _route_chain_to_file,
    _serialize_report,
    _vars_match,
)


def _chain(source: str, sink: str, source_line: int, sink_line: int) -> dict:
    return {
        "id": "finding",
        "type": "open_redirect",
        "cwe": "CWE-601",
        "source": {
            "variable": source,
            "file": "OIDCLoginProtocol.java",
            "line": source_line,
            "code_snippet": source,
        },
        "sink": {
            "variable": sink,
            "file": "OIDCLoginProtocol.java",
            "line": sink_line,
            "code_snippet": sink,
        },
        "path": [source, sink],
        "confidence": 0.9,
    }


def test_variable_matching_does_not_use_substrings() -> None:
    assert _vars_match("redirectUri", "redirectUri")
    assert not _vars_match("redirect", "redirectUri")


def test_repeated_endpoints_match_nearest_ground_truth() -> None:
    truth = {
        "cwe": "CWE-601",
        "true_positives": [
            {
                "id": "TP-1", "source_var": "redirect",
                "sink_var": "redirectUri", "source_line": 215,
                "sink_line": 303, "vuln_type": "open_redirect",
            },
            {
                "id": "TP-2", "source_var": "redirect",
                "sink_var": "redirectUri", "source_line": 321,
                "sink_line": 345, "vuln_type": "open_redirect",
            },
        ],
    }
    matched, _, _, false_negatives = _classify_chains(
        [_chain("redirect", "redirectUri", 321, 345)], truth
    )

    assert matched[0]["tp"]["id"] == "TP-2"
    assert false_negatives[0]["id"] == "TP-1"


def test_source_alias_cannot_replace_expected_endpoint() -> None:
    truth = {
        "true_positives": [{
            "id": "TP-1", "source_var": "ctxEntry",
            "source_aliases": ["asString"], "sink_var": "asBytes",
            "source_line": 244, "sink_line": 246,
            "vuln_type": "open_redirect",
        }],
    }

    matched, _, _, false_negatives = _classify_chains(
        [_chain("asString", "asBytes", 244, 245)], truth
    )

    assert matched == []
    assert false_negatives[0]["id"] == "TP-1"


def test_fp_pattern_fields_are_conjunctive() -> None:
    chain = _chain("input", "query", 1, 2)
    pattern = {"source_var": "other", "sink_var": "query"}

    assert not _chain_matches_fp_pattern(chain, pattern)


def test_project_fp_source_pattern_is_scoped_to_truth_file() -> None:
    chain = _chain("username", "file", 1, 2)
    chain["source"]["file"] = "OtherController.java"
    truth = {
        "false_positive_patterns": [{"source_var": "username"}],
        "true_positives": [],
    }

    _, false_positives, unclassified, _ = _classify_chains(
        [chain], truth, truth_file="BaseController.java"
    )

    assert false_positives == []
    assert len(unclassified) == 1


def test_precision_reports_known_and_lower_bound() -> None:
    report = EvaluationReport(files=[
        FileEvaluation(found_tp=1, fp=1, unclassified=2, fn=1, file="A.java")
    ])

    aggregate = _aggregate(report)

    assert aggregate["precision"] == 0.25
    assert aggregate["precision_known"] == 0.5
    assert aggregate["precision_lower_bound"] == 0.25
    assert aggregate["recall"] == 0.5


def test_difficulty_metadata_does_not_exclude_labelled_tp() -> None:
    truth = {
        "true_positives": [{
            "id": "hard", "source_var": "redirect",
            "sink_var": "redirectUri", "source_line": 1, "sink_line": 2,
            "vuln_type": "open_redirect", "expected_realistic": False,
        }],
    }

    matched, _, unclassified, false_negatives = _classify_chains(
        [_chain("redirect", "redirectUri", 1, 2)], truth
    )

    assert matched[0]["tp"]["id"] == "hard"
    assert unclassified == []
    assert false_negatives == []


def test_tp_match_rejects_locations_outside_fixed_tolerance() -> None:
    truth = {
        "true_positives": [{
            "id": "TP-1", "source_var": "input",
            "sink_var": "target", "source_line": 10, "sink_line": 20,
            "vuln_type": "open_redirect",
        }],
    }

    matched, _, unclassified, false_negatives = _classify_chains(
        [_chain("input", "target", 16, 20)], truth
    )

    assert matched == []
    assert len(unclassified) == 1
    assert false_negatives[0]["id"] == "TP-1"


def test_tp_match_rejects_unknown_reported_location() -> None:
    truth = {
        "true_positives": [{
            "id": "TP-1", "source_var": "input",
            "sink_var": "target", "source_line": 10, "sink_line": 20,
            "vuln_type": "open_redirect",
        }],
    }

    matched, _, unclassified, false_negatives = _classify_chains(
        [_chain("input", "target", 0, 0)], truth
    )

    assert matched == []
    assert len(unclassified) == 1
    assert false_negatives[0]["id"] == "TP-1"


def test_tp_match_rejects_wrong_vulnerability_type() -> None:
    truth = {
        "true_positives": [{
            "id": "TP-1", "source_var": "input",
            "sink_var": "target", "source_line": 10, "sink_line": 20,
            "vuln_type": "xss",
        }],
    }

    matched, _, unclassified, false_negatives = _classify_chains(
        [_chain("input", "target", 10, 20)], truth
    )

    assert matched == []
    assert len(unclassified) == 1
    assert false_negatives[0]["id"] == "TP-1"


def test_tp_match_rejects_wrong_sink_even_if_path_contains_expected_name() -> None:
    chain = _chain("input", "otherTarget", 10, 20)
    chain["path"] = ["input", "target", "otherTarget"]
    truth = {
        "true_positives": [{
            "id": "TP-1", "source_var": "input",
            "sink_var": "target", "source_line": 10, "sink_line": 20,
            "vuln_type": "open_redirect",
        }],
    }

    matched, _, unclassified, false_negatives = _classify_chains([chain], truth)

    assert matched == []
    assert len(unclassified) == 1
    assert false_negatives[0]["id"] == "TP-1"


def test_project_route_requires_exact_path_suffix() -> None:
    chain = _chain("input", "target", 10, 20)
    chain["sink"]["file"] = "/tmp/NotController.java.backup"

    assert _route_chain_to_file(chain, ["Controller.java"]) is None


def test_report_serializes_analysis_backend() -> None:
    report = EvaluationReport(
        analysis={
            "backend": "llm",
            "llm_analysis_mode": "targeted",
            "llm_provider": "openai",
            "llm_model": "test-model",
        }
    )
    report.aggregate = _aggregate(report)

    serialized = _serialize_report(report)
    markdown = _render_md(report)

    assert serialized["analysis"]["backend"] == "llm"
    assert "Backend: `llm`" in markdown
    assert "Model: `test-model`" in markdown


def test_analysis_metadata_records_material_configuration() -> None:
    from src.core.config import PipelineConfig

    config = PipelineConfig(
        llm_api_key="test-key",
        analysis_backend="llm",
        min_confidence=0.7,
        use_joern=True,
        cache_read_enabled=False,
    )

    metadata = _analysis_metadata(config)

    assert metadata["min_confidence"] == 0.7
    assert metadata["use_joern"] is True
    assert metadata["cache_read_enabled"] is False
    assert metadata["evaluation_policy"]["line_tolerance"] == 5
    assert metadata["evaluation_policy"]["unmatched_findings_count_as_fp"] is True
