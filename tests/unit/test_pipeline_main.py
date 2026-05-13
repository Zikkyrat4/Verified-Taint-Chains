"""Tests for pipeline CLI (src/pipeline/main.py)."""

import json
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from click.testing import CliRunner

from src.pipeline.main import (
    cli,
    _display_results,
    _save_results,
    _find_java_files,
)
from src.core.models import (
    TaintChain, Source, Sink, PathNode, CodeLocation, VulnerabilityType, VerificationStatus,
    Explanation,
)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def sample_chain():
    source = Source(
        location=CodeLocation(file_path="test.java", line_number=5),
        variable_name="userId",
        type="User Input",
        confidence=0.9,
        code_snippet='String userId = request.getParameter("id");',
    )
    sink = Sink(
        location=CodeLocation(file_path="test.java", line_number=10),
        variable_name="query",
        type="SQL",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        confidence=0.85,
        code_snippet='stmt.executeQuery(query);',
    )
    return TaintChain(
        id="test-chain",
        source=source,
        sink=sink,
        path=[
            PathNode(location=CodeLocation(file_path="test.java", line_number=5), variable_name="userId", node_type="source", code_snippet=""),
            PathNode(location=CodeLocation(file_path="test.java", line_number=10), variable_name="query", node_type="sink", code_snippet=""),
        ],
        length=2,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        confidence=0.875,
        verification_status=VerificationStatus.VERIFIED,
    )


@pytest.fixture
def sample_result(sample_chain):
    return {
        "file": "test.java",
        "total_chains": 1,
        "verified_chains": [sample_chain],
        "explanations": {},
        "metrics": {
            "sources_found": 1,
            "sinks_found": 1,
            "chains_found": 1,
            "chains_verified": 1,
            "verification_rate": 1.0,
            "explanations_generated": 0,
        },
    }


@pytest.fixture
def sample_multi_result(sample_chain):
    """Project-mode unified result."""
    return {
        "file": "project (2 files)",
        "files_analyzed": 2,
        "file_list": ["A.java", "B.java"],
        "total_chains": 1,
        "verified_chains": [sample_chain],
        "explanations": {},
        "metrics": {
            "sources_found": 1,
            "sinks_found": 1,
            "sanitizers_found": 0,
            "chains_found": 1,
            "chains_verified": 1,
            "verification_rate": 1.0,
            "explanations_generated": 0,
            "graph_nodes": 5,
            "graph_edges": 3,
        },
    }


class TestCLI:
    """Tests for CLI commands."""

    def test_cli_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "VTC" in result.output

    def test_cli_version(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_analyze_help(self, runner):
        result = runner.invoke(cli, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "Java" in result.output

    def test_analyze_no_file(self, runner):
        result = runner.invoke(cli, ["analyze"])
        assert result.exit_code != 0


class TestFindJavaFiles:
    """Tests for _find_java_files."""

    def test_single_file(self, tmp_path):
        java_file = tmp_path / "Test.java"
        java_file.write_text("public class Test {}")
        result = _find_java_files(str(java_file))
        assert result == [str(java_file)]

    def test_directory_with_java_files(self, tmp_path):
        (tmp_path / "A.java").write_text("class A {}")
        (tmp_path / "B.java").write_text("class B {}")
        (tmp_path / "readme.txt").write_text("ignore")
        result = _find_java_files(str(tmp_path))
        assert len(result) == 2
        assert all(f.endswith(".java") for f in result)

    def test_recursive_scan(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "Top.java").write_text("class Top {}")
        (sub / "Nested.java").write_text("class Nested {}")
        result = _find_java_files(str(tmp_path))
        assert len(result) == 2

    def test_empty_directory(self, tmp_path):
        result = _find_java_files(str(tmp_path))
        assert result == []

    def test_directory_no_java_files(self, tmp_path):
        (tmp_path / "readme.md").write_text("no java here")
        result = _find_java_files(str(tmp_path))
        assert result == []

    def test_sorted_output(self, tmp_path):
        (tmp_path / "Z.java").write_text("class Z {}")
        (tmp_path / "A.java").write_text("class A {}")
        result = _find_java_files(str(tmp_path))
        assert result[0].endswith("A.java")
        assert result[1].endswith("Z.java")


class TestProjectModeDisplay:
    """Tests for project-mode display."""

    def test_display_project_shows_files_analyzed(self, sample_multi_result, capsys):
        _display_results(sample_multi_result, verbose=False)
        captured = capsys.readouterr()
        assert "Files analyzed: 2" in captured.out

    def test_display_project_shows_vulnerabilities(self, sample_multi_result, capsys):
        _display_results(sample_multi_result, verbose=False)
        captured = capsys.readouterr()
        assert "VULNERABILITIES FOUND: 1" in captured.out

    def test_display_cross_file_chain(self, capsys):
        """Cross-file chains show file paths in display."""
        source = Source(
            location=CodeLocation(file_path="Controller.java", line_number=10),
            variable_name="userInput",
            type="User Input",
            confidence=0.9,
            code_snippet="",
        )
        sink = Sink(
            location=CodeLocation(file_path="DAOHelper.java", line_number=20),
            variable_name="query",
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.85,
            code_snippet="",
        )
        chain = TaintChain(
            id="cross-file-chain",
            source=source,
            sink=sink,
            path=[
                PathNode(location=source.location, variable_name="userInput", node_type="source", code_snippet=""),
                PathNode(location=sink.location, variable_name="query", node_type="sink", code_snippet=""),
            ],
            length=2,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.875,
            verification_status=VerificationStatus.VERIFIED,
        )
        result = {
            "file": "project (2 files)",
            "files_analyzed": 2,
            "file_list": ["Controller.java", "DAOHelper.java"],
            "total_chains": 1,
            "verified_chains": [chain],
            "explanations": {},
            "metrics": {
                "sources_found": 1, "sinks_found": 1, "sanitizers_found": 0,
                "chains_found": 1, "chains_verified": 1,
                "verification_rate": 1.0, "explanations_generated": 0,
                "graph_nodes": 4, "graph_edges": 2,
            },
        }
        _display_results(result, verbose=False)
        captured = capsys.readouterr()
        assert "Controller.java:10" in captured.out
        assert "DAOHelper.java:20" in captured.out


class TestDisplayResults:
    """Tests for _display_results."""

    def test_display_no_vulnerabilities(self, runner):
        result = {
            "file": "test.java",
            "total_chains": 0,
            "verified_chains": [],
            "explanations": {},
            "metrics": {
                "sources_found": 1,
                "sinks_found": 1,
                "chains_found": 0,
                "chains_verified": 0,
                "verification_rate": 0.0,
                "explanations_generated": 0,
            },
        }
        # Should not raise
        _display_results(result, verbose=False)

    def test_display_with_vulnerabilities(self, sample_result):
        # Should not raise
        _display_results(sample_result, verbose=False)

    def test_display_verbose(self, sample_result):
        # Should not raise
        _display_results(sample_result, verbose=True)

    def test_display_multi_file(self, sample_multi_result):
        # Should not raise; multi-file display includes "Files analyzed"
        _display_results(sample_multi_result, verbose=False)

    def test_display_multi_file_verbose(self, sample_multi_result):
        _display_results(sample_multi_result, verbose=True)


class TestSaveResults:
    """Tests for _save_results."""

    def test_save_results_basic(self, tmp_path, sample_result):
        output_path = str(tmp_path / "output.json")
        _save_results(sample_result, output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert data["file"] == "test.java"
        assert data["total_chains"] == 1
        assert len(data["vulnerabilities"]) == 1
        vuln = data["vulnerabilities"][0]
        assert vuln["type"] == "sql_injection"
        assert vuln["source"]["variable"] == "userId"
        assert vuln["sink"]["variable"] == "query"

    def test_save_results_with_verification(self, tmp_path, sample_result):
        output_path = str(tmp_path / "output.json")
        _save_results(sample_result, output_path)

        with open(output_path) as f:
            data = json.load(f)

        vuln = data["vulnerabilities"][0]
        assert vuln["verification"] == "verified"

    def test_save_results_with_explanation(self, tmp_path, sample_result, sample_chain):
        explanation = MagicMock()
        explanation.why_vulnerable = "Test explanation"
        explanation.how_to_fix = "Use parameterized queries"
        explanation.example_fix = "stmt.setString(1, param)"
        explanation.severity = "HIGH"
        explanation.cwe_id = "CWE-89"

        sample_result["explanations"] = {sample_chain.id: explanation}

        output_path = str(tmp_path / "output.json")
        _save_results(sample_result, output_path)

        with open(output_path) as f:
            data = json.load(f)

        vuln = data["vulnerabilities"][0]
        assert "explanation" in vuln
        assert vuln["explanation"]["why_vulnerable"] == "Test explanation"
        assert vuln["explanation"]["severity"] == "HIGH"
        assert vuln["explanation"]["cwe_id"] == "CWE-89"

    def test_save_results_empty(self, tmp_path):
        result = {
            "file": "test.java",
            "total_chains": 0,
            "verified_chains": [],
            "explanations": {},
            "metrics": {
                "sources_found": 0,
                "sinks_found": 0,
                "chains_found": 0,
                "chains_verified": 0,
                "verification_rate": 0.0,
                "explanations_generated": 0,
            },
        }
        output_path = str(tmp_path / "empty.json")
        _save_results(result, output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert data["vulnerabilities"] == []

    def test_save_project_results(self, tmp_path, sample_multi_result):
        output_path = str(tmp_path / "project.json")
        _save_results(sample_multi_result, output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert data["analysis_mode"] == "project"
        assert data["files_analyzed"] == 2
        assert data["file_list"] == ["A.java", "B.java"]
        assert len(data["vulnerabilities"]) == 1
        assert data["vulnerabilities"][0]["source"]["file"] == "test.java"

    def test_save_project_has_metrics(self, tmp_path, sample_multi_result):
        output_path = str(tmp_path / "project.json")
        _save_results(sample_multi_result, output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert "metrics" in data
        assert data["metrics"]["chains_verified"] == 1

    def test_save_single_file_includes_file_paths(self, tmp_path, sample_result):
        """Single-file save now includes file paths in source/sink dicts."""
        output_path = str(tmp_path / "single.json")
        _save_results(sample_result, output_path)

        with open(output_path) as f:
            data = json.load(f)

        vuln = data["vulnerabilities"][0]
        assert vuln["source"]["file"] == "test.java"
        assert vuln["sink"]["file"] == "test.java"
