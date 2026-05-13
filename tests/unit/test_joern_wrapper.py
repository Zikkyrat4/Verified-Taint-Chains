"""Tests for JoernWrapper."""

import json
import pytest
from unittest.mock import patch, MagicMock

from src.core.models import Source, Sink, CodeLocation, VulnerabilityType
from src.stage2_path_discovery.joern_wrapper import JoernWrapper


@pytest.fixture
def sample_sources():
    return [
        Source(
            location=CodeLocation(file_path="test.java", line_number=5),
            variable_name="userInput",
            type="User Input",
            confidence=0.9,
            code_snippet='String userInput = request.getParameter("input");',
        )
    ]


@pytest.fixture
def sample_sinks():
    return [
        Sink(
            location=CodeLocation(file_path="test.java", line_number=10),
            variable_name="query",
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.85,
            code_snippet='db.execute(query);',
        )
    ]


SAMPLE_CODE = """
public class Test {
    public void process(String userInput) {
        String query = "SELECT * FROM t WHERE id=" + userInput;
        db.execute(query);
    }
}
"""


class TestJoernWrapper:
    """Tests for JoernWrapper."""

    @patch("src.stage2_path_discovery.joern_wrapper.JoernWrapper._check_joern_available")
    def test_init_joern_unavailable(self, mock_check):
        mock_check.return_value = False
        wrapper = JoernWrapper()
        assert wrapper.joern_available is False
        assert wrapper.fallback_builder is not None

    @patch("src.stage2_path_discovery.joern_wrapper.JoernWrapper._check_joern_available")
    def test_build_graph_fallback(self, mock_check, sample_sources, sample_sinks):
        mock_check.return_value = False
        wrapper = JoernWrapper()
        graph = wrapper.build_graph(SAMPLE_CODE, sample_sources, sample_sinks)
        assert graph is not None
        assert graph.number_of_nodes() > 0

    @patch("src.stage2_path_discovery.joern_wrapper.JoernWrapper._check_joern_available")
    def test_get_joern_status_unavailable(self, mock_check):
        mock_check.return_value = False
        wrapper = JoernWrapper()
        status = wrapper.get_joern_status()
        assert status["joern_available"] is False
        assert status["using_fallback"] is True

    @patch("src.stage2_path_discovery.joern_wrapper.JoernWrapper._check_joern_available")
    def test_get_joern_status_available(self, mock_check):
        mock_check.return_value = True
        wrapper = JoernWrapper()
        status = wrapper.get_joern_status()
        assert status["joern_available"] is True
        assert status["using_fallback"] is False

    @patch("subprocess.run")
    def test_check_joern_available_found(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="1.0.0")
        wrapper = JoernWrapper.__new__(JoernWrapper)
        result = wrapper._check_joern_available()
        assert result is True

    @patch("subprocess.run")
    def test_check_joern_available_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError
        wrapper = JoernWrapper.__new__(JoernWrapper)
        result = wrapper._check_joern_available()
        assert result is False

    @patch("subprocess.run")
    def test_check_joern_available_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="joern", timeout=5)
        wrapper = JoernWrapper.__new__(JoernWrapper)
        result = wrapper._check_joern_available()
        assert result is False

    def test_parse_json_pdg(self, sample_sources, sample_sinks):
        wrapper = JoernWrapper.__new__(JoernWrapper)
        pdg_data = {
            "nodes": [
                {"id": "userInput", "type": "source", "label": "userInput"},
                {"id": "query", "type": "sink", "label": "query"},
            ],
            "edges": [
                {"source": "userInput", "target": "query", "type": "data_flow"},
            ],
        }
        graph = wrapper._parse_json_pdg(pdg_data, sample_sources, sample_sinks)
        assert graph.number_of_nodes() == 2
        assert graph.number_of_edges() == 1
        assert graph.has_edge("userInput", "query")

    def test_parse_json_pdg_with_context(self, sample_sources, sample_sinks):
        wrapper = JoernWrapper.__new__(JoernWrapper)
        pdg_data = {
            "nodes": [
                {"id": "userInput", "type": "variable"},
                {"id": "query", "type": "variable"},
                {"id": "other", "type": "literal"},
            ],
            "edges": [
                {"source": "userInput", "target": "query"},
            ],
        }
        graph = wrapper._parse_json_pdg(pdg_data, sample_sources, sample_sinks)
        # userInput should be marked as source context
        assert graph.nodes["userInput"].get("source_context") is True
        assert graph.nodes["query"].get("sink_context") is True

    def test_parse_json_pdg_empty(self, sample_sources, sample_sinks):
        wrapper = JoernWrapper.__new__(JoernWrapper)
        pdg_data = {}
        graph = wrapper._parse_json_pdg(pdg_data, sample_sources, sample_sinks)
        assert graph.number_of_nodes() == 0

    def test_parse_text_pdg(self, sample_sources, sample_sinks):
        wrapper = JoernWrapper.__new__(JoernWrapper)
        text_output = "userInput -> query\nquery -> dbExec\n"
        graph = wrapper._parse_text_pdg(text_output, sample_sources, sample_sinks)
        assert graph.number_of_nodes() >= 2
        assert graph.has_edge("userInput", "query")
        assert graph.has_edge("query", "dbExec")

    def test_parse_text_pdg_with_comments(self, sample_sources, sample_sinks):
        wrapper = JoernWrapper.__new__(JoernWrapper)
        text_output = "# comment\nuserInput -> query\n\n# another comment\n"
        graph = wrapper._parse_text_pdg(text_output, sample_sources, sample_sinks)
        assert graph.has_edge("userInput", "query")
        assert graph.number_of_edges() == 1

    def test_parse_text_pdg_empty(self, sample_sources, sample_sinks):
        wrapper = JoernWrapper.__new__(JoernWrapper)
        text_output = ""
        graph = wrapper._parse_text_pdg(text_output, sample_sources, sample_sinks)
        # Should still have source and sink nodes
        assert "userInput" in graph.nodes
        assert "query" in graph.nodes

    def test_parse_joern_pdg_json(self, sample_sources, sample_sinks):
        wrapper = JoernWrapper.__new__(JoernWrapper)
        json_output = json.dumps({
            "nodes": [{"id": "a"}, {"id": "b"}],
            "edges": [{"source": "a", "target": "b"}],
        })
        graph = wrapper._parse_joern_pdg(json_output, sample_sources, sample_sinks)
        assert graph.number_of_nodes() == 2

    def test_parse_joern_pdg_text_fallback(self, sample_sources, sample_sinks):
        wrapper = JoernWrapper.__new__(JoernWrapper)
        text_output = "a -> b\nb -> c"
        graph = wrapper._parse_joern_pdg(text_output, sample_sources, sample_sinks)
        assert graph.has_edge("a", "b")

    @patch("src.stage2_path_discovery.joern_wrapper.JoernWrapper._check_joern_available")
    @patch("src.stage2_path_discovery.joern_wrapper.JoernWrapper._build_graph_with_joern")
    def test_build_graph_joern_fails_fallback(
        self, mock_build, mock_check, sample_sources, sample_sinks
    ):
        mock_check.return_value = True
        mock_build.side_effect = RuntimeError("Joern failed")
        wrapper = JoernWrapper()
        graph = wrapper.build_graph(SAMPLE_CODE, sample_sources, sample_sinks)
        # Should fall back to EnhancedGraphBuilder
        assert graph is not None
        assert graph.number_of_nodes() > 0
