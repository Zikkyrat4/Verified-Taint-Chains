"""Tests for LLM-driven graph builder."""

import pytest
import networkx as nx
from unittest.mock import Mock, AsyncMock, patch

from src.core.config import PipelineConfig
from src.core.models import Source, Sink, CodeLocation, VulnerabilityType
from src.stage2_path_discovery.llm_graph_builder import LLMGraphBuilder
from src.stage2_path_discovery.graph_builder import EnhancedGraphBuilder


@pytest.fixture
def mock_llm_client():
    """Create mock LLM client for graph enrichment."""
    client = Mock()
    client.chat_with_json_prompt = AsyncMock(return_value={
        "additional_flows": [],
        "classifications": [],
    })
    return client


@pytest.fixture
def config():
    return PipelineConfig(
        llm_api_key="test-key",
        llm_model="gpt-4-turbo",
        use_llm_graph_builder=True,
        llm_graph_enrichment_confidence=0.7,
    )


@pytest.fixture
def sample_java_code():
    return """
public class UserController {
    public String getUser(HttpServletRequest request) {
        String userId = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(query);
        return rs.getString("name");
    }
}
"""


@pytest.fixture
def sample_sources():
    return [
        Source(
            location=CodeLocation(file_path="test.java", line_number=3),
            variable_name="userId",
            type="user_input",
            confidence=0.9,
            code_snippet='String userId = request.getParameter("id");',
        )
    ]


@pytest.fixture
def sample_sinks():
    return [
        Sink(
            location=CodeLocation(file_path="test.java", line_number=5),
            variable_name="query",
            type="sql",
            confidence=0.9,
            code_snippet="stmt.executeQuery(query)",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )
    ]


class TestBuildBaseGraph:
    """Tests for sync build_graph (AST-based, no LLM)."""

    def test_build_base_graph_returns_digraph(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """build_graph should return a networkx DiGraph."""
        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        assert isinstance(graph, nx.DiGraph)

    def test_build_base_graph_has_source_nodes(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """Graph should contain source variable nodes."""
        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        assert "userId" in graph.nodes
        assert graph.nodes["userId"]["type"] == "source"

    def test_build_base_graph_has_sink_nodes(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """Graph should contain sink variable nodes."""
        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        assert "query" in graph.nodes
        assert graph.nodes["query"]["type"] == "sink"

    def test_build_base_graph_has_edges(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """Graph should contain data flow edges from AST."""
        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        assert graph.number_of_edges() > 0

    def test_build_base_graph_has_ast_edges(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """Edges should be marked as ast_explicit."""
        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        ast_edges = [
            (u, v) for u, v, d in graph.edges(data=True)
            if d.get("edge_type") == "ast_explicit"
        ]
        assert len(ast_edges) > 0

    def test_build_base_graph_no_llm_call(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """build_graph (sync) should NOT call the LLM."""
        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        mock_llm_client.chat_with_json_prompt.assert_not_called()


class TestBuildBaseGraphRegexFallback:
    """Tests for regex fallback when tree-sitter unavailable."""

    def test_regex_fallback_produces_graph(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """Graph should be built even when tree-sitter is unavailable."""
        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        # Force parser to None to simulate tree-sitter unavailable
        builder.ast_parser.parser = None
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        assert isinstance(graph, nx.DiGraph)
        assert "userId" in graph.nodes
        assert "query" in graph.nodes

    def test_regex_fallback_has_edges(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """Regex fallback should still produce data flow edges."""
        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        builder.ast_parser.parser = None
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        assert graph.number_of_edges() > 0


class TestEnrichGraph:
    """Tests for async enrich_graph (LLM enrichment)."""

    @pytest.mark.asyncio
    async def test_enrich_graph_adds_llm_edges(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """LLM-inferred flows should be added as edges."""
        mock_llm_client.chat_with_json_prompt = AsyncMock(return_value={
            "additional_flows": [
                {"from": "userId", "to": "query", "flow_type": "implicit", "confidence": 0.9},
            ],
            "classifications": [],
        })

        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)

        # Remove any pre-existing edge between userId and query for this test
        if graph.has_edge("userId", "query"):
            graph.remove_edge("userId", "query")

        graph = await builder.enrich_graph(graph, sample_java_code, sample_sources, sample_sinks)

        assert graph.has_edge("userId", "query")
        edge_data = graph.edges["userId", "query"]
        assert edge_data["edge_type"] == "llm_inferred"
        assert edge_data["flow_type"] == "implicit"

    @pytest.mark.asyncio
    async def test_enrich_graph_applies_classifications(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """LLM classifications should be applied to node attributes."""
        mock_llm_client.chat_with_json_prompt = AsyncMock(return_value={
            "additional_flows": [],
            "classifications": [
                {"variable": "userId", "classification": "SOURCE", "confidence": 0.95},
                {"variable": "query", "classification": "SINK", "confidence": 0.9},
            ],
        })

        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        graph = await builder.enrich_graph(graph, sample_java_code, sample_sources, sample_sinks)

        assert graph.nodes["userId"]["security_class"] == "SOURCE"
        assert graph.nodes["query"]["security_class"] == "SINK"

    @pytest.mark.asyncio
    async def test_enrich_graph_filters_low_confidence(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """Flows below confidence threshold should be ignored."""
        mock_llm_client.chat_with_json_prompt = AsyncMock(return_value={
            "additional_flows": [
                {"from": "userId", "to": "query", "flow_type": "implicit", "confidence": 0.3},
            ],
            "classifications": [],
        })

        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)

        # Remove pre-existing edges for clean test
        edges_before = set(graph.edges())

        graph = await builder.enrich_graph(graph, sample_java_code, sample_sources, sample_sinks)

        # No new llm_inferred edges should be added
        llm_edges = [
            (u, v) for u, v, d in graph.edges(data=True)
            if d.get("edge_type") == "llm_inferred"
        ]
        assert len(llm_edges) == 0

    @pytest.mark.asyncio
    async def test_enrich_graph_ignores_unknown_nodes(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """Flows referencing non-existent nodes should be silently ignored."""
        mock_llm_client.chat_with_json_prompt = AsyncMock(return_value={
            "additional_flows": [
                {"from": "nonExistent", "to": "alsoNonExistent", "flow_type": "implicit", "confidence": 0.9},
            ],
            "classifications": [],
        })

        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        edges_before = graph.number_of_edges()

        graph = await builder.enrich_graph(graph, sample_java_code, sample_sources, sample_sinks)

        # No edges referencing unknown nodes should be added
        llm_edges = [
            (u, v) for u, v, d in graph.edges(data=True)
            if d.get("edge_type") == "llm_inferred"
        ]
        assert len(llm_edges) == 0

    @pytest.mark.asyncio
    async def test_enrich_graph_failure_graceful(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """LLM failure should not crash; graph returned unchanged."""
        mock_llm_client.chat_with_json_prompt = AsyncMock(
            side_effect=Exception("LLM API error")
        )

        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        edges_before = graph.number_of_edges()
        nodes_before = graph.number_of_nodes()

        graph = await builder.enrich_graph(graph, sample_java_code, sample_sources, sample_sinks)

        assert graph.number_of_edges() == edges_before
        assert graph.number_of_nodes() == nodes_before

    @pytest.mark.asyncio
    async def test_enrich_graph_calls_llm(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """enrich_graph should call the LLM client."""
        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        await builder.enrich_graph(graph, sample_java_code, sample_sources, sample_sinks)

        mock_llm_client.chat_with_json_prompt.assert_called_once()


class TestSameInterfaceAsEnhancedBuilder:
    """Verify LLMGraphBuilder.build_graph() has same interface as EnhancedGraphBuilder."""

    def test_same_return_type(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """Both builders should return nx.DiGraph."""
        llm_builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        enhanced_builder = EnhancedGraphBuilder()

        llm_graph = llm_builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        enhanced_graph = enhanced_builder.build_graph(sample_java_code, sample_sources, sample_sinks)

        assert isinstance(llm_graph, nx.DiGraph)
        assert isinstance(enhanced_graph, nx.DiGraph)

    def test_same_node_types(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """Both builders should produce nodes with type attribute."""
        llm_builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        llm_graph = llm_builder.build_graph(sample_java_code, sample_sources, sample_sinks)

        # Source and sink nodes should have type attributes
        assert llm_graph.nodes["userId"]["type"] == "source"
        assert llm_graph.nodes["query"]["type"] == "sink"

    def test_source_and_sink_present(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """Both source and sink variables must be in the graph."""
        llm_builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        llm_graph = llm_builder.build_graph(sample_java_code, sample_sources, sample_sinks)

        for src in sample_sources:
            assert src.variable_name in llm_graph.nodes
        for snk in sample_sinks:
            assert snk.variable_name in llm_graph.nodes


class TestEnrichmentPrompt:
    """Tests for the enrichment prompt building."""

    def test_prompt_contains_code(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """Enrichment prompt should contain the source code."""
        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        prompt = builder._build_enrichment_prompt(graph, sample_java_code)
        assert "UserController" in prompt

    def test_prompt_contains_flows(
        self, mock_llm_client, config, sample_java_code, sample_sources, sample_sinks
    ):
        """Enrichment prompt should list existing flows."""
        builder = LLMGraphBuilder(llm_client=mock_llm_client, config=config)
        graph = builder.build_graph(sample_java_code, sample_sources, sample_sinks)
        prompt = builder._build_enrichment_prompt(graph, sample_java_code)
        assert "->" in prompt  # Flow notation
