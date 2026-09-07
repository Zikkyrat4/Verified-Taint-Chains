"""Tests for A* pathfinding with semantic heuristics."""

import pytest
import numpy as np
import networkx as nx

from src.core.models import Source, Sink, CodeLocation, VulnerabilityType
from src.stage2_path_discovery.astar_search import (
    AStarPathFinder, SemanticHeuristic,
)


@pytest.fixture
def simple_graph():
    """Create a simple directed graph for testing."""
    g = nx.DiGraph()
    g.add_edge("userId", "temp", weight=1.0)
    g.add_edge("temp", "query", weight=1.0)
    g.add_edge("userId", "query", weight=2.0)
    g.add_edge("other", "unrelated", weight=1.0)
    return g


@pytest.fixture
def complex_graph():
    """Create a more complex graph."""
    g = nx.DiGraph()
    g.add_edge("input", "validate", weight=1.0)
    g.add_edge("validate", "process", weight=1.0)
    g.add_edge("process", "output", weight=1.0)
    g.add_edge("input", "direct", weight=1.0)
    g.add_edge("direct", "output", weight=1.0)
    g.add_edge("input", "log", weight=1.0)
    g.add_edge("log", "file", weight=1.0)
    return g


@pytest.fixture
def sample_source():
    return Source(
        location=CodeLocation(file_path="test.java", line_number=5),
        variable_name="userId",
        type="User Input",
        confidence=0.9,
        code_snippet='String userId = request.getParameter("id");',
    )


@pytest.fixture
def sample_sink():
    return Sink(
        location=CodeLocation(file_path="test.java", line_number=10),
        variable_name="query",
        type="SQL",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        confidence=0.85,
        code_snippet='stmt.executeQuery(query);',
    )


class TestSemanticHeuristic:
    """Tests for SemanticHeuristic."""

    def test_init(self):
        # Uses fallback since CodeBERT might not be loaded
        heuristic = SemanticHeuristic()
        assert heuristic is not None

    def test_get_embedding(self):
        heuristic = SemanticHeuristic()
        emb = heuristic.get_embedding("userId")
        assert isinstance(emb, np.ndarray)
        assert len(emb) > 0

    def test_get_embedding_caching(self):
        heuristic = SemanticHeuristic()
        emb1 = heuristic.get_embedding("testVar")
        emb2 = heuristic.get_embedding("testVar")
        np.testing.assert_array_equal(emb1, emb2)

    def test_get_embedding_with_context(self):
        heuristic = SemanticHeuristic()
        emb = heuristic.get_embedding("userId", context="String parameter")
        assert isinstance(emb, np.ndarray)

    def test_compute_distance(self):
        heuristic = SemanticHeuristic()
        dist = heuristic.compute_distance("userId", "query")
        assert 0.0 <= float(dist) <= 1.0

    def test_compute_distance_same(self):
        heuristic = SemanticHeuristic()
        dist = heuristic.compute_distance("userId", "userId")
        assert float(dist) == pytest.approx(0.0, abs=1e-6)

    def test_compute_distance_different(self):
        heuristic = SemanticHeuristic()
        dist = heuristic.compute_distance("ab", "cd")
        assert dist >= 0.0

    def test_clear_cache(self):
        heuristic = SemanticHeuristic()
        heuristic.get_embedding("test")
        assert len(heuristic.embedding_cache) > 0
        heuristic.clear_cache()
        assert len(heuristic.embedding_cache) == 0


class TestAStarPathFinder:
    """Tests for AStarPathFinder."""

    def test_init(self, simple_graph):
        finder = AStarPathFinder(simple_graph, use_semantic=False)
        assert finder.graph is simple_graph

    def test_find_path_direct(self, simple_graph):
        finder = AStarPathFinder(simple_graph, use_semantic=False)
        path = finder.find_path("userId", "query")
        assert path is not None
        assert path[0] == "userId"
        assert path[-1] == "query"

    def test_find_path_through_intermediate(self, simple_graph):
        finder = AStarPathFinder(simple_graph, use_semantic=False)
        path = finder.find_path("userId", "query")
        assert path is not None
        assert len(path) >= 2

    def test_find_path_no_connection(self, simple_graph):
        finder = AStarPathFinder(simple_graph, use_semantic=False)
        path = finder.find_path("userId", "unrelated")
        assert path is None

    def test_find_path_node_not_in_graph(self, simple_graph):
        finder = AStarPathFinder(simple_graph, use_semantic=False)
        path = finder.find_path("nonexistent", "query")
        assert path is None

    def test_find_path_max_length(self, complex_graph):
        finder = AStarPathFinder(complex_graph, use_semantic=False)
        # With max_length=2, should still find the direct path
        path = finder.find_path("input", "output", max_length=3)
        assert path is not None
        assert len(path) <= 4

    def test_find_path_max_length_too_short(self, complex_graph):
        finder = AStarPathFinder(complex_graph, use_semantic=False)
        # max_length=1 means only source node, no room for sink
        path = finder.find_path("input", "output", max_length=1)
        assert path is None

    def test_find_path_with_semantic(self, simple_graph):
        finder = AStarPathFinder(simple_graph, use_semantic=True)
        path = finder.find_path("userId", "query")
        assert path is not None
        assert path[0] == "userId"
        assert path[-1] == "query"

    def test_find_all_chains(self, simple_graph, sample_source, sample_sink):
        finder = AStarPathFinder(simple_graph, use_semantic=False)
        chains = finder.find_all_chains([sample_source], [sample_sink])
        assert len(chains) >= 1
        chain = chains[0]
        assert chain.source == sample_source
        assert chain.sink == sample_sink
        assert chain.vulnerability_type == VulnerabilityType.SQL_INJECTION

    def test_find_all_chains_no_path(self, sample_source, sample_sink):
        g = nx.DiGraph()
        g.add_node("userId")
        g.add_node("other")
        finder = AStarPathFinder(g, use_semantic=False)
        chains = finder.find_all_chains([sample_source], [sample_sink])
        assert len(chains) == 0

    def test_cross_file_bridge_must_belong_to_source_function(self):
        graph = nx.DiGraph()
        graph.add_edge(
            "A.java:username",
            "B.java:path",
            bridge=True,
            caller_function="processUpload",
        )
        source = Source(
            location=CodeLocation(
                file_path="A.java", line_number=10, function_name="otherEndpoint"
            ),
            variable_name="username",
            type="user_input",
            confidence=0.9,
            code_snippet="String username",
        )
        sink = Sink(
            location=CodeLocation(
                file_path="B.java", line_number=20, function_name="writeFile"
            ),
            variable_name="path",
            type="file_path",
            vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
            confidence=0.9,
            code_snippet="new File(path)",
        )

        chains = AStarPathFinder(graph, use_semantic=False).find_all_chains(
            [source],
            [sink],
            node_id_map={
                id(source): "A.java:username",
                id(sink): "B.java:path",
            },
        )

        assert chains == []

    def test_find_all_chains_multiple(self, simple_graph):
        source1 = Source(
            location=CodeLocation(file_path="t.java", line_number=1),
            variable_name="userId",
            type="User Input",
            confidence=0.9,
            code_snippet='String userId = request.getParameter("id");',
        )
        sink1 = Sink(
            location=CodeLocation(file_path="t.java", line_number=5),
            variable_name="query",
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.8,
            code_snippet='stmt.executeQuery(query);',
        )
        finder = AStarPathFinder(simple_graph, use_semantic=False)
        chains = finder.find_all_chains([source1], [sink1])
        assert len(chains) >= 1

    def test_create_chain_from_path(self, sample_source, sample_sink):
        path = ["userId", "temp", "query"]
        chain = AStarPathFinder._create_chain_from_path(sample_source, sample_sink, path)
        assert chain is not None
        assert chain.source == sample_source
        assert chain.sink == sample_sink
        assert len(chain.path) == 3
        assert chain.confidence == (0.9 + 0.85) / 2.0

    def test_compute_heuristic_same_node(self, simple_graph):
        finder = AStarPathFinder(simple_graph, use_semantic=False)
        h = finder._compute_heuristic("userId", "userId")
        assert h == 0.0

    def test_compute_heuristic_different_nodes(self, simple_graph):
        finder = AStarPathFinder(simple_graph, use_semantic=False)
        h = finder._compute_heuristic("userId", "query")
        assert h >= 0.0

    def test_cycle_detection(self):
        g = nx.DiGraph()
        g.add_edge("a", "b")
        g.add_edge("b", "c")
        g.add_edge("c", "a")  # cycle
        g.add_edge("c", "d")
        finder = AStarPathFinder(g, use_semantic=False)
        path = finder.find_path("a", "d")
        assert path is not None
        assert path == ["a", "b", "c", "d"]

    def test_skip_cross_method_chains(self, simple_graph):
        """Test that A* skips cross-method source-sink pairs."""
        source = Source(
            location=CodeLocation(
                file_path="test.java", line_number=5, function_name="methodA"
            ),
            variable_name="userId",
            type="User Input",
            confidence=0.9,
            code_snippet="",
        )
        sink = Sink(
            location=CodeLocation(
                file_path="test.java", line_number=10, function_name="methodB"
            ),
            variable_name="query",
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.85,
            code_snippet="",
        )
        finder = AStarPathFinder(simple_graph, use_semantic=False)
        chains = finder.find_all_chains([source], [sink])
        assert len(chains) == 0

    def test_allow_cross_method_chain_through_declared_field(self):
        graph = nx.DiGraph()
        graph.add_node("title")
        graph.add_node("m_title", is_field=True)
        graph.add_edge(
            "title",
            "m_title",
            function_name="setTitle",
            field_flow_functions=["setTitle"],
        )
        source = Source(
            location=CodeLocation(
                file_path="Tag.java", line_number=5, function_name="setTitle"
            ),
            variable_name="title", type="user_input", confidence=0.9,
            code_snippet="m_title = title;",
        )
        sink = Sink(
            location=CodeLocation(
                file_path="Tag.java", line_number=20, function_name="render"
            ),
            variable_name="m_title", type="html_output", confidence=0.9,
            code_snippet="out.print(m_title);",
            vulnerability_type=VulnerabilityType.XSS,
        )

        chains = AStarPathFinder(graph, use_semantic=False).find_all_chains(
            [source], [sink]
        )

        assert len(chains) == 1

    def test_reject_cross_method_chain_borrowing_unrelated_method_edge(self):
        graph = nx.DiGraph()
        graph.add_node("input")
        graph.add_node("shared", is_field=True)
        graph.add_node("output")
        graph.add_edge("input", "shared", function_name="sourceMethod")
        graph.add_edge("shared", "output", function_name="unrelatedMethod")
        source = Source(
            location=CodeLocation(
                file_path="T.java", line_number=5, function_name="sourceMethod"
            ),
            variable_name="input", type="user_input", confidence=0.9,
            code_snippet="shared = input;",
        )
        sink = Sink(
            location=CodeLocation(
                file_path="T.java", line_number=30, function_name="sinkMethod"
            ),
            variable_name="output", type="html_output", confidence=0.9,
            code_snippet="out.print(output);",
            vulnerability_type=VulnerabilityType.XSS,
        )

        chains = AStarPathFinder(graph, use_semantic=False).find_all_chains(
            [source], [sink]
        )

        assert chains == []

    def test_allow_same_method_chains(self, simple_graph):
        """Test that A* allows same-method source-sink pairs."""
        source = Source(
            location=CodeLocation(
                file_path="test.java", line_number=5, function_name="process"
            ),
            variable_name="userId",
            type="User Input",
            confidence=0.9,
            code_snippet="",
        )
        sink = Sink(
            location=CodeLocation(
                file_path="test.java", line_number=10, function_name="process"
            ),
            variable_name="query",
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.85,
            code_snippet="",
        )
        finder = AStarPathFinder(simple_graph, use_semantic=False)
        chains = finder.find_all_chains([source], [sink])
        assert len(chains) >= 1
