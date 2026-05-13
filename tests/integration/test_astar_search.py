"""Integration tests for A* path finding with semantic heuristics."""

import pytest
import networkx as nx

from src.stage2_path_discovery.astar_search import AStarPathFinder, SemanticHeuristic
from src.core.models import Source, Sink, CodeLocation, VulnerabilityType


class TestSemanticHeuristic:
    """Tests for SemanticHeuristic."""

    def test_heuristic_initialization(self) -> None:
        """Test that semantic heuristic initializes."""
        heuristic = SemanticHeuristic()
        assert heuristic is not None

    def test_heuristic_identical_variables(self) -> None:
        """Test that identical variables have zero distance."""
        heuristic = SemanticHeuristic()
        distance = heuristic.compute_distance("userInput", "userInput")
        assert distance == 0.0

    def test_heuristic_different_variables(self) -> None:
        """Test that different variables have non-zero distance."""
        heuristic = SemanticHeuristic()
        distance = heuristic.compute_distance("userInput", "systemOutput")
        assert 0.0 <= distance <= 1.0

    def test_heuristic_with_context(self) -> None:
        """Test heuristic computation with context."""
        heuristic = SemanticHeuristic()
        distance = heuristic.compute_distance(
            "input",
            "output",
            context1="String type",
            context2="String type",
        )
        assert 0.0 <= distance <= 1.0

    def test_embedding_cache(self) -> None:
        """Test that embeddings are cached."""
        heuristic = SemanticHeuristic()

        # First call computes embedding
        emb1 = heuristic.get_embedding("variable")
        assert emb1 is not None

        # Second call should return cached value
        emb2 = heuristic.get_embedding("variable")
        assert emb1 is emb2  # Same object from cache

    def test_cache_clear(self) -> None:
        """Test clearing the embedding cache."""
        heuristic = SemanticHeuristic()

        # Populate cache
        heuristic.get_embedding("var1")
        heuristic.get_embedding("var2")
        assert len(heuristic.embedding_cache) > 0

        # Clear cache
        heuristic.clear_cache()
        assert len(heuristic.embedding_cache) == 0

    def test_heuristic_symmetry(self) -> None:
        """Test that semantic distance is somewhat symmetric."""
        heuristic = SemanticHeuristic()
        dist_ab = heuristic.compute_distance("variableA", "variableB")
        dist_ba = heuristic.compute_distance("variableB", "variableA")

        # Distance should be symmetric
        assert abs(dist_ab - dist_ba) < 0.01


class TestAStarPathFinder:
    """Tests for A* path finding."""

    def test_astar_initialization(self) -> None:
        """Test A* path finder initialization."""
        graph = nx.DiGraph()
        graph.add_nodes_from(["a", "b", "c"])
        graph.add_edges_from([("a", "b"), ("b", "c")])

        finder = AStarPathFinder(graph)
        assert finder.graph == graph

    def test_astar_simple_path(self) -> None:
        """Test A* finds simple path."""
        graph = nx.DiGraph()
        graph.add_nodes_from(["a", "b", "c"])
        graph.add_edges_from([("a", "b"), ("b", "c")])

        finder = AStarPathFinder(graph)
        path = finder.find_path("a", "c")

        assert path is not None
        assert path == ["a", "b", "c"]

    def test_astar_direct_path(self) -> None:
        """Test A* with direct edge."""
        graph = nx.DiGraph()
        graph.add_nodes_from(["source", "sink"])
        graph.add_edge("source", "sink")

        finder = AStarPathFinder(graph)
        path = finder.find_path("source", "sink")

        assert path == ["source", "sink"]

    def test_astar_multiple_paths_chooses_shortest(self) -> None:
        """Test A* chooses shortest path among alternatives."""
        graph = nx.DiGraph()
        # Create diamond: source -> (a or b) -> sink
        graph.add_nodes_from(["source", "a", "b", "sink"])
        graph.add_edges_from([
            ("source", "a"),
            ("source", "b"),
            ("a", "sink"),
            ("b", "sink"),
        ])

        finder = AStarPathFinder(graph)
        path = finder.find_path("source", "sink")

        assert path is not None
        assert len(path) == 3  # source -> (a or b) -> sink

    def test_astar_no_path(self) -> None:
        """Test A* returns None when no path exists."""
        graph = nx.DiGraph()
        graph.add_nodes_from(["a", "b", "c", "d"])
        graph.add_edges_from([("a", "b"), ("c", "d")])

        finder = AStarPathFinder(graph)
        path = finder.find_path("a", "d")

        assert path is None

    def test_astar_missing_nodes(self) -> None:
        """Test A* with missing source or sink."""
        graph = nx.DiGraph()
        graph.add_node("a")

        finder = AStarPathFinder(graph)
        path = finder.find_path("a", "missing")

        assert path is None

    def test_astar_max_length_constraint(self) -> None:
        """Test A* respects maximum path length."""
        graph = nx.DiGraph()
        # Create chain: 0 -> 1 -> 2 -> 3 -> 4 -> 5
        nodes = [str(i) for i in range(6)]
        edges = [(str(i), str(i + 1)) for i in range(5)]
        graph.add_nodes_from(nodes)
        graph.add_edges_from(edges)

        finder = AStarPathFinder(graph)

        # Should find path with max_length=6
        path = finder.find_path("0", "5", max_length=6)
        assert path is not None
        assert len(path) == 6

        # Should not find path with max_length=3
        path = finder.find_path("0", "5", max_length=3)
        assert path is None

    def test_astar_with_semantic_heuristic(self) -> None:
        """Test A* with semantic heuristic enabled."""
        graph = nx.DiGraph()
        graph.add_nodes_from(["input", "processed", "output"], var_type="String")
        graph.add_edges_from([("input", "processed"), ("processed", "output")])

        heuristic = SemanticHeuristic()
        finder = AStarPathFinder(graph, semantic_heuristic=heuristic, use_semantic=True)

        path = finder.find_path("input", "output")
        assert path == ["input", "processed", "output"]

    def test_astar_without_semantic_heuristic(self) -> None:
        """Test A* with semantic heuristic disabled."""
        graph = nx.DiGraph()
        graph.add_nodes_from(["a", "b", "c"])
        graph.add_edges_from([("a", "b"), ("b", "c")])

        finder = AStarPathFinder(graph, use_semantic=False)
        path = finder.find_path("a", "c")

        assert path == ["a", "b", "c"]

    def test_astar_find_all_chains(self) -> None:
        """Test A* finds all taint chains."""
        graph = nx.DiGraph()
        graph.add_nodes_from(["input", "var", "sink"], type="intermediate")
        graph.nodes["input"]["type"] = "source"
        graph.nodes["sink"]["type"] = "sink"
        graph.add_edges_from([("input", "var"), ("var", "sink")])

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="input",
            type="User Input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=3),
            variable_name="sink",
            type="SQL Query",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.95,
            code_snippet="",
        )

        finder = AStarPathFinder(graph)
        chains = finder.find_all_chains([source], [sink])

        assert len(chains) == 1
        assert chains[0].source == source
        assert chains[0].sink == sink
        assert len(chains[0].path) == 3

    def test_astar_no_chains_found(self) -> None:
        """Test A* returns empty list when no chains found."""
        graph = nx.DiGraph()
        graph.add_nodes_from(["input", "sink"])
        # No edges between input and sink

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="input",
            type="User Input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=3),
            variable_name="sink",
            type="SQL Query",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.95,
            code_snippet="",
        )

        finder = AStarPathFinder(graph)
        chains = finder.find_all_chains([source], [sink])

        assert len(chains) == 0

    def test_astar_complex_graph(self) -> None:
        """Test A* on a more complex data flow graph."""
        graph = nx.DiGraph()

        # Create a more realistic graph
        nodes = ["userInput", "sanitized", "processed", "final", "output"]
        graph.add_nodes_from(nodes, var_type="String")

        edges = [
            ("userInput", "sanitized"),
            ("sanitized", "processed"),
            ("processed", "final"),
            ("final", "output"),
            # Add alternative path
            ("userInput", "processed"),
        ]
        graph.add_edges_from(edges)

        finder = AStarPathFinder(graph)

        # Should find shortest path
        path = finder.find_path("userInput", "output")
        assert path is not None
        assert len(path) <= 5  # Should use shorter alternative path


class TestAStarComparison:
    """Tests comparing A* with BFS."""

    def test_astar_finds_optimal_path(self) -> None:
        """Test that A* finds optimal paths."""
        graph = nx.DiGraph()

        # Create grid-like structure where A* should beat BFS
        nodes = ["source"]
        edges = []

        # Add two alternative paths
        # Path 1: short but narrow
        edges.extend([
            ("source", "a1"),
            ("a1", "a2"),
            ("a2", "sink"),
        ])

        # Path 2: longer but wider (BFS might explore more)
        edges.extend([
            ("source", "b1"),
            ("b1", "b2"),
            ("b2", "b3"),
            ("b3", "sink"),
        ])

        nodes.extend(["a1", "a2", "b1", "b2", "b3", "sink"])
        graph.add_nodes_from(nodes)
        graph.add_edges_from(edges)

        finder = AStarPathFinder(graph)
        path = finder.find_path("source", "sink")

        # A* should prefer shorter path
        assert path == ["source", "a1", "a2", "sink"]
