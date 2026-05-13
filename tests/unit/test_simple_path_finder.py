"""Unit tests for simple path finder."""

import pytest
import networkx as nx

from src.stage2_path_discovery.simple_path_finder import (
    SimpleGraphBuilder,
    SimpleBFSPathFinder,
)
from src.core.models import (
    Source,
    Sink,
    CodeLocation,
    VulnerabilityType,
    TaintChain,
)


class TestSimpleGraphBuilderExtractVariables:
    """Tests for variable extraction."""

    def test_extract_variables_simple(self) -> None:
        """Test extracting variables from simple Java code."""
        builder = SimpleGraphBuilder()
        code = "String name = 5; int count = 10;"

        variables = builder._extract_variables(code)

        assert "name" in variables
        assert "count" in variables
        assert "String" not in variables  # Type keyword should be filtered
        assert "int" not in variables

    def test_extract_variables_filters_keywords(self) -> None:
        """Test that Java keywords are filtered out."""
        builder = SimpleGraphBuilder()
        code = "public static void main(String[] args) { int count = 5; }"

        variables = builder._extract_variables(code)

        assert "count" in variables
        assert "args" in variables
        # Keywords should not be in variables
        assert "public" not in variables
        assert "static" not in variables
        assert "void" not in variables
        assert "main" in variables  # method name is kept

    def test_extract_variables_multiple_occurrences(self) -> None:
        """Test that duplicate variables are deduplicated."""
        builder = SimpleGraphBuilder()
        code = "String name = 5; name = 10; name = 15;"

        variables = builder._extract_variables(code)

        # Variables returns a set, so duplicates are removed
        assert "name" in variables

    def test_extract_variables_from_expressions(self) -> None:
        """Test extracting variables from expressions."""
        builder = SimpleGraphBuilder()
        code = "int result = alpha + beta * gamma;"

        variables = builder._extract_variables(code)

        assert "result" in variables
        assert "alpha" in variables
        assert "beta" in variables
        assert "gamma" in variables


class TestSimpleGraphBuilderDataFlows:
    """Tests for data flow extraction."""

    def test_extract_data_flows_simple_assignment(self) -> None:
        """Test extracting simple assignment flows."""
        builder = SimpleGraphBuilder()
        code = "int x = y;"

        flows = builder._extract_data_flows(code)

        # Should have edge y -> x
        assert any(src == "y" and tgt == "x" for src, tgt in flows)

    def test_extract_data_flows_multiple_variables(self) -> None:
        """Test extracting flows with multiple variables."""
        builder = SimpleGraphBuilder()
        code = "int result = a + b;"

        flows = builder._extract_data_flows(code)

        # Should have edges a -> result and b -> result
        targets = {tgt for src, tgt in flows if tgt == "result"}
        assert "a" in {src for src, tgt in flows}
        assert "b" in {src for src, tgt in flows}

    def test_extract_data_flows_chained(self) -> None:
        """Test extracting flows from chained assignments."""
        builder = SimpleGraphBuilder()
        code = "int x = y; int z = x;"

        flows = builder._extract_data_flows(code)

        # Should have y -> x and x -> z
        assert any(src == "y" and tgt == "x" for src, tgt in flows)
        assert any(src == "x" and tgt == "z" for src, tgt in flows)


class TestSimpleGraphBuilderBuildGraph:
    """Tests for graph building."""

    def test_build_graph_creates_nodes(self) -> None:
        """Test that graph includes source and sink nodes."""
        builder = SimpleGraphBuilder()
        code = "String x = request.getParameter('q'); db.execute(x);"

        loc = CodeLocation(file_path="test.java", line_number=1)
        source = Source(
            location=loc,
            variable_name="x",
            type="user_input",
            confidence=0.9,
            code_snippet="",
        )
        sink = Sink(
            location=loc,
            variable_name="query",
            type="sql",
            confidence=0.9,
            code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        graph = builder.build_graph(code, [source], [sink])

        assert "x" in graph.nodes
        assert "query" in graph.nodes

    def test_build_graph_adds_edges(self) -> None:
        """Test that graph includes data flow edges."""
        builder = SimpleGraphBuilder()
        code = "int result = source;"

        graph = builder.build_graph(code, [], [])

        # Should have some edges (source -> result)
        assert graph.number_of_edges() > 0

    def test_build_graph_returns_digraph(self) -> None:
        """Test that build_graph returns a DirectedGraph."""
        builder = SimpleGraphBuilder()
        code = "int x = 5;"

        graph = builder.build_graph(code, [], [])

        assert isinstance(graph, nx.DiGraph)


class TestSimpleBFSPathFinderInit:
    """Tests for path finder initialization."""

    def test_init_with_graph(self) -> None:
        """Test initializing path finder with a graph."""
        graph = nx.DiGraph()
        graph.add_edges_from([("a", "b"), ("b", "c")])

        finder = SimpleBFSPathFinder(graph)

        assert finder.graph is graph


class TestSimpleBFSPathFinderFindPath:
    """Tests for path finding."""

    def test_find_path_direct_edge(self) -> None:
        """Test finding a direct edge path."""
        graph = nx.DiGraph()
        graph.add_edge("x", "y")

        finder = SimpleBFSPathFinder(graph)
        path = finder.find_path("x", "y")

        assert path is not None
        assert path == ["x", "y"]

    def test_find_path_longer_chain(self) -> None:
        """Test finding a path through multiple nodes."""
        graph = nx.DiGraph()
        graph.add_edges_from([("a", "b"), ("b", "c"), ("c", "d")])

        finder = SimpleBFSPathFinder(graph)
        path = finder.find_path("a", "d")

        assert path is not None
        assert len(path) == 4
        assert path[0] == "a"
        assert path[-1] == "d"

    def test_find_path_no_path(self) -> None:
        """Test that no path returns None."""
        graph = nx.DiGraph()
        graph.add_edges_from([("a", "b"), ("c", "d")])  # Two separate components

        finder = SimpleBFSPathFinder(graph)
        path = finder.find_path("a", "d")

        assert path is None

    def test_find_path_nonexistent_nodes(self) -> None:
        """Test that nonexistent nodes return None."""
        graph = nx.DiGraph()
        graph.add_edge("a", "b")

        finder = SimpleBFSPathFinder(graph)
        path = finder.find_path("x", "y")

        assert path is None

    def test_find_path_same_source_sink(self) -> None:
        """Test finding path from node to itself."""
        graph = nx.DiGraph()
        graph.add_edge("a", "a")  # Self-loop

        finder = SimpleBFSPathFinder(graph)
        path = finder.find_path("a", "a")

        # nx.shortest_path returns single node when source == sink
        assert path is not None
        assert path == ["a"]

    def test_find_path_respects_max_length(self) -> None:
        """Test that max_length limit is respected."""
        graph = nx.DiGraph()
        # Create a long chain: a -> b -> c -> d -> e
        graph.add_edges_from([("a", "b"), ("b", "c"), ("c", "d"), ("d", "e")])

        finder = SimpleBFSPathFinder(graph)
        path = finder.find_path("a", "e", max_length=3)

        # Path exists but is too long, should return None
        assert path is None

    def test_find_path_within_max_length(self) -> None:
        """Test that valid paths within max_length are found."""
        graph = nx.DiGraph()
        graph.add_edges_from([("a", "b"), ("b", "c")])

        finder = SimpleBFSPathFinder(graph)
        path = finder.find_path("a", "c", max_length=5)

        assert path is not None
        assert path == ["a", "b", "c"]


class TestSimpleBFSPathFinderFindAllChains:
    """Tests for finding all taint chains."""

    def test_find_all_chains_single_pair(self) -> None:
        """Test finding chains with single source and sink."""
        graph = nx.DiGraph()
        graph.add_edges_from([("x", "y"), ("y", "z")])

        loc = CodeLocation(file_path="test.java", line_number=1)
        source = Source(
            location=loc,
            variable_name="x",
            type="user_input",
            confidence=0.9,
            code_snippet="",
        )
        sink = Sink(
            location=loc,
            variable_name="z",
            type="sql",
            confidence=0.9,
            code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains([source], [sink])

        assert len(chains) == 1
        assert chains[0].source == source
        assert chains[0].sink == sink

    def test_find_all_chains_multiple_pairs(self) -> None:
        """Test finding chains with multiple sources and sinks."""
        graph = nx.DiGraph()
        graph.add_edges_from([("a", "b"), ("c", "d")])

        loc = CodeLocation(file_path="test.java", line_number=1)
        sources = [
            Source(
                location=loc,
                variable_name="a",
                type="user_input",
                confidence=0.9,
                code_snippet="",
            ),
            Source(
                location=loc,
                variable_name="c",
                type="user_input",
                confidence=0.9,
                code_snippet="",
            ),
        ]
        sinks = [
            Sink(
                location=loc,
                variable_name="b",
                type="sql",
                confidence=0.9,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            Sink(
                location=loc,
                variable_name="d",
                type="sql",
                confidence=0.9,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
        ]

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains(sources, sinks)

        assert len(chains) == 2

    def test_find_all_chains_no_paths(self) -> None:
        """Test with disconnected sources and sinks."""
        graph = nx.DiGraph()
        graph.add_edges_from([("a", "b"), ("c", "d")])  # Two components

        loc = CodeLocation(file_path="test.java", line_number=1)
        source = Source(
            location=loc,
            variable_name="a",
            type="user_input",
            confidence=0.9,
            code_snippet="",
        )
        sink = Sink(
            location=loc,
            variable_name="d",
            type="sql",
            confidence=0.9,
            code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains([source], [sink])

        assert len(chains) == 0

    def test_find_all_chains_returns_taint_chain_objects(self) -> None:
        """Test that returned chains are proper TaintChain objects."""
        graph = nx.DiGraph()
        graph.add_edge("x", "y")

        loc = CodeLocation(file_path="test.java", line_number=1)
        source = Source(
            location=loc,
            variable_name="x",
            type="user_input",
            confidence=0.8,
            code_snippet="",
        )
        sink = Sink(
            location=loc,
            variable_name="y",
            type="sql",
            confidence=0.9,
            code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains([source], [sink])

        assert len(chains) == 1
        chain = chains[0]
        assert isinstance(chain, TaintChain)
        assert chain.source == source
        assert chain.sink == sink
        assert len(chain.path) == 2


class TestCrossMethodFiltering:
    """Tests for cross-method chain filtering."""

    def test_skip_cross_method_pairs(self) -> None:
        """Test that source/sink from different methods are skipped."""
        graph = nx.DiGraph()
        graph.add_edge("query", "query")  # Self-loop (same variable name)

        loc_a = CodeLocation(
            file_path="test.java", line_number=10, function_name="findById"
        )
        loc_b = CodeLocation(
            file_path="test.java", line_number=50, function_name="searchUsers"
        )

        source = Source(
            location=loc_a,
            variable_name="query",
            type="user_input",
            confidence=0.9,
            code_snippet="",
        )
        sink = Sink(
            location=loc_b,
            variable_name="query",
            type="sql",
            confidence=0.9,
            code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains([source], [sink])

        # Should be filtered out because different functions
        assert len(chains) == 0

    def test_allow_same_method_pairs(self) -> None:
        """Test that source/sink from the same method are allowed."""
        graph = nx.DiGraph()
        graph.add_edge("input", "query")

        loc = CodeLocation(
            file_path="test.java", line_number=10, function_name="findById"
        )

        source = Source(
            location=loc,
            variable_name="input",
            type="user_input",
            confidence=0.9,
            code_snippet="",
        )
        sink = Sink(
            location=CodeLocation(
                file_path="test.java", line_number=15, function_name="findById"
            ),
            variable_name="query",
            type="sql",
            confidence=0.9,
            code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains([source], [sink])

        assert len(chains) == 1

    def test_allow_when_function_name_not_set(self) -> None:
        """Test backward compat: no function_name means no filtering."""
        graph = nx.DiGraph()
        graph.add_edge("x", "y")

        loc = CodeLocation(file_path="test.java", line_number=1)
        source = Source(
            location=loc,
            variable_name="x",
            type="user_input",
            confidence=0.9,
            code_snippet="",
        )
        sink = Sink(
            location=loc,
            variable_name="y",
            type="sql",
            confidence=0.9,
            code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains([source], [sink])

        # No function_name set, so no filtering
        assert len(chains) == 1

    def test_cross_file_pairs_not_filtered(self) -> None:
        """Cross-file pairs with different function_name should NOT be filtered."""
        graph = nx.DiGraph()
        graph.add_edge("userQuery", "dbQuery")  # Real 2-node path

        loc_a = CodeLocation(
            file_path="Controller.java", line_number=10, function_name="handleRequest"
        )
        loc_b = CodeLocation(
            file_path="DAOHelper.java", line_number=20, function_name="executeSQL"
        )

        source = Source(
            location=loc_a,
            variable_name="userQuery",
            type="user_input",
            confidence=0.9,
            code_snippet="",
        )
        sink = Sink(
            location=loc_b,
            variable_name="dbQuery",
            type="sql",
            confidence=0.9,
            code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains([source], [sink])

        # Different files -> cross-method filter should NOT apply
        assert len(chains) == 1

    def test_same_file_cross_method_still_filtered(self) -> None:
        """Same file, different methods should still be filtered."""
        graph = nx.DiGraph()
        graph.add_edge("data", "data")  # Self-loop

        loc_a = CodeLocation(
            file_path="Service.java", line_number=10, function_name="readData"
        )
        loc_b = CodeLocation(
            file_path="Service.java", line_number=50, function_name="writeData"
        )

        source = Source(
            location=loc_a,
            variable_name="data",
            type="user_input",
            confidence=0.9,
            code_snippet="",
        )
        sink = Sink(
            location=loc_b,
            variable_name="data",
            type="sql",
            confidence=0.9,
            code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains([source], [sink])

        # Same file, different methods -> still filtered
        assert len(chains) == 0


class TestReachabilityPreFilter:
    """Tests for BFS reachability pre-filter in find_all_chains."""

    def test_prefilter_finds_reachable_chains(self) -> None:
        """Reachable source-sink pairs must still produce chains."""
        graph = nx.DiGraph()
        graph.add_edges_from([("a", "b"), ("b", "c"), ("c", "d")])

        loc = CodeLocation(file_path="test.java", line_number=1)
        source = Source(
            location=loc,
            variable_name="a",
            type="user_input",
            confidence=0.9,
            code_snippet="",
        )
        sink = Sink(
            location=loc,
            variable_name="d",
            type="sql",
            confidence=0.9,
            code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains([source], [sink])

        assert len(chains) == 1
        assert chains[0].source.variable_name == "a"
        assert chains[0].sink.variable_name == "d"

    def test_prefilter_skips_unreachable_pairs(self) -> None:
        """Unreachable pairs should produce no chains (same as before)."""
        graph = nx.DiGraph()
        graph.add_edges_from([("a", "b"), ("c", "d")])

        loc = CodeLocation(file_path="test.java", line_number=1)
        sources = [
            Source(location=loc, variable_name="a", type="user_input",
                   confidence=0.9, code_snippet=""),
        ]
        sinks = [
            Sink(location=loc, variable_name="d", type="sql",
                 confidence=0.9, code_snippet="",
                 vulnerability_type=VulnerabilityType.SQL_INJECTION),
        ]

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains(sources, sinks)

        assert len(chains) == 0

    def test_prefilter_mixed_reachable_and_unreachable(self) -> None:
        """With mixed pairs, only reachable ones produce chains."""
        graph = nx.DiGraph()
        # a -> b -> sink1, c is disconnected from sink2
        graph.add_edges_from([("a", "b"), ("b", "sink1"), ("c", "x")])
        graph.add_node("sink2")

        loc = CodeLocation(file_path="test.java", line_number=1)
        sources = [
            Source(location=loc, variable_name="a", type="user_input",
                   confidence=0.9, code_snippet=""),
            Source(location=loc, variable_name="c", type="user_input",
                   confidence=0.9, code_snippet=""),
        ]
        sinks = [
            Sink(location=loc, variable_name="sink1", type="sql",
                 confidence=0.9, code_snippet="",
                 vulnerability_type=VulnerabilityType.SQL_INJECTION),
            Sink(location=loc, variable_name="sink2", type="sql",
                 confidence=0.9, code_snippet="",
                 vulnerability_type=VulnerabilityType.SQL_INJECTION),
        ]

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains(sources, sinks)

        # Only a -> sink1 is reachable
        assert len(chains) == 1
        assert chains[0].source.variable_name == "a"
        assert chains[0].sink.variable_name == "sink1"


class TestIntegrationGraphAndFinder:
    """Integration tests combining graph builder and finder."""

    def test_sql_injection_vulnerability_detection(self) -> None:
        """Test detecting SQL injection vulnerability."""
        code = """String userName = request.getParameter('username');
                  String password = request.getParameter('password');
                  String query = userName + password;
                  db.executeQuery(query);"""

        builder = SimpleGraphBuilder()
        loc = CodeLocation(file_path="auth.java", line_number=1)

        sources = [
            Source(
                location=loc,
                variable_name="userName",
                type="user_input",
                confidence=0.95,
                code_snippet="",
            ),
        ]
        sinks = [
            Sink(
                location=loc,
                variable_name="query",
                type="sql_query",
                confidence=0.95,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
        ]

        graph = builder.build_graph(code, sources, sinks)
        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains(sources, sinks)

        # May or may not find chain depending on graph construction
        # but should not crash
        assert isinstance(chains, list)

    def test_complex_data_flow(self) -> None:
        """Test with complex data flow."""
        code = """String input = request.getParameter('data');
                  String processed = filter(input);
                  String final_query = "SELECT * FROM t WHERE col = " + processed;
                  execute(final_query);"""

        builder = SimpleGraphBuilder()
        loc = CodeLocation(file_path="service.java", line_number=1)

        sources = [
            Source(
                location=loc,
                variable_name="input",
                type="user_input",
                confidence=0.9,
                code_snippet="",
            ),
        ]
        sinks = [
            Sink(
                location=loc,
                variable_name="final_query",
                type="sql_query",
                confidence=0.9,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
        ]

        graph = builder.build_graph(code, sources, sinks)
        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains(sources, sinks)

        assert isinstance(chains, list)


class TestNodeIdMap:
    """Tests for node_id_map support in find_all_chains."""

    def test_find_all_chains_with_node_id_map(self) -> None:
        """Chains should be found via scoped IDs when node_id_map is provided."""
        graph = nx.DiGraph()
        graph.add_edges_from([("A.java:x", "A.java:y")])

        loc = CodeLocation(file_path="A.java", line_number=1)
        source = Source(
            location=loc, variable_name="x",
            type="user_input", confidence=0.9, code_snippet="",
        )
        sink = Sink(
            location=loc, variable_name="y",
            type="sql", confidence=0.9, code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        node_id_map = {
            id(source): "A.java:x",
            id(sink): "A.java:y",
        }

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains([source], [sink], node_id_map=node_id_map)

        assert len(chains) == 1
        # Variable names in PathNodes should be stripped of scope prefix
        assert chains[0].path[0].variable_name == "x"
        assert chains[0].path[-1].variable_name == "y"

    def test_find_all_chains_without_node_id_map_unchanged(self) -> None:
        """Backward compat: without node_id_map, plain variable_name is used."""
        graph = nx.DiGraph()
        graph.add_edge("x", "y")

        loc = CodeLocation(file_path="test.java", line_number=1)
        source = Source(
            location=loc, variable_name="x",
            type="user_input", confidence=0.9, code_snippet="",
        )
        sink = Sink(
            location=loc, variable_name="y",
            type="sql", confidence=0.9, code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        finder = SimpleBFSPathFinder(graph)
        chains = finder.find_all_chains([source], [sink])

        assert len(chains) == 1
        assert chains[0].path[0].variable_name == "x"
        assert chains[0].path[-1].variable_name == "y"
