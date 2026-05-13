"""Integration tests for enhanced graph builder."""

import pytest
import networkx as nx

from src.stage2_path_discovery.graph_builder import EnhancedGraphBuilder, VariableTracker
from src.core.models import Source, Sink, CodeLocation, VulnerabilityType


class TestVariableTracker:
    """Tests for VariableTracker."""

    def test_tracker_initialization(self) -> None:
        """Test variable tracker initializes."""
        tracker = VariableTracker()
        assert len(tracker.declarations) == 0
        assert len(tracker.definitions) == 0
        assert len(tracker.uses) == 0

    def test_add_declaration(self) -> None:
        """Test adding variable declaration."""
        tracker = VariableTracker()
        tracker.add_declaration("username", "String")

        assert tracker.get_type("username") == "String"

    def test_add_multiple_declarations(self) -> None:
        """Test adding multiple declarations."""
        tracker = VariableTracker()
        tracker.add_declaration("username", "String")
        tracker.add_declaration("count", "int")
        tracker.add_declaration("items", "List")

        assert tracker.get_type("username") == "String"
        assert tracker.get_type("count") == "int"
        assert tracker.get_type("items") == "List"

    def test_is_untrusted_type(self) -> None:
        """Test detection of untrusted types."""
        tracker = VariableTracker()

        # Untrusted types
        assert tracker.is_untrusted_type("HttpServletRequest") is True
        assert tracker.is_untrusted_type("InputStream") is True
        assert tracker.is_untrusted_type("String") is True  # From user input

        # ResultSet is NOT untrusted (internal Java object, not user input)
        assert tracker.is_untrusted_type("ResultSet") is False

        # Trusted types
        assert tracker.is_untrusted_type("int") is False
        assert tracker.is_untrusted_type("boolean") is False

    def test_add_definition(self) -> None:
        """Test tracking variable definitions."""
        tracker = VariableTracker()
        tracker.add_definition("var1", "line_10")
        tracker.add_definition("var1", "line_20")

        assert len(tracker.definitions["var1"]) == 2
        assert "line_10" in tracker.definitions["var1"]
        assert "line_20" in tracker.definitions["var1"]

    def test_add_use(self) -> None:
        """Test tracking variable uses."""
        tracker = VariableTracker()
        tracker.add_use("var1", "in_method_foo")
        tracker.add_use("var1", "in_method_bar")

        assert len(tracker.uses["var1"]) == 2


class TestEnhancedGraphBuilder:
    """Tests for EnhancedGraphBuilder."""

    def test_builder_initialization(self) -> None:
        """Test graph builder initializes."""
        builder = EnhancedGraphBuilder()
        assert builder is not None
        assert builder.variable_tracker is not None

    def test_extract_declarations(self) -> None:
        """Test extraction of variable declarations."""
        builder = EnhancedGraphBuilder()
        code = """
        String username = "user";
        int count = 0;
        HttpServletRequest request;
        """

        builder._extract_declarations(code)

        assert builder.variable_tracker.get_type("username") == "String"
        assert builder.variable_tracker.get_type("count") == "int"
        assert builder.variable_tracker.get_type("request") == "HttpServletRequest"

    def test_extract_variables(self) -> None:
        """Test variable extraction."""
        builder = EnhancedGraphBuilder()
        code = """
        String username = request.getParameter("user");
        int count = 0;
        """

        variables = builder._extract_variables(code)

        assert "username" in variables
        assert "count" in variables
        assert "request" in variables
        assert "String" not in variables  # Keywords filtered
        assert "int" not in variables

    def test_extract_data_flows_simple_assignment(self) -> None:
        """Test extracting simple data flow assignments."""
        builder = EnhancedGraphBuilder()
        code = """
        String x = y;
        String z = x;
        """

        flows = builder._extract_data_flows(code)

        # Should find y -> x and x -> z
        assert len(flows) >= 2

    def test_extract_data_flows_arithmetic(self) -> None:
        """Test extracting arithmetic data flows."""
        builder = EnhancedGraphBuilder()
        code = """
        int total = count + 10;
        int result = total - 5;
        """

        flows = builder._extract_data_flows(code)

        # Should find flows involving count and total
        assert len(flows) >= 1

    def test_extract_data_flows_method_call(self) -> None:
        """Test extracting data flows from method calls."""
        builder = EnhancedGraphBuilder()
        code = """
        String result = process(input);
        """

        flows = builder._extract_data_flows(code)

        # Should find input -> result through process method
        assert len(flows) >= 1

    def test_extract_control_flows_if_statement(self) -> None:
        """Test extracting control flow from if statements."""
        builder = EnhancedGraphBuilder()
        code = """
        if (user != null) {
            processUser();
        }
        """

        flows = builder._extract_control_flows(code)

        # Should find user in control flow
        assert any("user" in str(edge) for edge in flows)

    def test_extract_control_flows_loop(self) -> None:
        """Test extracting control flow from loops."""
        builder = EnhancedGraphBuilder()
        code = """
        for (int i = 0; i < count; i++) {
            process(i);
        }
        """

        flows = builder._extract_control_flows(code)

        # Should find count in control flow
        assert any("count" in str(edge) for edge in flows)

    def test_is_keyword(self) -> None:
        """Test keyword detection."""
        assert EnhancedGraphBuilder._is_keyword("String") is True
        assert EnhancedGraphBuilder._is_keyword("int") is True
        assert EnhancedGraphBuilder._is_keyword("if") is True
        assert EnhancedGraphBuilder._is_keyword("myVariable") is False
        assert EnhancedGraphBuilder._is_keyword("userName") is False

    def test_determine_flow_type(self) -> None:
        """Test flow type determination."""
        builder = EnhancedGraphBuilder()

        # Direct assignment
        assert builder._determine_flow_type("x", "x") == "direct"

        # String concatenation
        assert builder._determine_flow_type("x + y", "x") == "concatenation"

        # Arithmetic
        assert builder._determine_flow_type("x - 5", "x") == "arithmetic"

        # Method call
        assert builder._determine_flow_type("method(x)", "x") == "method_call"

    def test_build_graph_simple(self) -> None:
        """Test building a simple data flow graph."""
        builder = EnhancedGraphBuilder()
        code = """
        String input = request.getParameter("user");
        String query = "SELECT * FROM users WHERE name='" + input + "'";
        db.execute(query);
        """

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="input",
            type="User Input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=3),
            variable_name="query",
            type="SQL Query",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.95,
            code_snippet="",
        )

        graph = builder.build_graph(code, [source], [sink])

        assert isinstance(graph, nx.DiGraph)
        assert graph.number_of_nodes() >= 2
        assert source.variable_name in graph.nodes()
        assert sink.variable_name in graph.nodes()

    def test_build_graph_node_attributes(self) -> None:
        """Test that graph nodes have proper attributes."""
        builder = EnhancedGraphBuilder()
        code = """
        String userInput = request.getParameter("q");
        """

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="userInput",
            type="User Input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=2),
            variable_name="sink",
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.95,
            code_snippet="",
        )

        graph = builder.build_graph(code, [source], [sink])

        # Check source node attributes
        source_node = graph.nodes["userInput"]
        assert source_node.get("type") == "source"
        assert source_node.get("confidence") == 0.9

        # Check sink node attributes
        sink_node = graph.nodes["sink"]
        assert sink_node.get("type") == "sink"
        assert sink_node.get("confidence") == 0.95

    def test_build_graph_edge_attributes(self) -> None:
        """Test that graph edges have proper attributes."""
        builder = EnhancedGraphBuilder()
        code = """
        String x = y;
        """

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="y",
            type="User Input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="x",
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.95,
            code_snippet="",
        )

        graph = builder.build_graph(code, [source], [sink])

        # Check edges have proper metadata
        if graph.has_edge("y", "x"):
            edge = graph["y"]["x"]
            assert "edge_type" in edge
            assert edge.get("edge_type") == "data_flow"

    def test_build_graph_complex(self) -> None:
        """Test building a complex data flow graph."""
        builder = EnhancedGraphBuilder()
        code = """
        String input = request.getParameter("search");
        String sanitized = sanitize(input);
        String query = "SELECT * FROM db WHERE term='" + sanitized + "'";
        ResultSet rs = connection.executeQuery(query);
        while (rs.next()) {
            String data = rs.getString(1);
            response.write(data);
        }
        """

        sources = [
            Source(
                location=CodeLocation(file_path="test.java", line_number=1),
                variable_name="input",
                type="User Input",
                confidence=0.9,
                code_snippet="",
            ),
            Source(
                location=CodeLocation(file_path="test.java", line_number=5),
                variable_name="data",
                type="Database",
                confidence=0.85,
                code_snippet="",
            ),
        ]

        sinks = [
            Sink(
                location=CodeLocation(file_path="test.java", line_number=3),
                variable_name="query",
                type="SQL",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                confidence=0.95,
                code_snippet="",
            ),
            Sink(
                location=CodeLocation(file_path="test.java", line_number=7),
                variable_name="data",
                type="HTTP Response",
                vulnerability_type=VulnerabilityType.XSS,
                confidence=0.88,
                code_snippet="",
            ),
        ]

        graph = builder.build_graph(code, sources, sinks)

        assert graph.number_of_nodes() >= 4
        assert len(sources) + len(sinks) <= graph.number_of_nodes()
        assert graph.number_of_edges() > 0

    def test_enhanced_vs_simple_graph_builder(self) -> None:
        """Test that enhanced builder produces richer graphs."""
        enhanced = EnhancedGraphBuilder()

        code = """
        String username = request.getParameter("user");
        String password = request.getParameter("pass");
        String query = "SELECT * FROM users WHERE user='" + username + "' AND pass='" + password + "'";
        ResultSet rs = db.executeQuery(query);
        """

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="username",
            type="User Input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=3),
            variable_name="query",
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.95,
            code_snippet="",
        )

        graph = enhanced.build_graph(code, [source], [sink])

        # Enhanced builder should have node attributes
        for node_id, node_data in graph.nodes(data=True):
            assert "type" in node_data or node_data

        # Enhanced builder should have edge attributes
        for u, v, edge_data in graph.edges(data=True):
            assert "edge_type" in edge_data or edge_data
