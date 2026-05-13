"""Integration tests for symbolic execution."""

import pytest

from src.stage3_verification.symbolic_executor import (
    SymbolicExecutor,
    SymbolicBackend,
    SymbolicVariable,
    PathConstraints,
    Z3_AVAILABLE,
    JPYPE_AVAILABLE,
)
from src.core.models import (
    TaintChain,
    Source,
    Sink,
    PathNode,
    CodeLocation,
    VerificationStatus,
    VulnerabilityType,
)


def _make_path_nodes(*names):
    """Helper to create PathNode list from variable names."""
    nodes = []
    for i, name in enumerate(names):
        if i == 0:
            node_type = "source"
        elif i == len(names) - 1:
            node_type = "sink"
        else:
            node_type = "intermediate"
        nodes.append(
            PathNode(
                location=CodeLocation(file_path="test.java", line_number=i + 1),
                variable_name=name,
                node_type=node_type,
                code_snippet="",
            )
        )
    return nodes


class TestSymbolicVariable:
    """Tests for SymbolicVariable class."""

    def test_symbolic_variable_creation(self) -> None:
        """Test creating symbolic variable."""
        var = SymbolicVariable("input", "String")

        assert var.name == "input"
        assert var.var_type == "String"
        assert len(var.constraints) == 0

    def test_symbolic_variable_int_type(self) -> None:
        """Test creating integer symbolic variable."""
        var = SymbolicVariable("count", "int")

        assert var.name == "count"
        assert var.var_type == "int"

    def test_symbolic_variable_add_constraint(self) -> None:
        """Test adding constraints to symbolic variable."""
        var = SymbolicVariable("x", "int")
        var.add_constraint("x > 0")

        assert len(var.constraints) == 1

    def test_symbolic_variable_repr(self) -> None:
        """Test symbolic variable string representation."""
        var = SymbolicVariable("test", "String")
        assert "SymVar" in repr(var)
        assert "test" in repr(var)


class TestPathConstraints:
    """Tests for PathConstraints class."""

    def test_path_constraints_creation(self) -> None:
        """Test creating path constraints."""
        constraints = PathConstraints()

        assert len(constraints.constraints) == 0
        assert len(constraints.variables) == 0

    def test_add_variable(self) -> None:
        """Test adding symbolic variables."""
        constraints = PathConstraints()

        var = constraints.add_variable("input", "String")

        assert "input" in constraints.variables
        assert var.name == "input"
        assert var.var_type == "String"

    def test_add_duplicate_variable(self) -> None:
        """Test that adding duplicate variable returns existing one."""
        constraints = PathConstraints()

        var1 = constraints.add_variable("x", "int")
        var2 = constraints.add_variable("x", "int")

        assert var1 is var2
        assert len(constraints.variables) == 1

    def test_add_constraint(self) -> None:
        """Test adding path constraints."""
        constraints = PathConstraints()
        constraints.add_constraint("x > 0")

        assert len(constraints.constraints) == 1

    def test_path_constraints_repr(self) -> None:
        """Test path constraints string representation."""
        constraints = PathConstraints()
        constraints.add_variable("x", "int")
        constraints.add_constraint("x > 0")

        repr_str = repr(constraints)
        assert "PathConstraints" in repr_str
        assert "1 vars" in repr_str
        assert "1 constraints" in repr_str


class TestSymbolicExecutor:
    """Tests for SymbolicExecutor class."""

    def test_symbolic_executor_initialization_default(self) -> None:
        """Test symbolic executor initialization with auto-detection."""
        executor = SymbolicExecutor()

        assert executor.timeout == 30

        # Should auto-detect backend
        if Z3_AVAILABLE:
            assert executor.backend == SymbolicBackend.Z3
        elif JPYPE_AVAILABLE:
            assert executor.backend == SymbolicBackend.JPF
        else:
            assert executor.backend == SymbolicBackend.NONE

    def test_symbolic_executor_initialization_explicit_backend(self) -> None:
        """Test symbolic executor with explicit backend."""
        executor = SymbolicExecutor(backend=SymbolicBackend.NONE)

        assert executor.backend == SymbolicBackend.NONE

    def test_symbolic_executor_timeout(self) -> None:
        """Test symbolic executor with custom timeout."""
        executor = SymbolicExecutor(timeout=60)

        assert executor.timeout == 60

    @pytest.mark.skipif(not Z3_AVAILABLE, reason="Z3 not available")
    def test_execute_with_z3_simple_chain(self) -> None:
        """Test symbolic execution with Z3 on simple chain."""
        executor = SymbolicExecutor(backend=SymbolicBackend.Z3)

        code = """
        String input = request.getParameter("q");
        String query = "SELECT * FROM users WHERE id=" + input;
        db.execute(query);
        """

        path_nodes = _make_path_nodes("input", "query")

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
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.9,
            code_snippet="",
        )

        chain = TaintChain(
            id="test-chain",
            source=source,
            sink=sink,
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.9,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        status = executor.execute_path(chain, code)

        # Should return VERIFIED, FALSE, or UNVERIFIABLE (not error)
        assert status in (
            VerificationStatus.VERIFIED,
            VerificationStatus.FALSE,
            VerificationStatus.UNVERIFIABLE,
        )

    @pytest.mark.skipif(not Z3_AVAILABLE, reason="Z3 not available")
    def test_execute_with_z3_assignment(self) -> None:
        """Test Z3 symbolic execution with simple assignment."""
        executor = SymbolicExecutor(backend=SymbolicBackend.Z3)

        code = """
        String x = input;
        String y = x;
        """

        path_nodes = _make_path_nodes("input", "x", "y")

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="input",
            type="Input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=2),
            variable_name="y",
            type="Output",
            vulnerability_type=VulnerabilityType.XSS,
            confidence=0.9,
            code_snippet="",
        )

        chain = TaintChain(
            id="assign-chain",
            source=source,
            sink=sink,
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.9,
            vulnerability_type=VulnerabilityType.XSS,
        )

        status = executor.execute_path(chain, code)

        # Should be able to verify this simple path
        assert status in (
            VerificationStatus.VERIFIED,
            VerificationStatus.UNVERIFIABLE,
        )

    def test_execute_without_backend(self) -> None:
        """Test symbolic execution without backend."""
        executor = SymbolicExecutor(backend=SymbolicBackend.NONE)

        code = """
        String input = getInput();
        String output = input;
        """

        path_nodes = _make_path_nodes("input", "output")

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="input",
            type="Input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=2),
            variable_name="output",
            type="Output",
            vulnerability_type=VulnerabilityType.XSS,
            confidence=0.9,
            code_snippet="",
        )

        chain = TaintChain(
            id="no-backend",
            source=source,
            sink=sink,
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.9,
            vulnerability_type=VulnerabilityType.XSS,
        )

        status = executor.execute_path(chain, code)

        # Without backend, should return UNVERIFIABLE
        assert status == VerificationStatus.UNVERIFIABLE

    def test_get_backend_info(self) -> None:
        """Test getting backend information."""
        executor = SymbolicExecutor()
        info = executor.get_backend_info()

        assert "backend" in info
        assert "z3_available" in info
        assert "jpype_available" in info
        assert "timeout" in info
        assert info["z3_available"] == Z3_AVAILABLE
        assert info["jpype_available"] == JPYPE_AVAILABLE

    @pytest.mark.skipif(not Z3_AVAILABLE, reason="Z3 not available")
    def test_build_path_constraints(self) -> None:
        """Test building path constraints from chain."""
        executor = SymbolicExecutor(backend=SymbolicBackend.Z3)

        code = """
        String input = getInput();
        String output = input;
        """

        path_nodes = _make_path_nodes("input", "output")

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="input",
            type="Input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=2),
            variable_name="output",
            type="Output",
            vulnerability_type=VulnerabilityType.XSS,
            confidence=0.9,
            code_snippet="",
        )

        chain = TaintChain(
            id="test",
            source=source,
            sink=sink,
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.9,
            vulnerability_type=VulnerabilityType.XSS,
        )

        constraints = executor._build_path_constraints(chain, code)

        assert "input" in constraints.variables
        assert "output" in constraints.variables

    @pytest.mark.skipif(not Z3_AVAILABLE, reason="Z3 not available")
    def test_extract_constraint_from_simple_assignment(self) -> None:
        """Test extracting constraint from simple assignment."""
        executor = SymbolicExecutor(backend=SymbolicBackend.Z3)
        constraints = PathConstraints()

        stmt = "y = x;"
        constraint = executor._extract_constraint_from_statement(
            stmt, "x", "y", constraints
        )

        # Should create some constraint
        assert constraint is not None or "x" in constraints.variables

    @pytest.mark.skipif(not Z3_AVAILABLE, reason="Z3 not available")
    def test_extract_constraint_from_concatenation(self) -> None:
        """Test extracting constraint from string concatenation."""
        executor = SymbolicExecutor(backend=SymbolicBackend.Z3)
        constraints = PathConstraints()

        stmt = 'query = "SELECT * FROM users WHERE id=" + input;'
        constraint = executor._extract_constraint_from_statement(
            stmt, "input", "query", constraints
        )

        # Should handle concatenation
        assert "input" in constraints.variables
        assert "query" in constraints.variables


class TestSymbolicExecutorIntegration:
    """Integration tests for symbolic executor with real vulnerabilities."""

    @pytest.mark.skipif(not Z3_AVAILABLE, reason="Z3 not available")
    def test_sql_injection_verification(self) -> None:
        """Test symbolic execution for SQL injection."""
        executor = SymbolicExecutor(backend=SymbolicBackend.Z3)

        code = """
        public void doGet(HttpServletRequest request, HttpServletResponse response) {
            String id = request.getParameter("id");
            String query = "SELECT * FROM users WHERE id=" + id;
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
        }
        """

        path_nodes = _make_path_nodes("id", "query")

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=2),
            variable_name="id",
            type="User Input",
            confidence=0.95,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=5),
            variable_name="query",
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.95,
            code_snippet="",
        )

        chain = TaintChain(
            id="sqli",
            source=source,
            sink=sink,
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.95,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        status = executor.execute_path(chain, code)

        # Should be able to analyze this (may be VERIFIED or UNVERIFIABLE)
        assert status in (
            VerificationStatus.VERIFIED,
            VerificationStatus.FALSE,
            VerificationStatus.UNVERIFIABLE,
        )

    @pytest.mark.skipif(not Z3_AVAILABLE, reason="Z3 not available")
    def test_xss_verification(self) -> None:
        """Test symbolic execution for XSS."""
        executor = SymbolicExecutor(backend=SymbolicBackend.Z3)

        code = """
        String name = request.getParameter("name");
        String message = "Hello, " + name;
        response.getWriter().write(message);
        """

        path_nodes = _make_path_nodes("name", "message")

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="name",
            type="User Input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=3),
            variable_name="message",
            type="HTML Output",
            vulnerability_type=VulnerabilityType.XSS,
            confidence=0.9,
            code_snippet="",
        )

        chain = TaintChain(
            id="xss",
            source=source,
            sink=sink,
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.9,
            vulnerability_type=VulnerabilityType.XSS,
        )

        status = executor.execute_path(chain, code)

        # Should be able to analyze this
        assert status in (
            VerificationStatus.VERIFIED,
            VerificationStatus.FALSE,
            VerificationStatus.UNVERIFIABLE,
        )

    def test_jpf_backend_placeholder(self) -> None:
        """Test that JPF backend returns UNVERIFIABLE (not implemented yet)."""
        executor = SymbolicExecutor(backend=SymbolicBackend.JPF)

        code = """
        String x = input;
        """

        path_nodes = _make_path_nodes("input", "x")

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="input",
            type="Input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="x",
            type="Output",
            vulnerability_type=VulnerabilityType.XSS,
            confidence=0.9,
            code_snippet="",
        )

        chain = TaintChain(
            id="jpf-test",
            source=source,
            sink=sink,
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.9,
            vulnerability_type=VulnerabilityType.XSS,
        )

        status = executor.execute_path(chain, code)

        # JPF not implemented, should return UNVERIFIABLE
        assert status == VerificationStatus.UNVERIFIABLE
