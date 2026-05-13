"""Tests for SymbolicExecutor."""

import pytest
from unittest.mock import patch, MagicMock

from src.core.models import (
    TaintChain, Source, Sink, PathNode, CodeLocation, VulnerabilityType, VerificationStatus,
)
from src.stage3_verification.symbolic_executor import (
    SymbolicExecutor, SymbolicBackend, SymbolicVariable, PathConstraints,
)


@pytest.fixture
def sample_chain():
    source = Source(
        location=CodeLocation(file_path="test.java", line_number=3),
        variable_name="userId",
        type="User Input",
        confidence=0.9,
        code_snippet='String userId = request.getParameter("id");',
    )
    sink = Sink(
        location=CodeLocation(file_path="test.java", line_number=5),
        variable_name="query",
        type="SQL",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        confidence=0.85,
        code_snippet='stmt.executeQuery(query);',
    )
    return TaintChain(
        id="sym-test-chain",
        source=source,
        sink=sink,
        path=[
            PathNode(location=CodeLocation(file_path="test.java", line_number=3), variable_name="userId", node_type="source", code_snippet='String userId = request.getParameter("id");'),
            PathNode(location=CodeLocation(file_path="test.java", line_number=5), variable_name="query", node_type="sink", code_snippet='stmt.executeQuery(query);'),
        ],
        length=2,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        confidence=0.875,
    )


SAMPLE_CODE = """
public class Test {
    public void process(String userId) {
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        stmt.executeQuery(query);
    }
}
"""

SAMPLE_CODE_CONDITIONAL = """
public class Test {
    public void process(String userId) {
        if (userId.length() > 0) {
            String query = userId;
            stmt.executeQuery(query);
        }
    }
}
"""


class TestSymbolicVariable:
    """Tests for SymbolicVariable."""

    def test_creation_string(self):
        var = SymbolicVariable("test", "String")
        assert var.name == "test"
        assert var.var_type == "String"
        assert var.constraints == []

    def test_creation_int(self):
        var = SymbolicVariable("count", "int")
        assert var.name == "count"
        assert var.var_type == "int"

    def test_creation_boolean(self):
        var = SymbolicVariable("flag", "boolean")
        assert var.name == "flag"
        assert var.var_type == "boolean"

    def test_add_constraint(self):
        var = SymbolicVariable("x", "int")
        var.add_constraint("x > 0")
        assert len(var.constraints) == 1

    def test_repr(self):
        var = SymbolicVariable("test", "String")
        repr_str = repr(var)
        assert "test" in repr_str
        assert "String" in repr_str
        assert "0 constraints" in repr_str


class TestPathConstraints:
    """Tests for PathConstraints."""

    def test_creation(self):
        pc = PathConstraints()
        assert pc.constraints == []
        assert pc.variables == {}

    def test_add_variable(self):
        pc = PathConstraints()
        var = pc.add_variable("x", "int")
        assert var.name == "x"
        assert "x" in pc.variables

    def test_add_variable_dedup(self):
        pc = PathConstraints()
        var1 = pc.add_variable("x", "int")
        var2 = pc.add_variable("x", "int")
        assert var1 is var2
        assert len(pc.variables) == 1

    def test_add_constraint(self):
        pc = PathConstraints()
        pc.add_constraint("some constraint")
        assert len(pc.constraints) == 1

    def test_repr(self):
        pc = PathConstraints()
        pc.add_variable("x")
        pc.add_constraint("c1")
        repr_str = repr(pc)
        assert "1 vars" in repr_str
        assert "1 constraints" in repr_str


class TestSymbolicExecutor:
    """Tests for SymbolicExecutor."""

    def test_init_auto_detect(self):
        executor = SymbolicExecutor()
        assert executor.backend in (SymbolicBackend.Z3, SymbolicBackend.JPF, SymbolicBackend.NONE)
        assert executor.timeout == 30

    def test_init_with_timeout(self):
        executor = SymbolicExecutor(timeout=60)
        assert executor.timeout == 60

    def test_init_explicit_backend(self):
        executor = SymbolicExecutor(backend=SymbolicBackend.NONE)
        assert executor.backend == SymbolicBackend.NONE

    def test_execute_path_no_backend(self, sample_chain):
        executor = SymbolicExecutor(backend=SymbolicBackend.NONE)
        result = executor.execute_path(sample_chain, SAMPLE_CODE)
        assert result == VerificationStatus.UNVERIFIABLE

    def test_execute_path_z3(self, sample_chain):
        try:
            import z3
            executor = SymbolicExecutor(backend=SymbolicBackend.Z3)
            result = executor.execute_path(sample_chain, SAMPLE_CODE)
            assert isinstance(result, VerificationStatus)
        except ImportError:
            pytest.skip("Z3 not available")

    def test_execute_path_jpf(self, sample_chain):
        executor = SymbolicExecutor(backend=SymbolicBackend.JPF)
        result = executor.execute_path(sample_chain, SAMPLE_CODE)
        # JPF not implemented, returns UNVERIFIABLE
        assert result == VerificationStatus.UNVERIFIABLE

    def test_get_backend_info(self):
        executor = SymbolicExecutor()
        info = executor.get_backend_info()
        assert "backend" in info
        assert "z3_available" in info
        assert "jpype_available" in info
        assert "timeout" in info

    def test_build_path_constraints(self, sample_chain):
        executor = SymbolicExecutor()
        constraints = executor._build_path_constraints(sample_chain, SAMPLE_CODE)
        assert isinstance(constraints, PathConstraints)
        assert "userId" in constraints.variables
        assert "query" in constraints.variables

    def test_find_statement_for_edge(self):
        executor = SymbolicExecutor()
        stmt = executor._find_statement_for_edge(SAMPLE_CODE, "userId", "query")
        assert stmt is not None
        assert "userId" in stmt
        assert "query" in stmt

    def test_find_statement_for_edge_not_found(self):
        executor = SymbolicExecutor()
        stmt = executor._find_statement_for_edge(SAMPLE_CODE, "abc", "xyz")
        assert stmt is None

    def test_extract_constraint_from_statement_assignment(self):
        try:
            import z3
        except ImportError:
            pytest.skip("Z3 not available")

        executor = SymbolicExecutor()
        pc = PathConstraints()
        pc.add_variable("x", "String")
        pc.add_variable("y", "String")

        constraint = executor._extract_constraint_from_statement(
            "y = x;", "x", "y", pc
        )
        assert constraint is not None

    def test_extract_constraint_from_statement_concat(self):
        try:
            import z3
        except ImportError:
            pytest.skip("Z3 not available")

        executor = SymbolicExecutor()
        pc = PathConstraints()
        pc.add_variable("input", "String")
        pc.add_variable("result", "String")

        constraint = executor._extract_constraint_from_statement(
            'result = "prefix" + input;', "input", "result", pc
        )
        assert constraint is not None

    def test_parse_condition_greater_than(self):
        try:
            import z3
        except ImportError:
            pytest.skip("Z3 not available")

        executor = SymbolicExecutor()
        pc = PathConstraints()
        constraint = executor._parse_condition("x > 0", pc)
        assert constraint is not None

    def test_parse_condition_less_than(self):
        try:
            import z3
        except ImportError:
            pytest.skip("Z3 not available")

        executor = SymbolicExecutor()
        pc = PathConstraints()
        constraint = executor._parse_condition("x < 10", pc)
        assert constraint is not None

    def test_parse_condition_equals(self):
        try:
            import z3
        except ImportError:
            pytest.skip("Z3 not available")

        executor = SymbolicExecutor()
        pc = PathConstraints()
        constraint = executor._parse_condition('name == "admin"', pc)
        assert constraint is not None

    def test_parse_condition_complex(self):
        executor = SymbolicExecutor()
        pc = PathConstraints()
        # Complex condition that cannot be parsed
        constraint = executor._parse_condition("a && b || c", pc)
        assert constraint is None

    def test_z3_execution_with_chain(self, sample_chain):
        try:
            import z3
        except ImportError:
            pytest.skip("Z3 not available")

        executor = SymbolicExecutor(backend=SymbolicBackend.Z3, timeout=5)
        result = executor._execute_with_z3(sample_chain, SAMPLE_CODE)
        assert isinstance(result, VerificationStatus)
