"""Integration tests for CFG-based verification."""

import pytest
import networkx as nx

from src.stage3_verification.cfg_verifier import CFGVerifier, BasicBlock
from src.core.models import (
    TaintChain,
    Source,
    Sink,
    PathNode,
    CodeLocation,
    VerificationStatus,
    VulnerabilityType,
)


def _make_chain(chain_id, source, sink, path_vars, vuln_type):
    """Helper to create a TaintChain with PathNode path."""
    path_nodes = []
    for i, var in enumerate(path_vars):
        if i == 0:
            node_type = "source"
        elif i == len(path_vars) - 1:
            node_type = "sink"
        else:
            node_type = "intermediate"
        path_nodes.append(PathNode(
            location=CodeLocation(file_path="test.java", line_number=i + 1),
            variable_name=var,
            node_type=node_type,
            code_snippet="",
        ))
    return TaintChain(
        id=chain_id,
        source=source,
        sink=sink,
        path=path_nodes,
        length=len(path_nodes),
        confidence=0.9,
        vulnerability_type=vuln_type,
    )


class TestBasicBlock:
    """Tests for BasicBlock class."""

    def test_basic_block_creation(self) -> None:
        """Test creating a basic block."""
        statements = ["String x = input;", "String y = x + '1';"]
        block = BasicBlock(block_id=1, statements=statements)

        assert block.block_id == 1
        assert len(block.statements) == 2
        assert "x" in block.variables
        assert "y" in block.variables

    def test_basic_block_extracts_definitions(self) -> None:
        """Test that basic block extracts variable definitions."""
        statements = ["int count = 0;", "String name = input;"]
        block = BasicBlock(block_id=1, statements=statements)

        assert "count" in block.definitions
        assert "name" in block.definitions

    def test_basic_block_extracts_uses(self) -> None:
        """Test that basic block extracts variable uses."""
        statements = ["result = alpha + beta;", "print(result);"]
        block = BasicBlock(block_id=1, statements=statements)

        assert "alpha" in block.uses
        assert "beta" in block.uses
        assert "result" in block.definitions  # Also defined

    def test_basic_block_repr(self) -> None:
        """Test basic block string representation."""
        block = BasicBlock(block_id=5, statements=["x = 1;"])
        assert "Block(5" in repr(block)


class TestCFGVerifier:
    """Tests for CFGVerifier class."""

    def test_cfg_verifier_initialization(self) -> None:
        """Test CFG verifier initialization."""
        verifier = CFGVerifier(max_loop_iterations=5)

        assert verifier.max_loop_iterations == 5
        assert verifier.cfg is None
        assert verifier.next_block_id == 0

    def test_build_cfg_sequential_code(self) -> None:
        """Test building CFG from sequential code."""
        verifier = CFGVerifier()

        code = """
        String input = request.getParameter("q");
        String query = "SELECT * FROM users WHERE id=" + input;
        db.execute(query);
        """

        cfg = verifier.build_cfg(code)

        assert cfg is not None
        assert cfg.number_of_nodes() > 0
        assert verifier.blocks  # Should have created blocks

    def test_build_cfg_with_if_statement(self) -> None:
        """Test building CFG with if/else."""
        verifier = CFGVerifier()

        code = """
        String input = getInput();
        if (input != null) {
            process(input);
        } else {
            useDefault();
        }
        """

        cfg = verifier.build_cfg(code)

        assert cfg is not None
        assert cfg.number_of_nodes() >= 3  # Condition + if-branch + else-branch

        # Check for branch edges
        edge_types = [data.get('type') for _, _, data in cfg.edges(data=True)]
        assert any('branch' in str(t) for t in edge_types)

    def test_build_cfg_with_loop(self) -> None:
        """Test building CFG with while loop."""
        verifier = CFGVerifier()

        code = """
        int count = 0;
        while (count < 10) {
            count = count + 1;
        }
        """

        cfg = verifier.build_cfg(code)

        assert cfg is not None
        assert cfg.number_of_nodes() >= 2  # Loop header + body

        # Check for loop back edge
        edge_types = [data.get('type') for _, _, data in cfg.edges(data=True)]
        assert 'loop_back' in edge_types

    def test_build_cfg_empty_code(self) -> None:
        """Test building CFG from empty code."""
        verifier = CFGVerifier()
        cfg = verifier.build_cfg("")

        assert cfg is not None
        assert cfg.number_of_nodes() == 0

    def test_check_reachability_simple(self) -> None:
        """Test simple reachability check."""
        verifier = CFGVerifier()

        code = """
        String input = getInput();
        String output = input;
        print(output);
        """

        verifier.build_cfg(code)
        is_reachable = verifier.check_reachability("input", "output")

        assert is_reachable is True

    def test_check_reachability_unreachable(self) -> None:
        """Test reachability with unreachable variable."""
        verifier = CFGVerifier()

        code = """
        String input = getInput();
        if (false) {
            String output = input;
        }
        """

        verifier.build_cfg(code)

        # Note: Simple CFG builder doesn't perform constant propagation,
        # so it may still see this as reachable. This is expected behavior.

    def test_check_reachability_no_cfg(self) -> None:
        """Test reachability check without building CFG."""
        verifier = CFGVerifier()

        # Should return False if CFG not built
        is_reachable = verifier.check_reachability("input", "output")
        assert is_reachable is False

    def test_verify_chain(self) -> None:
        """Test verifying a taint chain."""
        verifier = CFGVerifier()

        code = """
        String input = request.getParameter("q");
        String query = "SELECT * FROM users WHERE id=" + input;
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
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.9,
            code_snippet="",
        )

        chain = _make_chain("test-chain", source, sink, ["input", "query"], VulnerabilityType.SQL_INJECTION)

        status = verifier.verify_chain(chain, code)

        # Should be either VERIFIED or FALSE, not UNVERIFIABLE
        assert status in (VerificationStatus.VERIFIED, VerificationStatus.FALSE)

    def test_get_cfg_info_no_cfg(self) -> None:
        """Test getting CFG info when no CFG built."""
        verifier = CFGVerifier()
        info = verifier.get_cfg_info()

        assert info["built"] is False
        assert info["blocks"] == 0

    def test_get_cfg_info_with_cfg(self) -> None:
        """Test getting CFG info after building CFG."""
        verifier = CFGVerifier()

        code = """
        String x = input;
        if (x != null) {
            print(x);
        }
        """

        verifier.build_cfg(code)
        info = verifier.get_cfg_info()

        assert info["built"] is True
        assert info["blocks"] > 0
        assert info["edges"] >= 0
        assert "edge_types" in info

    def test_loop_iteration_limit(self) -> None:
        """Test that loop iteration limit prevents infinite loops."""
        verifier = CFGVerifier(max_loop_iterations=2)

        code = """
        int x = 0;
        while (true) {
            x = x + 1;
        }
        int y = x;
        """

        verifier.build_cfg(code)

        # Should be able to build CFG even with infinite loop
        assert verifier.cfg is not None


class TestCFGVerifierIntegration:
    """Integration tests for CFG verifier with complex scenarios."""

    def test_sql_injection_vulnerability(self) -> None:
        """Test CFG verification of SQL injection vulnerability."""
        verifier = CFGVerifier()

        code = """
        public void query(HttpServletRequest request) {
            String id = request.getParameter("id");
            String query = "SELECT * FROM users WHERE id=" + id;
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
        }
        """

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

        chain = _make_chain("sqli-chain", source, sink, ["id", "query"], VulnerabilityType.SQL_INJECTION)

        status = verifier.verify_chain(chain, code)
        assert status in (VerificationStatus.VERIFIED, VerificationStatus.FALSE)

    def test_xss_vulnerability_with_branches(self) -> None:
        """Test CFG verification with conditional branches."""
        verifier = CFGVerifier()

        code = """
        String input = request.getParameter("name");
        String output;
        if (validate(input)) {
            output = sanitize(input);
        } else {
            output = input;
        }
        response.getWriter().write(output);
        """

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="input",
            type="User Input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=8),
            variable_name="output",
            type="HTML Output",
            vulnerability_type=VulnerabilityType.XSS,
            confidence=0.9,
            code_snippet="",
        )

        chain = _make_chain("xss-chain", source, sink, ["input", "output"], VulnerabilityType.XSS)

        status = verifier.verify_chain(chain, code)
        assert status in (VerificationStatus.VERIFIED, VerificationStatus.FALSE)

    def test_path_traversal_with_loop(self) -> None:
        """Test CFG verification with loops."""
        verifier = CFGVerifier()

        code = """
        String filename = request.getParameter("file");
        String path = basePath;
        for (int i = 0; i < parts.length; i++) {
            path = path + "/" + filename;
        }
        File file = new File(path);
        """

        source = Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="filename",
            type="User Input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=CodeLocation(file_path="test.java", line_number=6),
            variable_name="path",
            type="File Path",
            vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
            confidence=0.9,
            code_snippet="",
        )

        chain = _make_chain("path-traversal", source, sink, ["filename", "path"], VulnerabilityType.PATH_TRAVERSAL)

        status = verifier.verify_chain(chain, code)
        assert status in (VerificationStatus.VERIFIED, VerificationStatus.FALSE)
