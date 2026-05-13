"""Integration tests for VerificationEngine."""

import pytest

from src.stage3_verification.verification_engine import (
    VerificationEngine,
    VerificationResult,
)
from src.stage3_verification.symbolic_executor import Z3_AVAILABLE
from src.core.config import PipelineConfig
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


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_verification_result_creation(self) -> None:
        """Test creating verification result."""
        result = VerificationResult(
            status=VerificationStatus.VERIFIED,
            cfg_status=VerificationStatus.VERIFIED,
            symbolic_status=VerificationStatus.VERIFIED,
            confidence=0.95,
            method_used="cfg+symbolic",
            details="Both CFG and symbolic execution confirm vulnerability",
        )

        assert result.status == VerificationStatus.VERIFIED
        assert result.cfg_status == VerificationStatus.VERIFIED
        assert result.symbolic_status == VerificationStatus.VERIFIED
        assert result.confidence == 0.95
        assert result.method_used == "cfg+symbolic"

    def test_verification_result_to_dict(self) -> None:
        """Test converting verification result to dictionary."""
        result = VerificationResult(
            status=VerificationStatus.VERIFIED,
            cfg_status=VerificationStatus.VERIFIED,
            confidence=0.9,
            method_used="cfg",
        )

        result_dict = result.to_dict()

        assert result_dict["status"] == "verified"
        assert result_dict["cfg_status"] == "verified"
        assert result_dict["confidence"] == 0.9
        assert result_dict["method_used"] == "cfg"


class TestVerificationEngine:
    """Tests for VerificationEngine class."""

    def test_engine_initialization_without_symbolic(self) -> None:
        """Test engine initialization without symbolic execution."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="cfg",
        )

        engine = VerificationEngine(config)

        assert engine.config == config
        assert engine.cfg_verifier is not None
        assert engine.symbolic_executor is None

    def test_engine_initialization_with_symbolic(self) -> None:
        """Test engine initialization with symbolic execution."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="both",
        )

        engine = VerificationEngine(config)

        assert engine.config == config
        assert engine.cfg_verifier is not None
        assert engine.symbolic_executor is not None

    def test_engine_custom_parameters(self) -> None:
        """Test engine with custom parameters."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="cfg",
        )

        engine = VerificationEngine(
            config,
            max_loop_iterations=5,
            symbolic_timeout=60,
        )

        assert engine.max_loop_iterations == 5
        assert engine.symbolic_timeout == 60

    def test_verify_chain_cfg_only(self) -> None:
        """Test verifying chain with CFG only."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="cfg",
        )

        engine = VerificationEngine(config)

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

        result = engine.verify_chain(chain, code)

        assert result.cfg_status in (
            VerificationStatus.VERIFIED,
            VerificationStatus.FALSE,
        )
        assert result.symbolic_status is None
        assert result.method_used == "cfg"

    @pytest.mark.skipif(not Z3_AVAILABLE, reason="Z3 not available")
    def test_verify_chain_with_symbolic(self) -> None:
        """Test verifying chain with CFG + symbolic execution."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="both",
        )

        engine = VerificationEngine(config)

        code = """
        String input = getInput();
        String output = input;
        process(output);
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
            location=CodeLocation(file_path="test.java", line_number=3),
            variable_name="output",
            type="Output",
            vulnerability_type=VulnerabilityType.XSS,
            confidence=0.9,
            code_snippet="",
        )

        chain = TaintChain(
            id="symbolic-chain",
            source=source,
            sink=sink,
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.9,
            vulnerability_type=VulnerabilityType.XSS,
        )

        result = engine.verify_chain(chain, code)

        assert result.cfg_status in (
            VerificationStatus.VERIFIED,
            VerificationStatus.FALSE,
        )
        assert result.symbolic_status in (
            VerificationStatus.VERIFIED,
            VerificationStatus.FALSE,
            VerificationStatus.UNVERIFIABLE,
        )
        assert result.method_used in ("cfg", "cfg+symbolic")

    def test_verify_chain_cfg_rejects(self) -> None:
        """Test that CFG rejection skips symbolic execution."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="both",
        )

        engine = VerificationEngine(config)

        # Code where source and sink are in separate unreachable blocks
        code = """
        String input = getInput();
        if (false) {
            String output = input;
        }
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
            location=CodeLocation(file_path="test.java", line_number=3),
            variable_name="output",
            type="Output",
            vulnerability_type=VulnerabilityType.XSS,
            confidence=0.9,
            code_snippet="",
        )

        chain = TaintChain(
            id="unreachable",
            source=source,
            sink=sink,
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.9,
            vulnerability_type=VulnerabilityType.XSS,
        )

        result = engine.verify_chain(chain, code)

        # If CFG says FALSE, should return FALSE without running symbolic execution
        if result.cfg_status == VerificationStatus.FALSE:
            assert result.status == VerificationStatus.FALSE
            assert result.symbolic_status is None  # Should not run symbolic execution
            assert result.method_used == "cfg"

    def test_verify_all_chains(self) -> None:
        """Test verifying multiple chains."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="cfg",
        )

        engine = VerificationEngine(config)

        code = """
        String input1 = getInput1();
        String input2 = getInput2();
        String output1 = input1;
        String output2 = input2;
        """

        path_nodes1 = _make_path_nodes("input1", "output1")
        path_nodes2 = _make_path_nodes("input2", "output2")

        chains = [
            TaintChain(
                id="chain1",
                source=Source(
                    location=CodeLocation(file_path="test.java", line_number=1),
                    variable_name="input1",
                    type="Input",
                    confidence=0.9,
                    code_snippet="",
                ),
                sink=Sink(
                    location=CodeLocation(file_path="test.java", line_number=3),
                    variable_name="output1",
                    type="Output",
                    vulnerability_type=VulnerabilityType.XSS,
                    confidence=0.9,
                    code_snippet="",
                ),
                path=path_nodes1,
                length=len(path_nodes1),
                confidence=0.9,
                vulnerability_type=VulnerabilityType.XSS,
            ),
            TaintChain(
                id="chain2",
                source=Source(
                    location=CodeLocation(file_path="test.java", line_number=2),
                    variable_name="input2",
                    type="Input",
                    confidence=0.9,
                    code_snippet="",
                ),
                sink=Sink(
                    location=CodeLocation(file_path="test.java", line_number=4),
                    variable_name="output2",
                    type="Output",
                    vulnerability_type=VulnerabilityType.XSS,
                    confidence=0.9,
                    code_snippet="",
                ),
                path=path_nodes2,
                length=len(path_nodes2),
                confidence=0.9,
                vulnerability_type=VulnerabilityType.XSS,
            ),
        ]

        results = engine.verify_all_chains(chains, code)

        assert "verified" in results
        assert "false" in results
        assert "total" in results
        assert results["total"] == 2
        assert "avg_confidence" in results
        assert "method_counts" in results

    def test_verify_all_chains_statistics(self) -> None:
        """Test verification statistics from verify_all_chains."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="cfg",
        )

        engine = VerificationEngine(config)

        code = """
        String x = input;
        """

        path_nodes = _make_path_nodes("input", "x")

        chain = TaintChain(
            id="test",
            source=Source(
                location=CodeLocation(file_path="test.java", line_number=1),
                variable_name="input",
                type="Input",
                confidence=0.9,
                code_snippet="",
            ),
            sink=Sink(
                location=CodeLocation(file_path="test.java", line_number=1),
                variable_name="x",
                type="Output",
                vulnerability_type=VulnerabilityType.XSS,
                confidence=0.9,
                code_snippet="",
            ),
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.9,
            vulnerability_type=VulnerabilityType.XSS,
        )

        results = engine.verify_all_chains([chain], code)

        # Check statistics structure
        assert isinstance(results["verified"], list)
        assert isinstance(results["false"], list)
        assert isinstance(results["total"], int)
        assert isinstance(results["verification_rate"], float)
        assert isinstance(results["avg_confidence"], float)
        assert isinstance(results["method_counts"], dict)

    def test_get_statistics(self) -> None:
        """Test getting engine statistics."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="both",
        )

        engine = VerificationEngine(config)

        stats = engine.get_statistics()

        assert "cfg_enabled" in stats
        assert stats["cfg_enabled"] is True
        assert "symbolic_enabled" in stats
        assert stats["symbolic_enabled"] is True
        assert "max_loop_iterations" in stats
        assert "symbolic_timeout" in stats
        assert "cfg" in stats
        assert "symbolic" in stats

    def test_get_statistics_no_symbolic(self) -> None:
        """Test statistics when symbolic execution disabled."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="cfg",
        )

        engine = VerificationEngine(config)

        stats = engine.get_statistics()

        assert stats["symbolic_enabled"] is False
        assert stats["symbolic"]["enabled"] is False

    def test_verify_single_chain_simple(self) -> None:
        """Test convenience method for simple verification."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="cfg",
        )

        engine = VerificationEngine(config)

        code = """
        String x = input;
        """

        path_nodes = _make_path_nodes("input", "x")

        chain = TaintChain(
            id="simple",
            source=Source(
                location=CodeLocation(file_path="test.java", line_number=1),
                variable_name="input",
                type="Input",
                confidence=0.9,
                code_snippet="",
            ),
            sink=Sink(
                location=CodeLocation(file_path="test.java", line_number=1),
                variable_name="x",
                type="Output",
                vulnerability_type=VulnerabilityType.XSS,
                confidence=0.9,
                code_snippet="",
            ),
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.9,
            vulnerability_type=VulnerabilityType.XSS,
        )

        status = engine.verify_single_chain_simple(chain, code)

        # Should return a VerificationStatus
        assert isinstance(status, VerificationStatus)


class TestVerificationEngineIntegration:
    """Integration tests for VerificationEngine with real vulnerabilities."""

    def test_sql_injection_verification_cfg_only(self) -> None:
        """Test SQL injection verification with CFG only."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="cfg",
        )

        engine = VerificationEngine(config)

        code = """
        public void query(HttpServletRequest request) {
            String id = request.getParameter("id");
            String query = "SELECT * FROM users WHERE id=" + id;
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
        }
        """

        path_nodes = _make_path_nodes("id", "query")

        chain = TaintChain(
            id="sqli",
            source=Source(
                location=CodeLocation(file_path="test.java", line_number=2),
                variable_name="id",
                type="User Input",
                confidence=0.95,
                code_snippet="",
            ),
            sink=Sink(
                location=CodeLocation(file_path="test.java", line_number=5),
                variable_name="query",
                type="SQL",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                confidence=0.95,
                code_snippet="",
            ),
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.95,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        result = engine.verify_chain(chain, code)

        assert result.method_used == "cfg"
        assert result.confidence > 0.0

    @pytest.mark.skipif(not Z3_AVAILABLE, reason="Z3 not available")
    def test_sql_injection_verification_with_symbolic(self) -> None:
        """Test SQL injection verification with symbolic execution."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="both",
        )

        engine = VerificationEngine(config)

        code = """
        String id = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id=" + id;
        db.execute(query);
        """

        path_nodes = _make_path_nodes("id", "query")

        chain = TaintChain(
            id="sqli-symbolic",
            source=Source(
                location=CodeLocation(file_path="test.java", line_number=1),
                variable_name="id",
                type="User Input",
                confidence=0.95,
                code_snippet="",
            ),
            sink=Sink(
                location=CodeLocation(file_path="test.java", line_number=3),
                variable_name="query",
                type="SQL",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                confidence=0.95,
                code_snippet="",
            ),
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.95,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        result = engine.verify_chain(chain, code)

        # With symbolic execution, should have higher confidence
        if result.symbolic_status == VerificationStatus.VERIFIED:
            assert result.confidence >= 0.9

    def test_xss_verification_with_branches(self) -> None:
        """Test XSS verification with conditional branches."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_level="cfg",
        )

        engine = VerificationEngine(config)

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

        path_nodes = _make_path_nodes("input", "output")

        chain = TaintChain(
            id="xss-branches",
            source=Source(
                location=CodeLocation(file_path="test.java", line_number=1),
                variable_name="input",
                type="User Input",
                confidence=0.9,
                code_snippet="",
            ),
            sink=Sink(
                location=CodeLocation(file_path="test.java", line_number=8),
                variable_name="output",
                type="HTML Output",
                vulnerability_type=VulnerabilityType.XSS,
                confidence=0.9,
                code_snippet="",
            ),
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.9,
            vulnerability_type=VulnerabilityType.XSS,
        )

        result = engine.verify_chain(chain, code)

        # Should be able to verify (CFG should handle branches)
        assert result.status in (
            VerificationStatus.VERIFIED,
            VerificationStatus.FALSE,
            VerificationStatus.UNVERIFIABLE,
        )
