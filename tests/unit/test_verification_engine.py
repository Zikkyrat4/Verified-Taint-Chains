"""Tests for VerificationEngine two-level verification."""

import pytest
from unittest.mock import patch, MagicMock

from src.core.config import PipelineConfig
from src.core.models import (
    TaintChain, Source, Sink, PathNode, CodeLocation, VulnerabilityType, VerificationStatus,
)
from src.stage3_verification.verification_engine import (
    VerificationEngine, VerificationResult,
)


SAMPLE_CODE = """
public class Test {
    public void process(String userId) {
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = conn.createStatement();
        stmt.executeQuery(query);
    }
}
"""


@pytest.fixture
def cfg_config():
    return PipelineConfig(
        llm_api_key="test-key",
        verification_enabled=True,
        verification_level="cfg",
        symbolic_execution_enabled=False,
    )


@pytest.fixture
def symbolic_config():
    return PipelineConfig(
        llm_api_key="test-key",
        verification_enabled=True,
        verification_level="both",
        symbolic_execution_enabled=True,
        symbolic_timeout=10,
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
        location=CodeLocation(file_path="test.java", line_number=4),
        variable_name="query",
        type="SQL",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        confidence=0.85,
        code_snippet='String query = "SELECT * FROM users WHERE id = \'" + userId + "\'";',
    )
    return TaintChain(
        id="test-chain",
        source=source,
        sink=sink,
        path=[
            PathNode(location=CodeLocation(file_path="test.java", line_number=3), variable_name="userId", node_type="source", code_snippet='String userId = request.getParameter("id");'),
            PathNode(location=CodeLocation(file_path="test.java", line_number=4), variable_name="query", node_type="sink", code_snippet='String query = "SELECT * FROM users WHERE id = \'" + userId + "\'";'),
        ],
        length=2,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        confidence=0.875,
    )


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_creation(self):
        result = VerificationResult(
            status=VerificationStatus.VERIFIED,
            cfg_status=VerificationStatus.VERIFIED,
        )
        assert result.status == VerificationStatus.VERIFIED
        assert result.confidence == 0.5
        assert result.method_used == "cfg"

    def test_to_dict(self):
        result = VerificationResult(
            status=VerificationStatus.VERIFIED,
            cfg_status=VerificationStatus.VERIFIED,
            symbolic_status=VerificationStatus.VERIFIED,
            confidence=0.95,
            method_used="cfg+symbolic",
            details="Both verified",
        )
        d = result.to_dict()
        assert d["status"] == "verified"
        assert d["cfg_status"] == "verified"
        assert d["symbolic_status"] == "verified"
        assert d["confidence"] == 0.95
        assert d["method_used"] == "cfg+symbolic"

    def test_to_dict_no_symbolic(self):
        result = VerificationResult(
            status=VerificationStatus.UNVERIFIABLE,
            cfg_status=VerificationStatus.VERIFIED,
        )
        d = result.to_dict()
        assert d["symbolic_status"] is None


class TestVerificationEngine:
    """Tests for VerificationEngine."""

    def test_init_cfg_only(self, cfg_config):
        engine = VerificationEngine(cfg_config)
        assert engine.cfg_verifier is not None
        assert engine.symbolic_executor is None

    def test_init_with_symbolic(self, symbolic_config):
        engine = VerificationEngine(symbolic_config)
        assert engine.cfg_verifier is not None
        assert engine.symbolic_executor is not None

    def test_verify_chain_cfg_only(self, cfg_config, sample_chain):
        engine = VerificationEngine(cfg_config)
        result = engine.verify_chain(sample_chain, SAMPLE_CODE)
        assert isinstance(result, VerificationResult)
        assert result.cfg_status is not None
        assert result.method_used == "cfg"

    def test_verify_chain_updates_chain_status(self, cfg_config, sample_chain):
        engine = VerificationEngine(cfg_config)
        result = engine.verify_chain(sample_chain, SAMPLE_CODE)
        assert sample_chain.verification_status == result.status

    @patch("src.stage3_verification.verification_engine.CFGVerifier")
    def test_verify_chain_cfg_false_fast_reject(self, mock_cfg_cls, cfg_config, sample_chain):
        mock_verifier = MagicMock()
        mock_verifier.verify_chain.return_value = VerificationStatus.FALSE
        mock_cfg_cls.return_value = mock_verifier

        engine = VerificationEngine(cfg_config)
        engine.cfg_verifier = mock_verifier
        result = engine.verify_chain(sample_chain, SAMPLE_CODE)

        assert result.status == VerificationStatus.FALSE
        assert result.confidence == 0.9
        assert result.method_used == "cfg"

    @patch("src.stage3_verification.verification_engine.CFGVerifier")
    @patch("src.stage3_verification.verification_engine.SymbolicExecutor")
    def test_verify_chain_symbolic_verified(
        self, mock_sym_cls, mock_cfg_cls, symbolic_config, sample_chain
    ):
        mock_cfg = MagicMock()
        mock_cfg.verify_chain.return_value = VerificationStatus.VERIFIED
        mock_sym = MagicMock()
        mock_sym.execute_path.return_value = VerificationStatus.VERIFIED

        engine = VerificationEngine(symbolic_config)
        engine.cfg_verifier = mock_cfg
        engine.symbolic_executor = mock_sym
        result = engine.verify_chain(sample_chain, SAMPLE_CODE)

        assert result.status == VerificationStatus.VERIFIED
        assert result.confidence == 0.95
        assert result.method_used == "cfg+symbolic"

    @patch("src.stage3_verification.verification_engine.CFGVerifier")
    @patch("src.stage3_verification.verification_engine.SymbolicExecutor")
    def test_verify_chain_symbolic_false(
        self, mock_sym_cls, mock_cfg_cls, symbolic_config, sample_chain
    ):
        mock_cfg = MagicMock()
        mock_cfg.verify_chain.return_value = VerificationStatus.VERIFIED
        mock_sym = MagicMock()
        mock_sym.execute_path.return_value = VerificationStatus.FALSE

        engine = VerificationEngine(symbolic_config)
        engine.cfg_verifier = mock_cfg
        engine.symbolic_executor = mock_sym
        result = engine.verify_chain(sample_chain, SAMPLE_CODE)

        assert result.status == VerificationStatus.FALSE
        assert result.method_used == "cfg+symbolic"

    @patch("src.stage3_verification.verification_engine.CFGVerifier")
    @patch("src.stage3_verification.verification_engine.SymbolicExecutor")
    def test_verify_chain_symbolic_unverifiable(
        self, mock_sym_cls, mock_cfg_cls, symbolic_config, sample_chain
    ):
        mock_cfg = MagicMock()
        mock_cfg.verify_chain.return_value = VerificationStatus.VERIFIED
        mock_sym = MagicMock()
        mock_sym.execute_path.return_value = VerificationStatus.UNVERIFIABLE

        engine = VerificationEngine(symbolic_config)
        engine.cfg_verifier = mock_cfg
        engine.symbolic_executor = mock_sym
        result = engine.verify_chain(sample_chain, SAMPLE_CODE)

        assert result.status == VerificationStatus.UNVERIFIABLE
        assert result.confidence == 0.7

    def test_verify_all_chains(self, cfg_config, sample_chain):
        engine = VerificationEngine(cfg_config)
        results = engine.verify_all_chains([sample_chain], SAMPLE_CODE)

        assert "verified" in results
        assert "false" in results
        assert "unverifiable" in results
        assert "total" in results
        assert results["total"] == 1
        assert "avg_confidence" in results
        assert "method_counts" in results

    def test_verify_all_chains_empty(self, cfg_config):
        engine = VerificationEngine(cfg_config)
        results = engine.verify_all_chains([], SAMPLE_CODE)
        assert results["total"] == 0
        assert results["avg_confidence"] == 0.0

    def test_get_statistics_cfg_only(self, cfg_config):
        engine = VerificationEngine(cfg_config)
        stats = engine.get_statistics()
        assert stats["cfg_enabled"] is True
        assert stats["symbolic_enabled"] is False
        assert "cfg" in stats
        assert stats["symbolic"] == {"enabled": False}

    def test_get_statistics_with_symbolic(self, symbolic_config):
        engine = VerificationEngine(symbolic_config)
        stats = engine.get_statistics()
        assert stats["symbolic_enabled"] is True
        assert "symbolic" in stats
        assert stats["symbolic"]["backend"] is not None

    def test_verify_single_chain_simple(self, cfg_config, sample_chain):
        engine = VerificationEngine(cfg_config)
        status = engine.verify_single_chain_simple(sample_chain, SAMPLE_CODE)
        assert isinstance(status, VerificationStatus)
