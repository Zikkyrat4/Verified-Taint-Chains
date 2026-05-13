"""Unit tests for simple CFG verifier."""

import pytest
import networkx as nx

from src.stage3_verification.simple_verifier import SimpleCFGVerifier
from src.core.models import (
    TaintChain,
    Source,
    Sink,
    CodeLocation,
    VerificationStatus,
    VulnerabilityType,
    PathNode,
)


class TestSimpleCFGVerifierInit:
    """Tests for SimpleCFGVerifier initialization."""

    def test_init_with_digraph(self) -> None:
        """Test initialization with valid DiGraph."""
        graph = nx.DiGraph()
        graph.add_edge("a", "b")

        verifier = SimpleCFGVerifier(graph)

        assert verifier.graph is graph

    def test_init_with_invalid_graph(self) -> None:
        """Test that non-DiGraph raises ValueError."""
        graph = nx.Graph()  # Undirected graph

        with pytest.raises(ValueError, match="must be a NetworkX DiGraph"):
            SimpleCFGVerifier(graph)

    def test_init_with_empty_graph(self) -> None:
        """Test initialization with empty DiGraph."""
        graph = nx.DiGraph()

        verifier = SimpleCFGVerifier(graph)

        assert verifier.graph.number_of_nodes() == 0


class TestReachabilityCheck:
    """Tests for reachability checking."""

    def test_verify_reachability_direct_edge(self) -> None:
        """Test reachability with direct edge."""
        graph = nx.DiGraph()
        graph.add_edge("source", "sink")

        verifier = SimpleCFGVerifier(graph)
        result = verifier.verify_reachability("source", "sink")

        assert result is True

    def test_verify_reachability_path_exists(self) -> None:
        """Test reachability with multi-hop path."""
        graph = nx.DiGraph()
        graph.add_edges_from([("a", "b"), ("b", "c"), ("c", "d")])

        verifier = SimpleCFGVerifier(graph)
        result = verifier.verify_reachability("a", "d")

        assert result is True

    def test_verify_reachability_no_path(self) -> None:
        """Test reachability with disconnected nodes."""
        graph = nx.DiGraph()
        graph.add_edges_from([("a", "b"), ("c", "d")])

        verifier = SimpleCFGVerifier(graph)
        result = verifier.verify_reachability("a", "d")

        assert result is False

    def test_verify_reachability_nonexistent_source(self) -> None:
        """Test reachability with non-existent source."""
        graph = nx.DiGraph()
        graph.add_edge("a", "b")

        verifier = SimpleCFGVerifier(graph)
        result = verifier.verify_reachability("nonexistent", "b")

        assert result is False

    def test_verify_reachability_nonexistent_sink(self) -> None:
        """Test reachability with non-existent sink."""
        graph = nx.DiGraph()
        graph.add_edge("a", "b")

        verifier = SimpleCFGVerifier(graph)
        result = verifier.verify_reachability("a", "nonexistent")

        assert result is False


class TestVerifyChain:
    """Tests for chain verification."""

    def test_verify_chain_verified(self) -> None:
        """Test verification of a valid chain."""
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

        chain = TaintChain(
            id="chain1",
            source=source,
            sink=sink,
            path=[
                PathNode(location=loc, variable_name="x", node_type="source", code_snippet=""),
                PathNode(location=loc, variable_name="y", node_type="sink", code_snippet=""),
            ],
            length=2,
            confidence=0.85,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        verifier = SimpleCFGVerifier(graph)
        status = verifier.verify_chain(chain)

        assert status == VerificationStatus.VERIFIED

    def test_verify_chain_false(self) -> None:
        """Test verification of an invalid chain (no path)."""
        graph = nx.DiGraph()
        graph.add_edges_from([("a", "b"), ("c", "d")])

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

        chain = TaintChain(
            id="chain2",
            source=source,
            sink=sink,
            path=[],
            length=0,
            confidence=0.85,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        verifier = SimpleCFGVerifier(graph)
        status = verifier.verify_chain(chain)

        assert status == VerificationStatus.FALSE

    def test_verify_chain_updates_status(self) -> None:
        """Test that verify_chain can update chain status."""
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

        chain = TaintChain(
            id="chain1",
            source=source,
            sink=sink,
            path=[],
            length=0,
            confidence=0.85,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            verification_status=None,
        )

        verifier = SimpleCFGVerifier(graph)
        status = verifier.verify_chain(chain)

        assert status == VerificationStatus.VERIFIED
        # Note: verify_chain doesn't modify the chain, just returns status


class TestVerificationConfidence:
    """Tests for verification confidence calculation."""

    def test_confidence_verified(self) -> None:
        """Test confidence for verified chain."""
        graph = nx.DiGraph()
        loc = CodeLocation(file_path="test.java", line_number=1)
        chain = TaintChain(
            id="chain1",
            source=Source(
                location=loc,
                variable_name="x",
                type="user_input",
                confidence=0.9,
                code_snippet="",
            ),
            sink=Sink(
                location=loc,
                variable_name="y",
                type="sql",
                confidence=0.9,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            path=[],
            length=0,
            confidence=0.85,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            verification_status=VerificationStatus.VERIFIED,
        )

        verifier = SimpleCFGVerifier(graph)
        confidence = verifier.get_verification_confidence(chain)

        assert confidence == 0.8

    def test_confidence_false(self) -> None:
        """Test confidence for false chain."""
        graph = nx.DiGraph()
        loc = CodeLocation(file_path="test.java", line_number=1)
        chain = TaintChain(
            id="chain1",
            source=Source(
                location=loc,
                variable_name="x",
                type="user_input",
                confidence=0.9,
                code_snippet="",
            ),
            sink=Sink(
                location=loc,
                variable_name="y",
                type="sql",
                confidence=0.9,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            path=[],
            length=0,
            confidence=0.85,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            verification_status=VerificationStatus.FALSE,
        )

        verifier = SimpleCFGVerifier(graph)
        confidence = verifier.get_verification_confidence(chain)

        assert confidence == 0.2

    def test_confidence_unverifiable(self) -> None:
        """Test confidence for unverifiable chain."""
        graph = nx.DiGraph()
        loc = CodeLocation(file_path="test.java", line_number=1)
        chain = TaintChain(
            id="chain1",
            source=Source(
                location=loc,
                variable_name="x",
                type="user_input",
                confidence=0.9,
                code_snippet="",
            ),
            sink=Sink(
                location=loc,
                variable_name="y",
                type="sql",
                confidence=0.9,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            path=[],
            length=0,
            confidence=0.85,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            verification_status=VerificationStatus.UNVERIFIABLE,
        )

        verifier = SimpleCFGVerifier(graph)
        confidence = verifier.get_verification_confidence(chain)

        assert confidence == 0.5

    def test_confidence_none(self) -> None:
        """Test confidence for unverified chain."""
        graph = nx.DiGraph()
        loc = CodeLocation(file_path="test.java", line_number=1)
        chain = TaintChain(
            id="chain1",
            source=Source(
                location=loc,
                variable_name="x",
                type="user_input",
                confidence=0.9,
                code_snippet="",
            ),
            sink=Sink(
                location=loc,
                variable_name="y",
                type="sql",
                confidence=0.9,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            path=[],
            length=0,
            confidence=0.85,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            verification_status=None,
        )

        verifier = SimpleCFGVerifier(graph)
        confidence = verifier.get_verification_confidence(chain)

        assert confidence == 0.5


class TestVerifyAllChains:
    """Tests for verifying multiple chains."""

    def test_verify_all_chains_mixed(self) -> None:
        """Test verifying multiple chains with mixed results."""
        graph = nx.DiGraph()
        graph.add_edges_from([("a", "b"), ("c", "d")])

        loc = CodeLocation(file_path="test.java", line_number=1)

        # Chain that should verify
        chain1 = TaintChain(
            id="chain1",
            source=Source(
                location=loc,
                variable_name="a",
                type="user_input",
                confidence=0.9,
                code_snippet="",
            ),
            sink=Sink(
                location=loc,
                variable_name="b",
                type="sql",
                confidence=0.9,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            path=[],
            length=0,
            confidence=0.85,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        # Chain that should not verify
        chain2 = TaintChain(
            id="chain2",
            source=Source(
                location=loc,
                variable_name="a",
                type="user_input",
                confidence=0.9,
                code_snippet="",
            ),
            sink=Sink(
                location=loc,
                variable_name="d",
                type="sql",
                confidence=0.9,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            path=[],
            length=0,
            confidence=0.85,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        verifier = SimpleCFGVerifier(graph)
        results = verifier.verify_all_chains([chain1, chain2])

        assert len(results["verified"]) == 1
        assert len(results["false"]) == 1
        assert results["total"] == 2
        assert results["verification_rate"] == 0.5

    def test_verify_all_chains_all_verified(self) -> None:
        """Test when all chains verify."""
        graph = nx.DiGraph()
        graph.add_edges_from([("a", "b"), ("b", "c")])

        loc = CodeLocation(file_path="test.java", line_number=1)

        chains = [
            TaintChain(
                id="chain1",
                source=Source(
                    location=loc,
                    variable_name="a",
                    type="user_input",
                    confidence=0.9,
                    code_snippet="",
                ),
                sink=Sink(
                    location=loc,
                    variable_name="b",
                    type="sql",
                    confidence=0.9,
                    code_snippet="",
                    vulnerability_type=VulnerabilityType.SQL_INJECTION,
                ),
                path=[],
                length=0,
                confidence=0.85,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            TaintChain(
                id="chain2",
                source=Source(
                    location=loc,
                    variable_name="a",
                    type="user_input",
                    confidence=0.9,
                    code_snippet="",
                ),
                sink=Sink(
                    location=loc,
                    variable_name="c",
                    type="sql",
                    confidence=0.9,
                    code_snippet="",
                    vulnerability_type=VulnerabilityType.SQL_INJECTION,
                ),
                path=[],
                length=0,
                confidence=0.85,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
        ]

        verifier = SimpleCFGVerifier(graph)
        results = verifier.verify_all_chains(chains)

        assert len(results["verified"]) == 2
        assert len(results["false"]) == 0
        assert results["verification_rate"] == 1.0

    def test_verify_all_chains_empty_list(self) -> None:
        """Test verifying empty chain list."""
        graph = nx.DiGraph()

        verifier = SimpleCFGVerifier(graph)
        results = verifier.verify_all_chains([])

        assert len(results["verified"]) == 0
        assert len(results["false"]) == 0
        assert results["total"] == 0
        assert results["verification_rate"] == 0.0
