"""Simple CFG-based verification of taint chains."""

from typing import Dict, Optional

import networkx as nx

from src.core.models import TaintChain, VerificationStatus
from src.utils.logger import get_logger

logger = get_logger()


class SimpleCFGVerifier:
    """Simple Control Flow Graph-based taint chain verifier.

    Performs basic reachability checks to determine if a taint chain is valid.
    A chain is verified if the path from source to sink is reachable in the graph.

    For MVP, only performs reachability checking. Future versions will add:
    - Symbolic execution
    - Path constraints
    - Type analysis
    """

    def __init__(self, graph: nx.DiGraph) -> None:
        """Initialize the verifier with a graph.

        Args:
            graph: NetworkX DiGraph representing the control/data flow.

        Raises:
            ValueError: If graph is not a DiGraph.
        """
        if not isinstance(graph, nx.DiGraph):
            raise ValueError("graph must be a NetworkX DiGraph")

        self.graph = graph
        logger.info(
            f"Initialized SimpleCFGVerifier with graph containing "
            f"{graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges"
        )

    def verify_chain(
        self,
        chain: TaintChain,
        node_id_map: Optional[Dict[int, str]] = None,
    ) -> VerificationStatus:
        """Verify if a taint chain is reachable in the graph.

        Checks if there is a path from the source variable to the sink variable
        in the underlying graph. If a path exists, the chain is considered verified.

        Args:
            chain: TaintChain object to verify.
            node_id_map: Optional mapping from ``id(source/sink)`` to scoped
                graph node ID.  When *None* the plain ``variable_name`` is used.

        Returns:
            VerificationStatus.VERIFIED if path exists in graph.
            VerificationStatus.FALSE if no path exists in graph.
            (VerificationStatus.UNVERIFIABLE reserved for future use)
        """
        logger.debug(
            f"Verifying chain: {chain.source.variable_name} -> {chain.sink.variable_name}"
        )

        if node_id_map is not None:
            src_id = node_id_map.get(id(chain.source), chain.source.variable_name)
            sink_id = node_id_map.get(id(chain.sink), chain.sink.variable_name)
        else:
            src_id = chain.source.variable_name
            sink_id = chain.sink.variable_name

        # Check if path exists using networkx
        is_reachable = self.verify_reachability(src_id, sink_id)

        if is_reachable:
            logger.info(
                f"✓ Chain VERIFIED: {chain.source.variable_name} -> {chain.sink.variable_name}"
            )
            return VerificationStatus.VERIFIED
        else:
            logger.info(
                f"✗ Chain FALSE: {chain.source.variable_name} -> {chain.sink.variable_name}"
            )
            return VerificationStatus.FALSE

    def verify_reachability(self, source_node: str, sink_node: str) -> bool:
        """Check if there is a path from source to sink in the graph.

        Simple reachability check using NetworkX has_path function.

        Args:
            source_node: Source node identifier.
            sink_node: Sink node identifier.

        Returns:
            True if a path exists from source to sink, False otherwise.
        """
        if source_node not in self.graph:
            logger.debug(f"Source node '{source_node}' not in graph")
            return False

        if sink_node not in self.graph:
            logger.debug(f"Sink node '{sink_node}' not in graph")
            return False

        # Check reachability using NetworkX
        has_path = nx.has_path(self.graph, source_node, sink_node)

        logger.debug(
            f"Reachability check {source_node} -> {sink_node}: {has_path}"
        )

        return has_path

    def get_verification_confidence(self, chain: TaintChain) -> float:
        """Get confidence score for a verified chain.

        For MVP, returns a simple confidence based on verification status:
        - 0.8 if chain is VERIFIED
        - 0.2 if chain is FALSE
        - 0.5 for UNVERIFIABLE

        Future versions will calculate confidence based on:
        - Symbolic execution results
        - Type constraints
        - Sanitizer analysis
        - Path complexity

        Args:
            chain: TaintChain to evaluate.

        Returns:
            Confidence score between 0.0 and 1.0.
        """
        if chain.verification_status is None:
            logger.warning(f"Chain {chain.id} not yet verified, returning 0.5")
            return 0.5

        if chain.verification_status == VerificationStatus.VERIFIED:
            confidence = 0.8
        elif chain.verification_status == VerificationStatus.FALSE:
            confidence = 0.2
        else:  # UNVERIFIABLE
            confidence = 0.5

        logger.debug(
            f"Verification confidence for {chain.id}: {confidence}"
        )

        return confidence

    def verify_all_chains(
        self,
        chains: list[TaintChain],
        node_id_map: Optional[Dict[int, str]] = None,
    ) -> dict:
        """Verify multiple taint chains and return results.

        Args:
            chains: List of TaintChain objects to verify.
            node_id_map: Optional mapping from ``id(source/sink)`` to scoped
                graph node ID.  Passed through to ``verify_chain``.

        Returns:
            Dictionary with:
            - 'verified': List of verified chains
            - 'false': List of false chains
            - 'total': Total number of chains verified
        """
        verified: list[TaintChain] = []
        false: list[TaintChain] = []

        logger.info(f"Verifying {len(chains)} chains...")

        for chain in chains:
            status = self.verify_chain(chain, node_id_map=node_id_map)

            # Update chain with verification status
            chain.verification_status = status

            if status == VerificationStatus.VERIFIED:
                verified.append(chain)
            elif status == VerificationStatus.FALSE:
                false.append(chain)

        logger.info(
            f"Verification complete: {len(verified)} verified, {len(false)} false"
        )

        return {
            "verified": verified,
            "false": false,
            "total": len(chains),
            "verification_rate": len(verified) / len(chains) if chains else 0.0,
        }
