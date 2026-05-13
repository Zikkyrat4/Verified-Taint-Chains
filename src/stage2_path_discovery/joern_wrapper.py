"""Joern integration for program dependence graph (PDG) analysis.

Joern (https://joern.io) is a code analysis platform that can generate
precise program dependence graphs (PDGs) for vulnerability analysis.

This wrapper:
- Detects if Joern is available in the system
- Calls Joern CLI to analyze code and generate PDG
- Parses PDG output and converts to NetworkX graph
- Falls back to EnhancedGraphBuilder if Joern unavailable
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from src.core.models import Source, Sink
from src.stage2_path_discovery.graph_builder import EnhancedGraphBuilder
from src.utils.logger import get_logger

logger = get_logger()


class JoernWrapper:
    """Wrapper for Joern code analysis platform.

    Provides an interface to Joern for generating program dependence graphs
    (PDGs) for Java code analysis. Falls back to EnhancedGraphBuilder if
    Joern is not available.

    Attributes:
        joern_available: Whether Joern CLI is installed and accessible.
        fallback_builder: EnhancedGraphBuilder for fallback analysis.
    """

    def __init__(self) -> None:
        """Initialize Joern wrapper, detecting if Joern is available."""
        self.joern_available = self._check_joern_available()
        self.fallback_builder = EnhancedGraphBuilder()

        if self.joern_available:
            logger.info("Joern integration enabled")
        else:
            logger.warning(
                "Joern not available, will use EnhancedGraphBuilder fallback. "
                "To enable Joern, install from https://joern.io"
            )

    def build_graph(
        self, source_code: str, sources: List[Source], sinks: List[Sink]
    ) -> nx.DiGraph:
        """Build a PDG using Joern if available, otherwise fallback.

        Args:
            source_code: Java source code to analyze.
            sources: List of identified source nodes.
            sinks: List of identified sink nodes.

        Returns:
            NetworkX DiGraph representing program dependence.
        """
        if self.joern_available:
            try:
                logger.debug("Using Joern for PDG analysis")
                graph = self._build_graph_with_joern(source_code, sources, sinks)
                logger.info(
                    f"Built PDG with Joern: {graph.number_of_nodes()} nodes, "
                    f"{graph.number_of_edges()} edges"
                )
                return graph
            except Exception as e:
                logger.warning(
                    f"Joern analysis failed: {str(e)}, falling back to EnhancedGraphBuilder"
                )

        # Fallback to EnhancedGraphBuilder
        logger.debug("Using EnhancedGraphBuilder for data flow graph")
        return self.fallback_builder.build_graph(source_code, sources, sinks)

    def _check_joern_available(self) -> bool:
        """Check if Joern CLI is available in the system.

        Returns:
            True if Joern is installed and accessible, False otherwise.
        """
        try:
            result = subprocess.run(
                ["joern", "--version"],
                capture_output=True,
                timeout=5,
                text=True,
            )
            available = result.returncode == 0
            if available:
                logger.debug(f"Joern version: {result.stdout.strip()}")
            return available
        except FileNotFoundError:
            logger.debug("Joern CLI not found in PATH")
            return False
        except subprocess.TimeoutExpired:
            logger.debug("Joern check timed out")
            return False
        except Exception as e:
            logger.debug(f"Error checking Joern availability: {str(e)}")
            return False

    def _build_graph_with_joern(
        self, source_code: str, sources: List[Source], sinks: List[Sink]
    ) -> nx.DiGraph:
        """Build graph using Joern PDG analysis.

        Args:
            source_code: Java source code.
            sources: List of sources.
            sinks: List of sinks.

        Returns:
            NetworkX DiGraph from Joern analysis.

        Raises:
            RuntimeError: If Joern analysis fails.
        """
        # Create temporary file with source code
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".java", delete=False
        ) as tmp:
            tmp.write(source_code)
            tmp_path = tmp.name

        try:
            # Run Joern to export PDG
            logger.debug(f"Running Joern on {tmp_path}")

            # Export PDG to JSON
            result = subprocess.run(
                [
                    "joern",
                    "--script",
                    "exportPdg.sc",
                    tmp_path,
                ],
                capture_output=True,
                timeout=30,
                text=True,
            )

            if result.returncode != 0:
                raise RuntimeError(f"Joern failed: {result.stderr}")

            # Parse PDG output
            graph = self._parse_joern_pdg(result.stdout, sources, sinks)
            return graph

        finally:
            # Clean up temporary file
            Path(tmp_path).unlink(missing_ok=True)

    def _parse_joern_pdg(
        self,
        pdg_output: str,
        sources: List[Source],
        sinks: List[Sink],
    ) -> nx.DiGraph:
        """Parse Joern PDG output and convert to NetworkX graph.

        Joern PDG format (simplified):
        - Nodes: method declarations, variables, literals
        - Edges: data/control/call dependencies

        Args:
            pdg_output: Joern PDG output (JSON or text format).
            sources: Source nodes for context.
            sinks: Sink nodes for context.

        Returns:
            NetworkX DiGraph representation of PDG.
        """
        graph = nx.DiGraph()

        try:
            # Try parsing as JSON first
            pdg_data = json.loads(pdg_output)
            return self._parse_json_pdg(pdg_data, sources, sinks)
        except json.JSONDecodeError:
            # Fall back to text parsing
            logger.debug("Joern output not JSON, using text parsing")
            return self._parse_text_pdg(pdg_output, sources, sinks)

    def _parse_json_pdg(
        self,
        pdg_data: Dict,
        sources: List[Source],
        sinks: List[Sink],
    ) -> nx.DiGraph:
        """Parse JSON-formatted PDG from Joern.

        Args:
            pdg_data: Parsed JSON PDG data.
            sources: Source nodes.
            sinks: Sink nodes.

        Returns:
            NetworkX DiGraph.
        """
        graph = nx.DiGraph()

        # Add nodes from PDG
        if "nodes" in pdg_data:
            for node in pdg_data["nodes"]:
                node_id = node.get("id", str(node))
                node_type = node.get("type", "unknown")
                node_label = node.get("label", node_id)

                graph.add_node(
                    node_id,
                    type=node_type,
                    label=node_label,
                    data=node,
                )

        # Add edges from PDG
        if "edges" in pdg_data:
            for edge in pdg_data["edges"]:
                src = edge.get("source")
                dst = edge.get("target")
                edge_type = edge.get("type", "data_flow")

                if src and dst:
                    graph.add_edge(src, dst, edge_type=edge_type)

        # Add source and sink context
        source_names = {s.variable_name for s in sources}
        sink_names = {s.variable_name for s in sinks}

        for node_id in graph.nodes():
            if node_id in source_names:
                graph.nodes[node_id]["source_context"] = True
            if node_id in sink_names:
                graph.nodes[node_id]["sink_context"] = True

        logger.debug(f"Parsed JSON PDG: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
        return graph

    def _parse_text_pdg(
        self,
        pdg_output: str,
        sources: List[Source],
        sinks: List[Sink],
    ) -> nx.DiGraph:
        """Parse text-formatted PDG output from Joern.

        Expects format like:
        node1 -> node2
        node2 -> node3

        Args:
            pdg_output: Text PDG output.
            sources: Source nodes.
            sinks: Sink nodes.

        Returns:
            NetworkX DiGraph.
        """
        graph = nx.DiGraph()
        lines = pdg_output.strip().split("\n")

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Parse edge format: node1 -> node2
            if "->" in line:
                parts = line.split("->")
                if len(parts) == 2:
                    src = parts[0].strip()
                    dst = parts[1].strip()

                    if src and dst:
                        graph.add_node(src, type="intermediate")
                        graph.add_node(dst, type="intermediate")
                        graph.add_edge(src, dst, edge_type="data_flow")

        # Add source and sink nodes
        for source in sources:
            graph.add_node(
                source.variable_name,
                type="source",
                source=source,
            )

        for sink in sinks:
            graph.add_node(
                sink.variable_name,
                type="sink",
                sink=sink,
            )

        logger.debug(f"Parsed text PDG: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
        return graph

    def get_joern_status(self) -> Dict[str, bool]:
        """Get status of Joern integration.

        Returns:
            Dictionary with joern_available flag and reason if unavailable.
        """
        return {
            "joern_available": self.joern_available,
            "using_fallback": not self.joern_available,
        }
