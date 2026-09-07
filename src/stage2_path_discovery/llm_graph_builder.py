"""LLM-driven data flow graph builder using tree-sitter AST + LLM enrichment."""

from typing import Any, List

import networkx as nx

from src.core.models import Source, Sink
from src.stage1_llm_inference.ast_parser import JavaASTParser
from src.stage1_llm_inference.prompt_templates import build_graph_enrichment_prompt
from src.stage2_path_discovery.graph_builder import EnhancedGraphBuilder
from src.utils.logger import get_logger

logger = get_logger()


class LLMGraphBuilder:
    """Builds data flow graphs using tree-sitter AST + LLM enrichment.

    The build_graph() method constructs a base graph from AST-extracted
    explicit flows (or regex fallback). The async enrich_graph() method
    adds implicit/framework flows discovered by the LLM.

    Attributes:
        llm_client: LLM client for enrichment queries.
        ast_parser: JavaASTParser instance for AST-based flow extraction.
        config: Optional pipeline configuration.
    """

    def __init__(
        self,
        llm_client: Any,
        config: Any = None,
    ) -> None:
        """Initialize the LLM-driven graph builder.

        Args:
            llm_client: LLM client with chat_with_json_prompt() method.
            config: Optional PipelineConfig for confidence thresholds etc.
        """
        self.llm_client = llm_client
        self.ast_parser = JavaASTParser()
        self.config = config
        self._fallback = EnhancedGraphBuilder()

        # Minimum confidence for accepting LLM-inferred edges
        self._min_confidence = 0.7
        if config and hasattr(config, "llm_graph_enrichment_confidence"):
            self._min_confidence = config.llm_graph_enrichment_confidence

        logger.debug("Initialized LLMGraphBuilder")

    def build_graph(
        self, source_code: str, sources: List[Source], sinks: List[Sink]
    ) -> nx.DiGraph:
        """Build base data flow graph from AST (sync, no LLM calls).

        Same interface as EnhancedGraphBuilder.build_graph().

        Args:
            source_code: Java source code to analyze.
            sources: List of identified Source objects.
            sinks: List of identified Sink objects.

        Returns:
            NetworkX DiGraph with data flow edges from AST analysis.
        """
        graph = nx.DiGraph()

        # Extract all variables for intermediate nodes
        variables = self._fallback._extract_variables(source_code)
        field_names = set(self.ast_parser.extract_field_names(source_code))
        local_names = self.ast_parser.extract_local_names_by_function(source_code)

        # Add source nodes
        for source in sources:
            graph.add_node(
                source.variable_name,
                type="source",
                source=source,
                confidence=source.confidence,
            )

        # Add sink nodes
        for sink in sinks:
            graph.add_node(
                sink.variable_name,
                type="sink",
                sink=sink,
                confidence=sink.confidence,
            )

        # Add intermediate variable nodes
        for var in variables:
            if var not in graph:
                graph.add_node(
                    var,
                    type="intermediate",
                    is_field=var in field_names,
                )
            elif var in field_names:
                graph.nodes[var]["is_field"] = True

        # Extract explicit data flows from AST (or regex fallback)
        ast_flows = self.ast_parser.extract_data_flows(source_code)
        ast_edge_count = 0

        for flow in ast_flows:
            from_var = flow["from_var"]
            to_var = flow["to_var"]
            if from_var in graph and to_var in graph and from_var != to_var:
                existing = graph.get_edge_data(from_var, to_var, default={})
                function_names = set(existing.get("function_names", []))
                if existing.get("function_name"):
                    function_names.add(existing["function_name"])
                if flow.get("function_name"):
                    function_names.add(flow["function_name"])
                function_name = flow.get("function_name")
                locals_in_function = local_names.get(function_name or "", set())
                field_flow_functions = set(
                    existing.get("field_flow_functions", [])
                )
                if function_name and (
                    (from_var in field_names and from_var not in locals_in_function)
                    or (to_var in field_names and to_var not in locals_in_function)
                ):
                    field_flow_functions.add(function_name)
                graph.add_edge(
                    from_var,
                    to_var,
                    edge_type="ast_explicit",
                    flow_type=flow.get("flow_type", "unknown"),
                    line=flow.get("line", 0),
                    function_name=flow.get("function_name"),
                    function_names=sorted(function_names),
                    field_flow_functions=sorted(field_flow_functions),
                )
                ast_edge_count += 1

        # Also add control flow edges from the fallback builder
        control_flows = self._fallback._extract_control_flows(source_code)
        for source_var, target_var, condition in control_flows:
            if (
                source_var in graph
                and target_var in graph
                and not graph.has_edge(source_var, target_var)
            ):
                graph.add_edge(
                    source_var,
                    target_var,
                    edge_type="control_flow",
                    condition=condition,
                )

        logger.info(
            f"LLMGraphBuilder base graph: {graph.number_of_nodes()} nodes, "
            f"{ast_edge_count} AST edges, {graph.number_of_edges()} total edges"
        )

        return graph

    async def enrich_graph(
        self,
        graph: nx.DiGraph,
        source_code: str,
        sources: List[Source],
        sinks: List[Sink],
    ) -> nx.DiGraph:
        """Enrich graph with LLM-inferred implicit flows (async).

        Sends the current graph's explicit flows + source code to the LLM,
        which returns additional implicit/framework flows and security
        classifications.

        If LLM call fails, returns the graph unchanged.

        Args:
            graph: Base graph from build_graph().
            source_code: Java source code.
            sources: List of Source objects.
            sinks: List of Sink objects.

        Returns:
            Enriched graph with LLM-inferred edges and node classifications.
        """
        try:
            prompt = self._build_enrichment_prompt(graph, source_code)
            result = await self.llm_client.chat_with_json_prompt(prompt)

            added_edges = 0
            added_classifications = 0

            # Add LLM-inferred edges
            for flow in result.get("additional_flows", []):
                from_var = flow.get("from", "")
                to_var = flow.get("to", "")
                confidence = flow.get("confidence", 0.0)

                if confidence < self._min_confidence:
                    continue

                if from_var in graph and to_var in graph and from_var != to_var:
                    graph.add_edge(
                        from_var,
                        to_var,
                        edge_type="llm_inferred",
                        flow_type=flow.get("flow_type", "implicit"),
                        confidence=confidence,
                    )
                    added_edges += 1

            # Apply security classifications to nodes
            for cls in result.get("classifications", []):
                var = cls.get("variable", "")
                classification = cls.get("classification", "")
                if var in graph and classification:
                    graph.nodes[var]["security_class"] = classification
                    added_classifications += 1

            logger.info(
                f"LLM enrichment: added {added_edges} edges, "
                f"{added_classifications} classifications"
            )

        except Exception as e:
            logger.warning(
                f"LLM graph enrichment failed (graph unchanged): {str(e)}"
            )

        return graph

    def _build_enrichment_prompt(
        self, graph: nx.DiGraph, source_code: str
    ) -> str:
        """Build the enrichment prompt from current graph state.

        Args:
            graph: Current data flow graph.
            source_code: Java source code.

        Returns:
            Formatted prompt string.
        """
        # Format existing edges as a readable list
        flow_lines = []
        for u, v, data in graph.edges(data=True):
            flow_type = data.get("flow_type", data.get("edge_type", "unknown"))
            flow_lines.append(f"  {u} -> {v}  ({flow_type})")

        if flow_lines:
            explicit_flows = "\n".join(flow_lines[:50])  # Limit to avoid token overflow
            if len(flow_lines) > 50:
                explicit_flows += f"\n  ... and {len(flow_lines) - 50} more flows"
        else:
            explicit_flows = "  (none identified yet)"

        return build_graph_enrichment_prompt(source_code, explicit_flows)
