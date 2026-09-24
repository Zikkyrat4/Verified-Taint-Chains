"""Simple path discovery using BFS on a data flow graph."""

import hashlib
import re
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from src.core.models import Source, Sink, Sanitizer, TaintChain, PathNode, CodeLocation
from src.core.types import Variables
from src.utils.logger import get_logger

logger = get_logger()


def stable_chain_id(
    source: Source,
    sink: Sink,
    path_nodes: List[str],
) -> str:
    """Build a deterministic ID from endpoint locations and the graph path."""
    source_location = source.location
    sink_location = sink.location
    identity = "\0".join([
        source_location.file_path or "",
        str(source_location.line_number or 0),
        source_location.function_name or "",
        source.variable_name or "",
        sink_location.file_path or "",
        str(sink_location.line_number or 0),
        sink_location.function_name or "",
        sink.variable_name or "",
        sink.vulnerability_type.value,
        *path_nodes,
    ])
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    return f"{source.variable_name}_to_{sink.variable_name}_{digest}"


def candidate_pair_priority(source: Source, sink: Sink) -> Tuple[object, ...]:
    """Rank endpoint pairs without relying on benchmark-specific knowledge."""
    source_location = source.location
    sink_location = sink.location
    stable_identity = "\0".join([
        source_location.file_path or "",
        str(source_location.line_number or 0),
        source_location.function_name or "",
        source.variable_name or "",
        sink_location.file_path or "",
        str(sink_location.line_number or 0),
        sink_location.function_name or "",
        sink.variable_name or "",
        sink.vulnerability_type.value,
    ])
    return (
        (source.confidence + sink.confidence) / 2.0,
        source.confidence,
        sink.confidence,
        stable_identity,
    )


def _display_node_name(graph: nx.DiGraph, node_name: str) -> str:
    """Return the source identifier stored on a possibly scoped graph node."""
    if node_name in graph:
        variable_name = graph.nodes[node_name].get("variable_name")
        if variable_name:
            return str(variable_name)
    return node_name.rsplit(":", 1)[-1]


def _intermediate_path_node(
    graph: nx.DiGraph,
    node_name: str,
    previous: Optional[str],
    following: Optional[str],
    fallback: CodeLocation,
) -> PathNode:
    """Build an intermediate node from graph evidence, never fabricated lines."""
    data = graph.nodes[node_name] if node_name in graph else {}
    edge_candidates = []
    if previous in graph and node_name in graph and graph.has_edge(previous, node_name):
        edge_candidates.append(graph[previous][node_name])
    if following in graph and node_name in graph and graph.has_edge(node_name, following):
        edge_candidates.append(graph[node_name][following])

    def first_value(*keys: str) -> object:
        for key in keys:
            value = data.get(key)
            if value not in (None, "", 0):
                return value
        for edge in edge_candidates:
            for key in keys:
                value = edge.get(key)
                if value not in (None, "", 0):
                    return value
        return None

    raw_line = first_value("line", "line_number", "call_line")
    try:
        line_number = max(1, int(raw_line or fallback.line_number))
    except (TypeError, ValueError):
        line_number = fallback.line_number
    location = CodeLocation(
        file_path=str(first_value("file_path", "caller_file") or fallback.file_path),
        line_number=line_number,
        function_name=(
            str(first_value("function_name", "caller_function"))
            if first_value("function_name", "caller_function")
            else fallback.function_name
        ),
        class_name=(
            str(first_value("class_name"))
            if first_value("class_name")
            else fallback.class_name
        ),
    )
    return PathNode(
        location=location,
        variable_name=_display_node_name(graph, node_name),
        node_type="intermediate",
        code_snippet=str(data.get("code_snippet", "") or ""),
    )


class SimpleGraphBuilder:
    """Builds a simplified data flow graph from Java code.

    Uses simple heuristics to extract variable assignments and function calls
    to approximate data flow relationships.
    """

    def __init__(self) -> None:
        """Initialize the graph builder."""
        logger.debug("Initialized SimpleGraphBuilder")

    def build_graph(
        self, source_code: str, sources: List[Source], sinks: List[Sink]
    ) -> nx.DiGraph:
        """Build a data flow graph from source code.

        Creates a directed graph where:
        - Nodes are variable names
        - Edges represent data flow (var1 = var2 means var2 -> var1)

        Args:
            source_code: Java source code to analyze.
            sources: List of identified source nodes.
            sinks: List of identified sink nodes.

        Returns:
            NetworkX DiGraph representing data flow.
        """
        graph = nx.DiGraph()

        # Extract all variables from code
        variables = self._extract_variables(source_code)
        logger.debug(f"Extracted {len(variables)} unique variables")

        # Add source and sink variables as nodes
        for source in sources:
            graph.add_node(source.variable_name, type="source", source=source)

        for sink in sinks:
            graph.add_node(sink.variable_name, type="sink", sink=sink)

        # Add other variables
        for var in variables:
            if var not in graph:
                graph.add_node(var, type="intermediate")

        # Extract data flow relationships
        edges = self._extract_data_flows(source_code)
        logger.debug(f"Extracted {len(edges)} data flow edges")

        for source_var, target_var in edges:
            if source_var in graph and target_var in graph:
                graph.add_edge(source_var, target_var)

        logger.debug(
            f"Built graph with {graph.number_of_nodes()} nodes and "
            f"{graph.number_of_edges()} edges"
        )

        return graph

    def _extract_variables(self, code: str) -> Variables:
        """Extract variable names from Java code using regex.

        Args:
            code: Java source code.

        Returns:
            Set of unique variable names found.
        """
        # Pattern to match Java variable declarations and usages
        # Matches: type varName or just varName in expressions
        pattern = r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b"

        variables: Variables = set()

        # Extract all identifiers
        for match in re.finditer(pattern, code):
            var = match.group(1)

            # Filter out Java keywords
            keywords = {
                "public",
                "private",
                "protected",
                "static",
                "final",
                "class",
                "interface",
                "extends",
                "implements",
                "void",
                "int",
                "String",
                "boolean",
                "double",
                "float",
                "long",
                "short",
                "byte",
                "char",
                "if",
                "else",
                "for",
                "while",
                "return",
                "new",
                "this",
                "super",
                "null",
                "true",
                "false",
                "import",
                "package",
                "throws",
                "try",
                "catch",
                "finally",
                "synchronized",
                "transient",
                "volatile",
                "abstract",
                "native",
                "strictfp",
                "const",
                "goto",
            }

            if var not in keywords and len(var) > 1:
                variables.add(var)

        logger.debug(f"Found {len(variables)} variables (after filtering keywords)")
        return variables

    def _extract_data_flows(self, code: str) -> List[Tuple[str, str]]:
        """Extract data flow relationships from code.

        Uses simple patterns to identify assignments and function calls:
        - var1 = var2 -> edge var2 -> var1
        - var1 = func(var2) -> edge var2 -> var1
        - func(var1) -> if func is a sink, edge var1 -> func

        Args:
            code: Java source code.

        Returns:
            List of (source_var, target_var) tuples representing edges.
        """
        edges: List[Tuple[str, str]] = []

        # Pattern 1: Simple assignment var1 = var2 or var1 = constant
        # Matches: var1 = var2; or var1 = var2 + var3;
        # The RHS character class excludes ``;`` (statement terminator) but
        # NOT ``=`` — otherwise any RHS with ``==`` / ``!=`` / ``<=`` / ``>=``
        # or a ternary like ``x == null ? a : b`` aborts the whole match,
        # losing the data-flow edge entirely. Real Java code hits this
        # constantly (e.g. ``var f = new File(dir, id == null ? def : id);``).
        # The optional ``[]`` after the name captures C-style array
        # declarations ``String commandParts[] = {...}`` — without it the bracket
        # sits between the name and ``=`` and the whole assignment is missed,
        # so nothing flows INTO the array (e.g. the args to Runtime.exec).
        assignment_pattern = r"([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[\s*\])?\s*=\s*([^;]+);"

        for match in re.finditer(assignment_pattern, code):
            target_var = match.group(1).strip()
            source_expr = match.group(2).strip()

            # Extract variables used on the right side
            var_pattern = r"([a-zA-Z_][a-zA-Z0-9_]*)"
            for var_match in re.finditer(var_pattern, source_expr):
                source_var = var_match.group(1)

                # Skip if it's a Java keyword or method name
                if not self._is_keyword(source_var) and source_var != target_var:
                    edges.append((source_var, target_var))

        # Pattern 2: obj.method() — data flows from object through method call
        method_chain_pattern = r'\b([a-zA-Z_]\w+)\.([a-zA-Z_]\w+)\s*\('
        for match in re.finditer(method_chain_pattern, code):
            obj = match.group(1)
            method = match.group(2)
            if not self._is_keyword(obj) and len(obj) > 1 and not self._is_keyword(method) and len(method) > 1:
                edges.append((obj, method))

        # Pattern 3: throw new ExceptionType(args) — variables in args flow to exception
        throw_pattern = r'throw\s+new\s+(\w+)\s*\((.+?)\)\s*;'
        for match in re.finditer(throw_pattern, code):
            exception_type = match.group(1)
            args = match.group(2)
            for var_match in re.finditer(r'\b([a-zA-Z_]\w+)\b', args):
                var = var_match.group(1)
                if not self._is_keyword(var) and len(var) > 1:
                    edges.append((var, exception_type))

        # Pattern 4: return expr; — variables flow to return
        return_pattern = r'return\s+([^;]+);'
        for match in re.finditer(return_pattern, code):
            expr = match.group(1).strip()
            for var_match in re.finditer(r'\b([a-zA-Z_]\w+)\b', expr):
                var = var_match.group(1)
                if not self._is_keyword(var) and len(var) > 1:
                    edges.append((var, "return_value"))

        # Pattern 5: obj.method(arg1, arg2) — args flow to obj
        method_arg_pattern = r'(\w+)\.\w+\s*\(([^)]+)\)'
        for match in re.finditer(method_arg_pattern, code):
            receiver = match.group(1)
            args = match.group(2)
            if self._is_keyword(receiver) or len(receiver) <= 1:
                continue
            for var_match in re.finditer(r'\b([a-zA-Z_]\w+)\b', args):
                var = var_match.group(1)
                if not self._is_keyword(var) and var != receiver and len(var) > 1:
                    edges.append((var, receiver))

        logger.debug(f"Found {len(edges)} data flow edges")
        return edges

    @staticmethod
    def _is_keyword(word: str) -> bool:
        """Check if word is a Java keyword."""
        keywords = {
            "public",
            "private",
            "protected",
            "static",
            "final",
            "class",
            "interface",
            "void",
            "int",
            "String",
            "boolean",
            "double",
            "float",
            "long",
            "short",
            "if",
            "else",
            "for",
            "while",
            "return",
            "new",
            "null",
            "true",
            "false",
        }
        return word in keywords


class SimpleBFSPathFinder:
    """Finds data flow paths using BFS on a graph.

    Uses breadth-first search to find shortest paths between sources and sinks
    in a data flow graph.
    """

    def __init__(self, graph: nx.DiGraph) -> None:
        """Initialize the path finder.

        Args:
            graph: NetworkX DiGraph representing data flow.
        """
        self.graph = graph
        self.limit_exceeded = False
        self.reachable_pairs_seen = 0
        self.candidate_pairs_ranked = 0
        self.ranked_out_count = 0
        logger.debug(f"Initialized SimpleBFSPathFinder with graph of {graph.number_of_nodes()} nodes")

    def find_path(
        self, source_node: str, sink_node: str, max_length: int = 15
    ) -> Optional[List[str]]:
        """Find a path from source to sink using BFS.

        Args:
            source_node: Starting variable name.
            sink_node: Target variable name.
            max_length: Maximum path length to consider.

        Returns:
            List of variable names representing the path, or None if not found.
        """
        if source_node not in self.graph or sink_node not in self.graph:
            logger.debug(f"Source or sink not in graph: {source_node}, {sink_node}")
            return None

        try:
            # Use NetworkX shortest path with length limit
            path = nx.shortest_path(self.graph, source_node, sink_node)

            if len(path) <= max_length:
                logger.debug(f"Found path of length {len(path)}: {' -> '.join(path)}")
                return path
            else:
                logger.debug(f"Path too long ({len(path)} > {max_length})")
                return None

        except nx.NetworkXNoPath:
            logger.debug(f"No path found from {source_node} to {sink_node}")
            return None
        except nx.NodeNotFound:
            logger.debug("Node not found in graph")
            return None

    def find_all_chains(
        self,
        sources: List[Source],
        sinks: List[Sink],
        max_length: int = 15,
        sanitizers: Optional[List[Sanitizer]] = None,
        node_id_map: Optional[Dict[int, str]] = None,
        max_chains: int = 0,
    ) -> List[TaintChain]:
        """Find all taint chains between sources and sinks.

        For each (source, sink) pair, attempts to find a path. If a path exists,
        creates a TaintChain object.

        Args:
            sources: List of source nodes.
            sinks: List of sink nodes.
            max_length: Maximum path length to consider.
            sanitizers: Optional list of detected sanitizers to attach to chains.
            node_id_map: Optional mapping from ``id(source/sink)`` to scoped
                graph node ID (e.g. ``"File.java:varName"``).  When *None*
                (default) the plain ``variable_name`` is used — fully
                backward-compatible with the old single-file behaviour.
            max_chains: Maximum retained candidates. The finder records
                ``limit_exceeded`` when additional reachable pairs exist.

        Returns:
            List of TaintChain objects representing found vulnerabilities.
        """
        chains: List[TaintChain] = []
        self.limit_exceeded = False
        self.reachable_pairs_seen = 0
        self.candidate_pairs_ranked = 0
        self.ranked_out_count = 0

        def _node_id(obj: object) -> str:
            if node_id_map is not None:
                return node_id_map.get(id(obj), getattr(obj, "variable_name", ""))
            return getattr(obj, "variable_name", "")

        logger.info(f"Finding paths between {len(sources)} sources and {len(sinks)} sinks")

        # Pre-compute reachable sink names for each source (BFS bounded by max_length)
        sink_graph_ids = {_node_id(s) for s in sinks}
        source_reachable: Dict[str, Set[str]] = {}
        for source in sources:
            src_id = _node_id(source)
            if src_id not in self.graph:
                continue
            reachable: Set[str] = set()
            queue = [(src_id, 0)]
            visited: Set[str] = set()
            while queue:
                node, depth = queue.pop(0)
                if node in visited or depth > max_length:
                    continue
                visited.add(node)
                if node in sink_graph_ids:
                    reachable.add(node)
                for neighbor in self.graph.neighbors(node):
                    if neighbor not in visited:
                        queue.append((neighbor, depth + 1))
            source_reachable[src_id] = reachable

        skipped = 0
        candidate_pairs: List[Tuple[Tuple[object, ...], Source, Sink]] = []
        for source in sources:
            src_id = _node_id(source)
            reachable = source_reachable.get(src_id, set())
            for sink in sinks:
                sink_id = _node_id(sink)
                if sink_id not in reachable:
                    skipped += 1
                    continue
                # Skip cross-method pairs: if both have function_name set
                # and they differ, these variables are in different scopes.
                # Only apply within the same file — cross-file pairs are allowed.
                src_func = getattr(source.location, "function_name", None)
                sink_func = getattr(sink.location, "function_name", None)
                src_file = getattr(source.location, "file_path", "")
                sink_file = getattr(sink.location, "file_path", "")
                if (src_func and sink_func and src_func != sink_func
                        and src_file and sink_file and src_file == sink_file):
                    logger.debug(
                        f"Skipping cross-method pair: {source.variable_name} "
                        f"({src_func}) -> {sink.variable_name} ({sink_func})"
                    )
                    continue

                candidate_pairs.append(
                    (candidate_pair_priority(source, sink), source, sink)
                )

        candidate_pairs.sort(key=lambda item: item[0], reverse=True)
        self.candidate_pairs_ranked = len(candidate_pairs)
        self.reachable_pairs_seen = len(candidate_pairs)

        for pair_index, (_, source, sink) in enumerate(candidate_pairs):
            src_id = _node_id(source)
            sink_id = _node_id(sink)
            logger.debug(f"Checking path: {src_id} -> {sink_id}")

            path_nodes = self.find_path(src_id, sink_id, max_length)

            if path_nodes:
                # Filter self-loops: a single-node path means
                # source and sink map to the same graph node
                # — no actual data flow exists.
                if len(path_nodes) <= 1:
                    logger.debug(
                        f"Skipping self-loop chain: {src_id} "
                        f"(path length {len(path_nodes)})"
                    )
                    continue

                # Create TaintChain from path
                chain = self._create_chain_from_path(
                    source, sink, path_nodes, sanitizers or [], self.graph
                )
                chains.append(chain)
                logger.debug(f"Found chain: {src_id} -> {sink_id}")
                if max_chains and len(chains) >= max_chains:
                    self.ranked_out_count = len(candidate_pairs) - pair_index - 1
                    self.limit_exceeded = self.ranked_out_count > 0
                    if self.limit_exceeded:
                        logger.warning(
                            "Global top-k candidate selection retained "
                            f"{max_chains} of {len(candidate_pairs)} ranked "
                            "graph-reachable endpoint pairs"
                        )
                    break

        if skipped:
            logger.debug(f"Skipped {skipped} unreachable source-sink pairs via pre-filter")
        logger.info(f"Found {len(chains)} taint chains total")
        return chains

    @staticmethod
    def _create_chain_from_path(
        source: Source,
        sink: Sink,
        path_nodes: List[str],
        sanitizers: Optional[List[Sanitizer]] = None,
        graph: Optional[nx.DiGraph] = None,
    ) -> TaintChain:
        """Create a TaintChain object from a path.

        Args:
            source: Source node.
            sink: Sink node.
            path_nodes: List of variable names in path.
            sanitizers: List of detected sanitizers to check against this chain.

        Returns:
            TaintChain object.
        """
        # Create PathNode objects for each variable in the path
        path_objs: List[PathNode] = []

        for i, node_name in enumerate(path_nodes):
            if i == 0:
                # First node is the source
                node_type = "source"
                location = source.location
                code_snippet = source.code_snippet
                display_name = source.variable_name
            elif i == len(path_nodes) - 1:
                # Last node is the sink
                node_type = "sink"
                location = sink.location
                code_snippet = sink.code_snippet
                display_name = sink.variable_name
            else:
                if graph is not None:
                    display_name = _display_node_name(graph, node_name)
                    from_endpoint = graph.has_edge(path_nodes[i - 1], node_name) and (
                        graph[path_nodes[i - 1]][node_name].get("edge_type")
                        == "endpoint_binding"
                    )
                    to_endpoint = graph.has_edge(node_name, path_nodes[i + 1]) and (
                        graph[node_name][path_nodes[i + 1]].get("edge_type")
                        == "endpoint_binding"
                    )
                    if (
                        from_endpoint and display_name == source.variable_name
                    ) or (to_endpoint and display_name == sink.variable_name):
                        continue
                    path_objs.append(
                        _intermediate_path_node(
                            graph,
                            node_name,
                            path_nodes[i - 1],
                            path_nodes[i + 1],
                            source.location,
                        )
                    )
                    continue
                # Single-file compatibility for callers that create chains
                # without retaining the graph. Keep known source scope, but do
                # not invent a line number.
                node_type = "intermediate"
                location = source.location.model_copy()
                code_snippet = ""
                display_name = node_name.rsplit(":", 1)[-1]

            path_obj = PathNode(
                location=location,
                variable_name=display_name,
                node_type=node_type,
                code_snippet=code_snippet,
            )
            path_objs.append(path_obj)

        # Create TaintChain
        chain_id = stable_chain_id(source, sink, path_nodes)

        # Calculate confidence as average of source and sink confidence
        confidence = (source.confidence + sink.confidence) / 2.0

        # Find sanitizers relevant to this chain
        vuln_type = sink.vulnerability_type.value
        matching_sanitizers: List[Sanitizer] = []
        if sanitizers:
            src_line = source.location.line_number
            sink_line = sink.location.line_number
            min_line = min(src_line, sink_line)
            max_line = max(src_line, sink_line)

            # Collect chain variable names for variable-aware matching
            chain_vars = {source.variable_name, sink.variable_name}
            for node_name in path_nodes:
                display = (
                    _display_node_name(graph, node_name)
                    if graph is not None
                    else node_name.rsplit(":", 1)[-1]
                )
                chain_vars.add(display)

            for san in sanitizers:
                # Allow sanitizers slightly beyond the sink (e.g. setString
                # after prepareStatement on the next line)
                in_range = min_line <= san.location.line_number <= max_line + 5
                # Also allow if sanitizer explicitly references source variable
                refs_source = (
                    san.effectiveness >= 0.9
                    and source.variable_name
                    and len(source.variable_name) > 1
                    and source.variable_name in san.code_snippet
                )
                if not in_range and not refs_source:
                    continue
                # Match by vulnerability type
                if vuln_type in san.vulnerability_types:
                    matching_sanitizers.append(san)
                # Or match by variable name in sanitizer code (handles misclassification)
                elif san.effectiveness >= 0.9 and any(
                    v in san.code_snippet for v in chain_vars if len(v) > 1
                ):
                    matching_sanitizers.append(san)

            if matching_sanitizers:
                logger.debug(
                    f"Found {len(matching_sanitizers)} sanitizers on path "
                    f"{source.variable_name} -> {sink.variable_name}"
                )

        chain = TaintChain(
            id=chain_id,
            source=source,
            sink=sink,
            path=path_objs,
            length=len(path_objs),
            confidence=confidence,
            vulnerability_type=sink.vulnerability_type,
            sanitizers_on_path=matching_sanitizers,
            verification_status=None,
        )

        logger.debug(f"Created chain {chain_id} with {len(path_objs)} nodes")
        return chain
