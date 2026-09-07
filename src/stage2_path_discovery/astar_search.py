"""A* pathfinding with semantic heuristics using CodeBERT embeddings."""

import heapq
import os
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx
import numpy as np

from src.core.models import Source, Sink, Sanitizer, TaintChain, PathNode, CodeLocation
from src.utils.logger import get_logger

logger = get_logger()

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.warning("sentence-transformers not available, using fallback heuristic")


class SemanticHeuristic:
    """Computes semantic distances between variables using CodeBERT embeddings.

    Uses sentence-transformers with the CodeBERT model to compute embeddings
    of variable names and their contexts, then uses cosine distance as heuristic.
    """

    _model_cache: Dict[str, object] = {}
    _failed_models: Set[str] = set()

    def __init__(self, model_name: str = "microsoft/codebert-base") -> None:
        """Initialize semantic heuristic with CodeBERT model.

        Args:
            model_name: Name of sentence-transformers model to use.

        Raises:
            RuntimeError: If sentence-transformers is not available.
        """
        self.embedding_cache: Dict[str, np.ndarray] = {}

        if not SENTENCE_TRANSFORMERS_AVAILABLE:
            logger.warning("sentence-transformers not available, using fallback heuristic")
            self.model = None
            return

        if os.getenv("VTC_USE_CODEBERT", "false").lower() not in (
            "true", "1", "yes", "on"
        ):
            self.model = None
            logger.debug(
                "CodeBERT disabled; using deterministic lightweight heuristic"
            )
            return

        if model_name in self._model_cache:
            self.model = self._model_cache[model_name]
        elif model_name in self._failed_models:
            self.model = None
        else:
            try:
                self.model = SentenceTransformer(model_name)
                self._model_cache[model_name] = self.model
                logger.info(f"Loaded semantic heuristic model: {model_name}")
            except Exception as e:
                self._failed_models.add(model_name)
                logger.warning(
                    f"Failed to load semantic model: {str(e)}, using fallback"
                )
                self.model = None

    def get_embedding(self, variable_name: str, context: Optional[str] = None) -> np.ndarray:
        """Get embedding for a variable, with caching.

        Args:
            variable_name: Name of the variable.
            context: Optional context string (type, usage, etc.).

        Returns:
            Embedding vector (numpy array).
        """
        # Check cache first
        cache_key = f"{variable_name}:{context}"
        if cache_key in self.embedding_cache:
            return self.embedding_cache[cache_key]

        if self.model is None:
            # Return fixed-size fallback: hash-based embedding (deterministic, simple)
            # Use fixed dimension to ensure all embeddings have same shape
            dim = 64
            fallback = np.zeros(dim, dtype=np.float32)
            for i, c in enumerate(variable_name):
                fallback[i % dim] += hash(c) % 256
            self.embedding_cache[cache_key] = fallback
            return fallback

        # Build text to embed
        text_to_embed = variable_name
        if context:
            text_to_embed = f"{variable_name} {context}"

        try:
            # Get embedding from model
            embedding = self.model.encode(text_to_embed, convert_to_numpy=True)
            # Cache it
            self.embedding_cache[cache_key] = embedding
            return embedding
        except Exception as e:
            logger.debug(f"Error computing embedding: {str(e)}, using fallback")
            dim = 64
            fallback = np.zeros(dim, dtype=np.float32)
            for i, c in enumerate(variable_name):
                fallback[i % dim] += hash(c) % 256
            self.embedding_cache[cache_key] = fallback
            return fallback

    def compute_distance(
        self, var1: str, var2: str, context1: Optional[str] = None, context2: Optional[str] = None
    ) -> float:
        """Compute semantic distance between two variables using cosine distance.

        Args:
            var1: First variable name.
            var2: Second variable name.
            context1: Optional context for first variable.
            context2: Optional context for second variable.

        Returns:
            Distance value (0.0 to 2.0, where 0 is identical, 1.0 is orthogonal).
        """
        if var1 == var2 and context1 == context2:
            return 0.0

        emb1 = self.get_embedding(var1, context1)
        emb2 = self.get_embedding(var2, context2)

        # Compute cosine distance
        # Avoid division by zero
        norm1 = np.linalg.norm(emb1)
        norm2 = np.linalg.norm(emb2)

        if norm1 == 0 or norm2 == 0:
            return 0.0 if np.array_equal(emb1, emb2) else 1.0

        # Cosine similarity = dot product / (norm1 * norm2)
        cosine_similarity = np.dot(emb1, emb2) / (norm1 * norm2)

        # Convert similarity to distance (1 - similarity), bounded to [0, 1]
        distance = max(0.0, min(1.0, 1.0 - cosine_similarity))
        return distance

    def clear_cache(self) -> None:
        """Clear the embedding cache to free memory."""
        self.embedding_cache.clear()
        logger.debug("Cleared semantic heuristic embedding cache")


class AStarPathFinder:
    """Finds optimal paths using A* algorithm with semantic heuristics.

    Uses A* search with:
    - g(n): actual cost from start (path length)
    - h(n): heuristic estimate to goal (semantic distance)
    - f(n) = g(n) + h(n): total estimated cost

    The semantic heuristic provides better guidance than simple distance,
    considering data type and variable relationships.
    """

    def __init__(
        self,
        graph: nx.DiGraph,
        semantic_heuristic: Optional[SemanticHeuristic] = None,
        use_semantic: bool = True,
    ) -> None:
        """Initialize A* path finder.

        Args:
            graph: NetworkX DiGraph representing data flow.
            semantic_heuristic: Optional SemanticHeuristic instance.
            use_semantic: Whether to use semantic heuristic or simple distance.
        """
        self.graph = graph
        self.use_semantic = use_semantic

        if semantic_heuristic is None:
            self.heuristic = SemanticHeuristic() if use_semantic else None
        else:
            self.heuristic = semantic_heuristic

        logger.debug(
            f"Initialized AStarPathFinder with {graph.number_of_nodes()} nodes, "
            f"semantic={'enabled' if use_semantic else 'disabled'}"
        )

    def find_path(
        self,
        source_node: str,
        sink_node: str,
        max_length: int = 15,
        function_name: Optional[str] = None,
    ) -> Optional[List[str]]:
        """Find optimal path from source to sink using A*.

        Args:
            source_node: Starting variable name.
            sink_node: Target variable name.
            max_length: Maximum path length to consider.

        Returns:
            List of variable names representing the optimal path, or None if not found.
        """
        if source_node not in self.graph or sink_node not in self.graph:
            logger.debug(f"Source or sink not in graph: {source_node}, {sink_node}")
            return None

        # Priority queue: (f_score, counter, current_node, path)
        # Counter ensures FIFO for equal f-scores
        open_set: List[Tuple[float, int, str, List[str]]] = []
        counter = 0

        # g_score: actual cost from start to current node
        g_score: Dict[str, float] = {source_node: 0.0}

        # f_score: estimated total cost
        f_score: Dict[str, float] = {source_node: self._compute_heuristic(source_node, sink_node)}

        # Visited set to avoid cycles
        visited: Set[str] = set()

        # Initial state
        heapq.heappush(
            open_set,
            (f_score[source_node], counter, source_node, [source_node]),
        )
        counter += 1

        logger.trace(f"Starting A* search from {source_node} to {sink_node}")

        while open_set:
            current_f, _, current_node, path = heapq.heappop(open_set)

            # Check if we reached the goal
            if current_node == sink_node:
                logger.info(f"A* found path of length {len(path)}: {' -> '.join(path)}")
                return path

            # Skip if already visited (cycle detection)
            if current_node in visited:
                continue

            visited.add(current_node)

            # Check path length constraint
            if len(path) > max_length:
                logger.debug(f"Path exceeds max length ({len(path)} > {max_length})")
                continue

            # Explore neighbors
            for neighbor in self.graph.neighbors(current_node):
                if neighbor in visited:
                    continue
                edge_scope = self.graph[current_node][neighbor].get("function_name")
                edge_scopes = self.graph[current_node][neighbor].get(
                    "function_names", []
                )
                if function_name:
                    if edge_scopes and function_name not in edge_scopes:
                        continue
                    if not edge_scopes and edge_scope and edge_scope != function_name:
                        continue

                # Calculate tentative g_score
                # Cost of edge is 1 plus any edge weight if present
                edge_cost = self.graph[current_node][neighbor].get("weight", 1.0)
                tentative_g = g_score[current_node] + edge_cost

                # Only consider this path if it's better than previously found
                if neighbor not in g_score or tentative_g < g_score[neighbor]:
                    g_score[neighbor] = tentative_g
                    h = self._compute_heuristic(neighbor, sink_node)
                    f = tentative_g + h
                    f_score[neighbor] = f

                    new_path = path + [neighbor]
                    heapq.heappush(
                        open_set,
                        (f, counter, neighbor, new_path),
                    )
                    counter += 1

                    logger.trace(
                        f"Exploring {current_node} -> {neighbor}: "
                        f"g={tentative_g:.2f}, h={h:.2f}, f={f:.2f}"
                    )

        logger.trace(f"No path found from {source_node} to {sink_node} using A*")
        return None

    def _find_scoped_field_path(
        self,
        source_node: str,
        sink_node: str,
        allowed_functions: Set[str],
        max_length: int,
    ) -> Optional[List[str]]:
        """Find a cross-method path constrained to its endpoint scopes."""
        if source_node not in self.graph or sink_node not in self.graph:
            return None

        queue = deque([(source_node, [source_node], False)])
        visited: Set[Tuple[str, bool]] = set()
        while queue:
            node, path, has_field_flow = queue.popleft()
            state = (node, has_field_flow)
            if state in visited or len(path) > max_length:
                continue
            visited.add(state)
            if node == sink_node and has_field_flow:
                return path

            for neighbor in self.graph.neighbors(node):
                edge = self.graph[node][neighbor]
                next_has_field = has_field_flow
                if not edge.get("bridge"):
                    edge_functions = set(edge.get("function_names", []))
                    if edge.get("function_name"):
                        edge_functions.add(edge["function_name"])
                    if not edge_functions or edge_functions.isdisjoint(
                        allowed_functions
                    ):
                        continue
                    field_functions = set(edge.get("field_flow_functions", []))
                    if not field_functions.isdisjoint(allowed_functions):
                        next_has_field = True
                queue.append((neighbor, path + [neighbor], next_has_field))
        return None

    def find_all_chains(
        self,
        sources: List[Source],
        sinks: List[Sink],
        max_length: int = 15,
        sanitizers: Optional[List[Sanitizer]] = None,
        node_id_map: Optional[Dict[int, str]] = None,
    ) -> List[TaintChain]:
        """Find all taint chains between sources and sinks using A*.

        For each (source, sink) pair, uses A* to find the optimal path based
        on semantic similarity and path length.

        Args:
            sources: List of source nodes.
            sinks: List of sink nodes.
            max_length: Maximum path length to consider.
            sanitizers: Optional list of detected sanitizers to attach to chains.
            node_id_map: Optional mapping from ``id(source/sink)`` to scoped
                graph node ID (e.g. ``"File.java:varName"``).  When *None*
                (default) the plain ``variable_name`` is used — fully
                backward-compatible with the old single-file behaviour.

        Returns:
            List of TaintChain objects representing found vulnerabilities.
        """
        chains: List[TaintChain] = []

        def _node_id(obj: object) -> str:
            if node_id_map is not None:
                return node_id_map.get(id(obj), getattr(obj, "variable_name", ""))
            return getattr(obj, "variable_name", "")

        logger.info(f"Finding optimal paths for {len(sources)} sources and {len(sinks)} sinks")

        # Pre-compute reachable sink names for each source (BFS bounded by max_length)
        sink_graph_ids = {_node_id(s) for s in sinks}
        source_reachable: Dict[str, Set[str]] = {}
        for source in sources:
            src_id = _node_id(source)
            if src_id not in self.graph:
                continue
            reachable: Set[str] = set()
            queue = deque([(src_id, 0)])
            visited: Set[str] = set()
            while queue:
                node, depth = queue.popleft()
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
        for source in sources:
            src_id = _node_id(source)
            reachable = source_reachable.get(src_id, set())
            for sink in sinks:
                sink_id = _node_id(sink)
                if sink_id not in reachable:
                    skipped += 1
                    continue
                # Same-file, cross-method flows are accepted only when the
                # discovered path crosses a declared class field. This keeps
                # legitimate setter -> renderer flows while preventing local
                # variables with identical names from collapsing scopes.
                src_func = getattr(source.location, "function_name", None)
                sink_func = getattr(sink.location, "function_name", None)
                src_file = getattr(source.location, "file_path", "")
                sink_file = getattr(sink.location, "file_path", "")
                cross_method = bool(
                    src_func and sink_func and src_func != sink_func
                    and src_file and sink_file and src_file == sink_file
                )

                logger.trace(f"A* search: {src_id} -> {sink_id}")

                pair_function = None
                if src_func and sink_func and src_func == sink_func and src_file == sink_file:
                    pair_function = src_func
                if cross_method:
                    path_nodes = self._find_scoped_field_path(
                        src_id,
                        sink_id,
                        {src_func, sink_func},
                        max_length,
                    )
                else:
                    path_nodes = self.find_path(
                        src_id,
                        sink_id,
                        max_length,
                        function_name=pair_function,
                    )

                if path_nodes:
                    cross_file = bool(
                        src_file and sink_file and src_file != sink_file
                    )
                    if cross_file and src_func:
                        bridge_functions = [
                            self.graph[left][right].get("caller_function")
                            for left, right in zip(path_nodes, path_nodes[1:])
                            if self.graph[left][right].get("bridge")
                        ]
                        if (
                            bridge_functions
                            and src_func not in bridge_functions
                        ):
                            logger.debug(
                                "Skipping cross-file path whose call bridge "
                                f"belongs to another method: {src_id} -> {sink_id}"
                            )
                            continue
                    if cross_method:
                        allowed_functions = {src_func, sink_func}
                        edges_in_scope = True
                        has_field_flow = False
                        for left, right in zip(path_nodes, path_nodes[1:]):
                            edge = self.graph[left][right]
                            if edge.get("bridge"):
                                continue
                            edge_functions = set(edge.get("function_names", []))
                            if edge.get("function_name"):
                                edge_functions.add(edge["function_name"])
                            if not edge_functions or edge_functions.isdisjoint(
                                allowed_functions
                            ):
                                edges_in_scope = False
                                break
                            field_functions = set(
                                edge.get("field_flow_functions", [])
                            )
                            if not field_functions.isdisjoint(allowed_functions):
                                has_field_flow = True
                        if not has_field_flow or not edges_in_scope:
                            logger.debug(
                                "Skipping unscoped cross-method path: "
                                f"{src_id} -> {sink_id}"
                            )
                            continue
                    # Filter self-loops: a single-node path means
                    # source and sink map to the same graph node
                    # — no actual data flow exists.
                    if len(path_nodes) <= 1:
                        logger.debug(
                            f"Skipping self-loop chain: {src_id} (path length {len(path_nodes)})"
                        )
                        continue

                    # Create TaintChain from path
                    chain = self._create_chain_from_path(
                        source, sink, path_nodes, sanitizers or []
                    )
                    chains.append(chain)
                    logger.info(f"Found optimal chain: {src_id} -> {sink_id}")

        if skipped:
            logger.debug(f"Skipped {skipped} unreachable source-sink pairs via pre-filter")
        logger.info(f"A* found {len(chains)} optimal taint chains")
        return chains

    def _compute_heuristic(self, current: str, goal: str) -> float:
        """Compute heuristic estimate of distance to goal.

        Uses semantic distance if available, otherwise simple length-based heuristic.

        Args:
            current: Current node name.
            goal: Goal node name.

        Returns:
            Heuristic value (non-negative, 0 if nodes are same).
        """
        if current == goal:
            return 0.0

        # Use semantic heuristic if available
        if self.use_semantic and self.heuristic is not None:
            try:
                # Get node type information from graph
                current_type = self.graph.nodes[current].get("var_type", "")
                goal_type = self.graph.nodes[goal].get("var_type", "")

                # Compute semantic distance
                semantic_distance = self.heuristic.compute_distance(
                    current, goal, context1=current_type, context2=goal_type
                )

                # Scale by estimated graph diameter
                # Heuristic should never overestimate actual distance
                estimated_path_length = min(10, max(1, len(self.graph) // 5))
                h_value = semantic_distance * estimated_path_length

                logger.trace(
                    f"Semantic heuristic {current} -> {goal}: distance={semantic_distance:.3f}, h={h_value:.3f}"
                )

                return h_value

            except Exception as e:
                logger.debug(f"Error computing semantic heuristic: {str(e)}, using fallback")

        # Fallback: simple distance heuristic
        # Estimate: nodes farther apart in name are likely farther in graph
        name_distance = len(set(current) ^ set(goal)) / max(len(current), len(goal), 1)
        return max(0.0, name_distance)

    @staticmethod
    def _create_chain_from_path(
        source: Source,
        sink: Sink,
        path_nodes: List[str],
        sanitizers: Optional[List[Sanitizer]] = None,
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
            # Strip scope prefix (e.g. "File.java:varName" -> "varName")
            display_name = node_name.split(":", 1)[-1] if ":" in node_name else node_name

            if i == 0:
                # First node is the source
                node_type = "source"
                location = source.location
                code_snippet = source.code_snippet
            elif i == len(path_nodes) - 1:
                # Last node is the sink
                node_type = "sink"
                location = sink.location
                code_snippet = sink.code_snippet
            else:
                # Intermediate nodes
                node_type = "intermediate"
                location = CodeLocation(
                    file_path=source.location.file_path,
                    line_number=source.location.line_number + i,
                )
                code_snippet = ""

            path_obj = PathNode(
                location=location,
                variable_name=display_name,
                node_type=node_type,
                code_snippet=code_snippet,
            )
            path_objs.append(path_obj)

        # Create TaintChain
        chain_id = f"{source.variable_name}_to_{sink.variable_name}_{id(path_nodes)}"

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
                display = node_name.split(":", 1)[-1] if ":" in node_name else node_name
                chain_vars.add(display)

            for san in sanitizers:
                san_file = san.location.file_path
                src_file = source.location.file_path
                sink_file = sink.location.file_path
                if san_file not in {src_file, sink_file}:
                    continue

                if src_file == sink_file:
                    ordered = min_line <= san.location.line_number <= max_line + 5
                elif san_file == src_file:
                    ordered = san.location.line_number >= src_line
                else:
                    ordered = san.location.line_number <= sink_line + 5
                if not ordered:
                    continue

                # Static pattern matching is not a proof unless it is tied to
                # an actual value carried by this chain.
                if not san.variable_name or san.variable_name not in chain_vars:
                    continue
                if vuln_type not in san.vulnerability_types:
                    continue
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
