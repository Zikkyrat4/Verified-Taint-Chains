"""Main pipeline orchestrator for security analysis."""

import asyncio
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

from src.core.config import PipelineConfig
from src.core.models import Source, Sink, TaintChain, SourceCategory, SinkCategory
from src.core.exceptions import TaintAnalysisError
from src.stage1_llm_inference.client_factory import create_llm_client
from src.stage1_llm_inference.specification_extractor import SimpleSpecificationExtractor
from src.stage2_path_discovery.simple_path_finder import (
    SimpleGraphBuilder,
    SimpleBFSPathFinder,
)
from src.stage2_path_discovery.graph_builder import EnhancedGraphBuilder
from src.stage2_path_discovery.llm_graph_builder import LLMGraphBuilder
from src.stage2_path_discovery.astar_search import (
    AStarPathFinder,
    SemanticHeuristic,
)
from src.stage2_path_discovery.joern_wrapper import JoernWrapper
from src.stage3_verification.simple_verifier import SimpleCFGVerifier
from src.stage3_verification.verification_engine import VerificationEngine
from src.stage4_explanation.explanation_generator import ExplanationGenerator
from src.pipeline.result import PipelineResult
from src.utils.logger import get_logger
from src.utils.progress import ProgressReporter

logger = get_logger()


class SimplePipeline:
    """Main pipeline orchestrator for multi-stage taint analysis.

    Coordinates the execution of all 4 stages:
    1. LLM-based specification extraction (sources and sinks)
    2. Graph-based path discovery (data flow paths)
    3. CFG-based verification (reachability checking)
    4. LLM-based explanation generation (human-readable output)
    """

    def __init__(self, config: PipelineConfig) -> None:
        """Initialize pipeline with configuration.

        Args:
            config: PipelineConfig instance with all settings.

        Raises:
            ValueError: If config is invalid.
        """
        if not config:
            raise ValueError("config is required")

        self.config = config

        # Initialize Stage 1 components (use factory to support multiple providers)
        self.llm_client = create_llm_client(config)

        self.spec_extractor = SimpleSpecificationExtractor(
            llm_client=self.llm_client,
            confidence_threshold=config.min_confidence,
        )

        # Stage 2-3 components initialized in run()
        self.graph_builder: Optional[Any] = None  # SimpleGraphBuilder or EnhancedGraphBuilder
        self.path_finder: Optional[Any] = None  # SimpleBFSPathFinder or AStarPathFinder
        self.semantic_heuristic: Optional[SemanticHeuristic] = None
        self.verifier: Optional[SimpleCFGVerifier] = None
        self.verification_engine: Optional[VerificationEngine] = None

        # Stage 4 components
        self.explainer = ExplanationGenerator(llm_client=self.llm_client)

        logger.info(
            f"Initialized SimplePipeline with config: "
            f"model={config.llm_model}, "
            f"max_path_length={config.max_path_length}, "
            f"min_confidence={config.min_confidence}, "
            f"pathfinding_algorithm={config.pathfinding_algorithm}, "
            f"use_joern={config.use_joern}"
        )

    async def run(self, source_file: str) -> Dict[str, Any]:
        """Execute complete pipeline on source file.

        Runs all 4 stages in sequence:
        1. Extract specifications (sources, sinks)
        2. Discover data flow paths
        3. Verify chain reachability
        4. Generate explanations

        Args:
            source_file: Path to Java source file to analyze.

        Returns:
            Dictionary containing results from all stages with metrics.

        Raises:
            TaintAnalysisError: If any stage fails critically.
            FileNotFoundError: If source file not found.
        """
        logger.info(f"Starting pipeline execution on {source_file}")

        try:
            # Read source file
            source_code = self._read_source_file(source_file)
            logger.debug(f"Read {len(source_code)} bytes from {source_file}")

            # ============ STAGE 1: LLM-based Specification Extraction ============
            logger.info("Stage 1: Extracting specifications...")

            specification = await self.spec_extractor.extract(
                source_code=source_code,
                file_path=source_file,
                model=self.config.llm_model,
            )

            sources = specification.sources
            sinks = specification.sinks
            sanitizers = specification.sanitizers

            logger.info(
                f"✓ Stage 1 complete: Found {len(sources)} sources, {len(sinks)} sinks, "
                f"{len(sanitizers)} sanitizers"
            )

            # ============ STAGES 2-4: Path Discovery, Verification, Explanation ============
            result = await self._run_stages(source_code, sources, sinks, sanitizers)
            result["file"] = source_file

            return result

        except FileNotFoundError as e:
            logger.error(f"Source file not found: {source_file}")
            raise

        except Exception as e:
            logger.error(f"Pipeline execution failed: {str(e)}")
            raise TaintAnalysisError(f"Pipeline error: {str(e)}") from e

    # Patterns that indicate a Java file may contain security-relevant code
    SECURITY_PATTERNS = [
        # HTTP input sources
        r"getParameter|getHeader|getCookies|getInputStream|getReader|getQueryString",
        r"@RequestParam|@PathVariable|@RequestBody|@RequestHeader|@CookieValue",
        r"HttpServletRequest|HttpServletResponse",
        # SQL sinks
        r"executeQuery|executeUpdate|prepareStatement|createStatement|execute\(",
        r"createNativeQuery|createQuery",
        # Command injection
        r"Runtime\.getRuntime|ProcessBuilder|exec\(",
        # XSS / output
        r"setAttribute|getRequestDispatcher|sendRedirect|addCookie|\.write\(",
        r"innerHTML|document\.write|\.html\(",
        # File / path traversal
        r"new\s+File\(|new\s+FileInputStream|Paths\.get|Files\.",
        # XXE
        r"DocumentBuilder|SAXParser|XMLReader|TransformerFactory",
        # SSRF
        r"URL\(|HttpURLConnection|HttpClient|openConnection",
        # Deserialization
        r"ObjectInputStream|readObject|XMLDecoder",
        # LDAP
        r"DirContext|InitialDirContext|search\(",
    ]

    _SECURITY_RE = re.compile("|".join(SECURITY_PATTERNS))

    @staticmethod
    def _is_security_relevant(code: str) -> bool:
        """Check if source code contains security-relevant patterns.

        Performs a fast regex scan to decide whether a file is worth
        sending to the LLM for full specification extraction.

        Args:
            code: Source code content.

        Returns:
            True if the code contains at least one security-relevant pattern.
        """
        if not code or not code.strip():
            return False
        return bool(SimplePipeline._SECURITY_RE.search(code))

    def _partition_files(
        self, java_files: List[str]
    ) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
        """Partition files into security-relevant and irrelevant.

        Reads each file and classifies it by security pattern presence.

        Args:
            java_files: List of file paths.

        Returns:
            Tuple of (relevant, irrelevant) where each is a list of
            (file_path, code) tuples.
        """
        relevant: List[Tuple[str, str]] = []
        irrelevant: List[Tuple[str, str]] = []

        for java_file in java_files:
            code = self._read_source_file(java_file)
            if self._is_security_relevant(code):
                relevant.append((java_file, code))
            else:
                irrelevant.append((java_file, code))

        logger.info(
            f"File priority: {len(relevant)}/{len(java_files)} files match known "
            f"security patterns (analyzed first); {len(irrelevant)} analyzed after"
        )
        return relevant, irrelevant

    async def run_project(
        self,
        java_files: List[str],
        show_progress: bool = False,
    ) -> Dict[str, Any]:
        """Execute pipeline in project mode with per-file graph scoping.

        Stage 1 runs per-file on security-relevant files only (concurrent).
        Stages 2-4 use *scoped* graphs so that identically-named variables
        in different files remain distinct nodes, preventing false cross-file
        taint chains.

        Args:
            java_files: List of paths to Java source files.
            show_progress: If True, render a progress bar to stderr.

        Returns:
            Dictionary containing unified results with metrics.

        Raises:
            TaintAnalysisError: If analysis fails critically.
        """
        # Apply --max-files cap if set
        if self.config.max_files > 0 and len(java_files) > self.config.max_files:
            logger.info(
                f"Capping files from {len(java_files)} to {self.config.max_files} (--max-files)"
            )
            java_files = java_files[: self.config.max_files]

        logger.info(f"Starting project-mode analysis on {len(java_files)} files")

        try:
            # Partition files by security relevance — used for ORDERING, not
            # exclusion. Analyzing only keyword-matching files blinds the
            # detector to 0-day patterns in files using unfamiliar APIs, so
            # every file is analyzed (security-matching ones first). The old
            # exclude-irrelevant behavior is opt-in via VTC_FAST_PREFILTER
            # (debug/CI only).
            relevant, irrelevant = self._partition_files(java_files)
            fast_prefilter = os.getenv(
                "VTC_FAST_PREFILTER", "false"
            ).lower() in ("true", "1", "yes", "on")
            if fast_prefilter:
                logger.info(
                    f"[fast] Excluding {len(irrelevant)} non-matching files "
                    f"from Stage 1"
                )
            else:
                relevant = relevant + irrelevant
                irrelevant = []

            # Stage 1: concurrent per-file extraction on relevant files only
            all_sources: List = []
            all_sinks: List = []
            all_sanitizers: List = []
            # Per-file maps for scoped graph building
            file_code_map: Dict[str, str] = {}
            file_sources: Dict[str, List[Source]] = {}
            file_sinks: Dict[str, List[Sink]] = {}

            max_concurrent = self.config.max_concurrent_files
            semaphore = asyncio.Semaphore(max_concurrent)
            total_relevant = len(relevant)
            completed = 0
            start_time = time.monotonic()

            progress: Optional[ProgressReporter] = None
            if show_progress and total_relevant > 0:
                progress = ProgressReporter(total_relevant, "Stage 1: Extracting specs")

            async def extract_one(
                idx: int, java_file: str, code: str
            ) -> Tuple[str, str, Any]:
                nonlocal completed
                async with semaphore:
                    elapsed = time.monotonic() - start_time
                    avg = elapsed / completed if completed > 0 else 0
                    remaining = total_relevant - completed
                    eta = f", ETA ~{avg * remaining:.0f}s" if completed > 0 else ""
                    file_name = Path(java_file).name
                    logger.info(
                        f"Stage 1 [{idx}/{total_relevant}]: "
                        f"Extracting from {file_name}... "
                        f"(avg {avg:.1f}s/file{eta})"
                    )
                    spec = await self.spec_extractor.extract(
                        source_code=code,
                        file_path=java_file,
                        model=self.config.llm_model,
                    )
                    completed += 1
                    if progress is not None:
                        progress.update()
                    return java_file, code, spec

            tasks = [
                extract_one(i, fpath, code)
                for i, (fpath, code) in enumerate(relevant, 1)
            ]
            results = await asyncio.gather(*tasks)

            if progress is not None:
                progress.finish()

            # Collect results from relevant files
            for java_file, code, spec in results:
                all_sources.extend(spec.sources)
                all_sinks.extend(spec.sinks)
                all_sanitizers.extend(spec.sanitizers)
                file_code_map[java_file] = code
                file_sources[java_file] = list(spec.sources)
                file_sinks[java_file] = list(spec.sinks)

            # Include irrelevant files' code for graph building (no LLM calls)
            for java_file, code in irrelevant:
                file_code_map[java_file] = code
                file_sources.setdefault(java_file, [])
                file_sinks.setdefault(java_file, [])

            elapsed_total = time.monotonic() - start_time
            logger.info(
                f"✓ Stage 1 complete (project): Found {len(all_sources)} sources, "
                f"{len(all_sinks)} sinks, {len(all_sanitizers)} sanitizers "
                f"across {total_relevant} relevant files "
                f"({len(irrelevant)} skipped) in {elapsed_total:.1f}s"
            )

            # Stages 2-4: scoped graph analysis
            result = await self._run_stages_project(
                file_code_map, file_sources, file_sinks,
                all_sources, all_sinks, all_sanitizers,
            )
            result["file"] = f"project ({len(java_files)} files)"
            result["files_analyzed"] = len(java_files)
            result["files_llm_extracted"] = total_relevant
            result["files_skipped"] = len(irrelevant)
            result["file_list"] = java_files

            return result

        except Exception as e:
            logger.error(f"Project-mode analysis failed: {str(e)}")
            raise TaintAnalysisError(f"Pipeline error: {str(e)}") from e

    async def collect_sinks(
        self,
        java_files: List[str],
        show_progress: bool = False,
    ) -> Dict[str, Any]:
        """Stage-1-only sink inventory across an entire project.

        Runs only Stage 1 (LLM specification extraction) on every file and
        returns the sinks it found — *without* building a graph, discovering
        taint chains, or requiring a matching source. This surfaces dangerous
        operations even when no full source→sink chain is confirmed, which is
        exactly what 0-day triage needs (chain discovery is recall-limited by
        Stage 1 also extracting the paired source).

        Filtering ("which sinks are dangerous") is left to the caller so it can
        report how many were dropped; this method returns the raw set.

        Args:
            java_files: List of paths to Java source files.
            show_progress: If True, render a progress bar to stderr.

        Returns:
            Dict with ``files_analyzed`` / ``files_llm_extracted`` /
            ``files_skipped`` and ``sinks`` — a list of ``(file_path, Sink)``
            tuples (file path taken from the extraction loop, authoritative).

        Raises:
            TaintAnalysisError: If extraction fails critically.
        """
        # Apply --max-files cap if set (mirror run_project).
        if self.config.max_files > 0 and len(java_files) > self.config.max_files:
            logger.info(
                f"Capping files from {len(java_files)} to "
                f"{self.config.max_files} (--max-files)"
            )
            java_files = java_files[: self.config.max_files]

        logger.info(f"Starting sink-inventory analysis on {len(java_files)} files")

        try:
            # Partition for ORDERING only (security-matching files first); every
            # file is analyzed unless VTC_FAST_PREFILTER opts into the old skip.
            relevant, irrelevant = self._partition_files(java_files)
            fast_prefilter = os.getenv(
                "VTC_FAST_PREFILTER", "false"
            ).lower() in ("true", "1", "yes", "on")
            if fast_prefilter:
                logger.info(
                    f"[fast] Excluding {len(irrelevant)} non-matching files "
                    f"from Stage 1"
                )
            else:
                relevant = relevant + irrelevant
                irrelevant = []

            max_concurrent = self.config.max_concurrent_files
            semaphore = asyncio.Semaphore(max_concurrent)
            total_relevant = len(relevant)
            completed = 0
            start_time = time.monotonic()

            progress: Optional[ProgressReporter] = None
            if show_progress and total_relevant > 0:
                progress = ProgressReporter(total_relevant, "Stage 1: Extracting sinks")

            async def extract_one(
                idx: int, java_file: str, code: str
            ) -> Tuple[str, Any]:
                nonlocal completed
                async with semaphore:
                    elapsed = time.monotonic() - start_time
                    avg = elapsed / completed if completed > 0 else 0
                    remaining = total_relevant - completed
                    eta = f", ETA ~{avg * remaining:.0f}s" if completed > 0 else ""
                    file_name = Path(java_file).name
                    logger.info(
                        f"Stage 1 [{idx}/{total_relevant}]: "
                        f"Extracting from {file_name}... "
                        f"(avg {avg:.1f}s/file{eta})"
                    )
                    spec = await self.spec_extractor.extract(
                        source_code=code,
                        file_path=java_file,
                        model=self.config.llm_model,
                    )
                    completed += 1
                    if progress is not None:
                        progress.update()
                    return java_file, spec

            tasks = [
                extract_one(i, fpath, code)
                for i, (fpath, code) in enumerate(relevant, 1)
            ]
            results = await asyncio.gather(*tasks)

            if progress is not None:
                progress.finish()

            collected: List[Tuple[str, Sink]] = []
            for java_file, spec in results:
                for snk in spec.sinks:
                    collected.append((java_file, snk))

            elapsed_total = time.monotonic() - start_time
            logger.info(
                f"✓ Sink inventory complete: {len(collected)} sinks across "
                f"{total_relevant} files ({len(irrelevant)} skipped) "
                f"in {elapsed_total:.1f}s"
            )

            return {
                "files_analyzed": len(java_files),
                "files_llm_extracted": total_relevant,
                "files_skipped": len(irrelevant),
                "sinks": collected,
            }

        except Exception as e:
            logger.error(f"Sink-inventory analysis failed: {str(e)}")
            raise TaintAnalysisError(f"Pipeline error: {str(e)}") from e

    async def _build_scoped_graph(
        self,
        file_code_map: Dict[str, str],
        file_sources: Dict[str, List[Source]],
        file_sinks: Dict[str, List[Sink]],
    ) -> Tuple[nx.DiGraph, Dict[int, str]]:
        """Build a merged graph with per-file scoped node names.

        Each file gets its own sub-graph built by the configured graph builder.
        Nodes are then relabelled to ``"ShortName.java:varName"`` so that
        identically-named variables in different files stay distinct.

        Cross-file bridge edges are added when the same ``variable_name``
        appears as a source output in one file and a sink input in another.

        Args:
            file_code_map: ``{file_path: source_code}``.
            file_sources: ``{file_path: [Source, ...]}``.
            file_sinks: ``{file_path: [Sink, ...]}``.

        Returns:
            ``(merged_graph, scope_map)`` where *scope_map* maps
            ``id(source_or_sink_obj)`` to the scoped node name used in
            the merged graph.
        """
        use_llm_builder = self.config.use_llm_graph_builder

        # Choose the right builder class (don't touch Joern — it builds its own)
        if not use_llm_builder:
            if self.config.pathfinding_algorithm == "astar":
                builder_cls = EnhancedGraphBuilder
            else:
                builder_cls = SimpleGraphBuilder

        # Detect duplicate short names so we can disambiguate
        short_names: Dict[str, List[str]] = {}
        for fpath in file_code_map:
            short = Path(fpath).name
            short_names.setdefault(short, []).append(fpath)

        def _short_name(fpath: str) -> str:
            short = Path(fpath).name
            if len(short_names.get(short, [])) > 1:
                return f"{Path(fpath).parent.name}/{short}"
            return short

        graphs: List[nx.DiGraph] = []
        scope_map: Dict[int, str] = {}  # id(Source/Sink obj) -> scoped node id

        for fpath, code in file_code_map.items():
            sources_f = file_sources.get(fpath, [])
            sinks_f = file_sinks.get(fpath, [])

            if use_llm_builder:
                builder = LLMGraphBuilder(
                    llm_client=self.llm_client, config=self.config
                )
                g = builder.build_graph(code, sources_f, sinks_f)
                g = await builder.enrich_graph(g, code, sources_f, sinks_f)
            else:
                builder = builder_cls()
                g = builder.build_graph(code, sources_f, sinks_f)

            prefix = _short_name(fpath)
            mapping = {n: f"{prefix}:{n}" for n in g.nodes()}
            g = nx.relabel_nodes(g, mapping)

            # Record scoped IDs for source/sink objects
            for src in sources_f:
                scope_map[id(src)] = f"{prefix}:{src.variable_name}"
            for snk in sinks_f:
                scope_map[id(snk)] = f"{prefix}:{snk.variable_name}"

            graphs.append(g)

        if graphs:
            merged = nx.compose_all(graphs)
        else:
            merged = nx.DiGraph()

        # Add cross-file bridge edges where same variable_name is a source
        # output in one file and a sink input in another.
        src_by_var: Dict[str, List[Tuple[str, Source]]] = {}
        snk_by_var: Dict[str, List[Tuple[str, Sink]]] = {}
        for fpath, sources_f in file_sources.items():
            for src in sources_f:
                src_by_var.setdefault(src.variable_name, []).append((fpath, src))
        for fpath, sinks_f in file_sinks.items():
            for snk in sinks_f:
                snk_by_var.setdefault(snk.variable_name, []).append((fpath, snk))

        for var_name in set(src_by_var) & set(snk_by_var):
            for src_fpath, src_obj in src_by_var[var_name]:
                for snk_fpath, snk_obj in snk_by_var[var_name]:
                    if src_fpath == snk_fpath:
                        continue  # same file — already connected inside the graph
                    src_node = scope_map[id(src_obj)]
                    snk_node = scope_map[id(snk_obj)]
                    if src_node in merged and snk_node in merged:
                        merged.add_edge(src_node, snk_node, weight=1.0, bridge=True)
                        logger.debug(
                            f"Bridge edge: {src_node} -> {snk_node}"
                        )

        # Bridge 2 (parameter pass-through): a source variable in file A often
        # re-appears as a same-named formal parameter in file B (inheritance /
        # delegation — a subclass passes ``fullName`` into
        # ``super.execute(file, fullName, ..)`` and the base method then builds
        # ``new File(dir, fullName)`` assigned to ``uploadedFile``). Bridge 1
        # only fires when the *same name* is also a sink in B; when B's sink is
        # the assignment target (``uploadedFile``) the cross-file flow is lost.
        # Connect the source to B's same-named node when that node actually
        # propagates onward (out-degree > 0), so taint reaches B's own sinks.
        # Restricted to source variables to bound the number of false bridges.
        bridged = set()
        for var_name, occurrences in src_by_var.items():
            for src_fpath, src_obj in occurrences:
                src_node = scope_map[id(src_obj)]
                if src_node not in merged:
                    continue
                for bfpath in file_code_map:
                    if bfpath == src_fpath:
                        continue
                    b_node = f"{_short_name(bfpath)}:{var_name}"
                    if b_node == src_node or (src_node, b_node) in bridged:
                        continue
                    if b_node in merged and merged.out_degree(b_node) > 0:
                        merged.add_edge(src_node, b_node, weight=1.0, bridge=True)
                        bridged.add((src_node, b_node))
                        logger.debug(f"Param bridge edge: {src_node} -> {b_node}")

        logger.info(
            f"Scoped graph: {merged.number_of_nodes()} nodes, "
            f"{merged.number_of_edges()} edges across {len(file_code_map)} files"
        )
        return merged, scope_map

    async def _run_stages_project(
        self,
        file_code_map: Dict[str, str],
        file_sources: Dict[str, List[Source]],
        file_sinks: Dict[str, List[Sink]],
        all_sources: List,
        all_sinks: List,
        all_sanitizers: List,
    ) -> Dict[str, Any]:
        """Run Stages 2-4 with per-file scoped graph.

        Uses ``_build_scoped_graph`` to create a merged graph with
        file-scoped node names, then runs path discovery and verification
        using the ``node_id_map`` to resolve scoped lookups.

        Args:
            file_code_map: ``{file_path: code}``.
            file_sources / file_sinks: per-file Source/Sink lists.
            all_sources / all_sinks / all_sanitizers: flat merged lists.

        Returns:
            Dictionary with verified_chains, explanations, metrics, total_chains.
        """
        # ============ STAGE 2: Graph-based Path Discovery ============
        logger.info(
            f"Stage 2: Building scoped graph and discovering paths "
            f"(algorithm: {self.config.pathfinding_algorithm})..."
        )

        graph, scope_map = await self._build_scoped_graph(
            file_code_map, file_sources, file_sinks,
        )

        # Find all chains using selected algorithm
        if self.config.pathfinding_algorithm == "astar":
            if self.config.use_semantic_heuristic:
                self.semantic_heuristic = SemanticHeuristic()
                self.path_finder = AStarPathFinder(
                    graph,
                    semantic_heuristic=self.semantic_heuristic,
                    use_semantic=True,
                )
            else:
                self.path_finder = AStarPathFinder(graph, use_semantic=False)
        else:
            self.path_finder = SimpleBFSPathFinder(graph)

        chains = self.path_finder.find_all_chains(
            sources=all_sources,
            sinks=all_sinks,
            max_length=self.config.max_path_length,
            sanitizers=all_sanitizers,
            node_id_map=scope_map,
        )

        # Drop hallucinated chains whose snippets don't match the variable name
        chains = self._filter_low_quality_chains(chains)

        # Deduplicate chains
        chains = self._deduplicate_chains(chains)

        # Adjust confidence based on source/sink categories
        chains = self._adjust_chain_confidence(chains, self.config.min_confidence)

        logger.info(f"✓ Stage 2 complete: Found {len(chains)} taint chains")

        # ============ STAGE 3: Verification ============
        if self.config.verification_enabled and chains:
            if self.config.verification_level in ("symbolic", "both"):
                logger.info(
                    f"Stage 3: Verifying chains with verification_level="
                    f"'{self.config.verification_level}' "
                    f"(timeout={self.config.symbolic_timeout}s)..."
                )
                combined_code = "\n".join(file_code_map.values())
                self.verification_engine = VerificationEngine(
                    config=self.config,
                    max_loop_iterations=10,
                    symbolic_timeout=self.config.symbolic_timeout,
                )
                verification_results = self.verification_engine.verify_all_chains(
                    chains, combined_code,
                )
            else:  # cfg
                logger.info("Stage 3: Verifying chain reachability with CFG...")
                self.verifier = SimpleCFGVerifier(graph)
                verification_results = self.verifier.verify_all_chains(
                    chains, node_id_map=scope_map,
                )

            verified_chains = verification_results["verified"]
            verification_rate = verification_results["verification_rate"]

            if "unverifiable" in verification_results:
                unverifiable_count = len(verification_results["unverifiable"])
                if unverifiable_count > 0:
                    logger.info(
                        f"  ({unverifiable_count} chains unverifiable - "
                        f"set verification_level='symbolic' or 'both' "
                        f"for higher confidence)"
                    )

            logger.info(
                f"✓ Stage 3 complete: {len(verified_chains)} chains verified "
                f"({verification_rate:.1%})"
            )
        else:
            verified_chains = chains
            logger.info("Stage 3: Verification disabled, using all chains")

        # ============ STAGE 4: Explanation Generation ============
        if verified_chains:
            logger.info("Stage 4: Generating explanations...")
            explanations = self.explainer.generate_explanations_batch(verified_chains)
            logger.info(
                f"✓ Stage 4 complete: Generated {len(explanations)} explanations"
            )
        else:
            explanations = {}
            logger.info("Stage 4: No chains to explain")

        # ============ Compile Results ============
        metrics = {
            "sources_found": len(all_sources),
            "sinks_found": len(all_sinks),
            "sanitizers_found": len(all_sanitizers),
            "chains_found": len(chains),
            "chains_verified": len(verified_chains),
            "verification_rate": (
                len(verified_chains) / len(chains) if chains else 0.0
            ),
            "explanations_generated": len(explanations),
            "graph_nodes": graph.number_of_nodes(),
            "graph_edges": graph.number_of_edges(),
        }

        result = {
            "total_chains": len(chains),
            "verified_chains": verified_chains,
            "explanations": explanations,
            "metrics": metrics,
        }

        logger.info("✓ Pipeline execution completed successfully")
        logger.info(f"Summary: {len(chains)} chains, {len(verified_chains)} verified")

        return result

    @staticmethod
    def _filter_low_quality_chains(chains: List[TaintChain]) -> List[TaintChain]:
        """Drop chains where BOTH source and sink snippets fail to mention their variables.

        When the LLM hallucinates line numbers, the populated ``code_snippets``
        end up unrelated to the reported variables on **both** sides
        (e.g., ``source: var='samlRequest' snip='SAML2Object samlObject = ...'``
        paired with ``sink: var='issuerNameId' snip='event.detail(...)'``).
        Such chains escape category classification (both fall back to UNKNOWN)
        and bypass the risk-matrix multiplier.

        The check is conservative — only drops a chain when **both** sides
        mismatch — to avoid penalising legitimate cases where the source
        variable is declared on a function signature line but used a few
        lines below.
        """
        kept: List[TaintChain] = []
        dropped = 0
        for chain in chains:
            src_var = (chain.source.variable_name or "").strip()
            sink_var = (chain.sink.variable_name or "").strip()
            src_snip = (chain.source.code_snippet or "").strip()
            sink_snip = (chain.sink.code_snippet or "").strip()

            src_bad = bool(src_snip) and len(src_var) > 1 and src_var not in src_snip
            sink_bad = bool(sink_snip) and len(sink_var) > 1 and sink_var not in sink_snip

            if src_bad and sink_bad:
                dropped += 1
                logger.info(
                    f"Filtered hallucinated chain: src='{src_var}' / sink='{sink_var}' "
                    f"both snippets unrelated to variable names"
                )
                continue
            kept.append(chain)

        if dropped > 0:
            logger.info(f"Quality filter: removed {dropped} chains with mismatched snippets")
        return kept

    @staticmethod
    def _deduplicate_chains(chains: List[TaintChain]) -> List[TaintChain]:
        """Remove duplicate chains, keeping the most precise one.

        Two chains are considered duplicates only when they share the same
        ``(source_var, source_file, source_line, sink_var, sink_file, sink_line,
        vulnerability_type)``. Including file/line guarantees that two
        identically-named variables in different methods or files are not
        collapsed into one — that previously caused both false negatives
        (real vulns dropped) and inflated false positives (collisions
        promoting weaker chains).

        When duplicates are detected, the chain with the **shortest path** is
        preferred (shorter = fewer transformations between source and sink =
        usually a more direct flow). Confidence is the tiebreaker.

        Args:
            chains: List of TaintChain objects.

        Returns:
            De-duplicated list of TaintChain objects.
        """
        def _loc(component: Any) -> Tuple[str, int]:
            location = getattr(component, "location", None)
            return (
                getattr(location, "file_path", "") or "",
                getattr(location, "line_number", 0) or 0,
            )

        best: Dict[tuple, TaintChain] = {}
        for chain in chains:
            src_file, src_line = _loc(chain.source)
            sink_file, sink_line = _loc(chain.sink)
            key = (
                chain.source.variable_name,
                src_file,
                src_line,
                chain.sink.variable_name,
                sink_file,
                sink_line,
                chain.vulnerability_type,
            )
            existing = best.get(key)
            if existing is None:
                best[key] = chain
                continue
            # Tie-break: shorter path wins, then higher confidence
            new_len = len(chain.path) if chain.path else 0
            old_len = len(existing.path) if existing.path else 0
            if new_len < old_len or (
                new_len == old_len and chain.confidence > existing.confidence
            ):
                best[key] = chain

        deduped = list(best.values())
        removed = len(chains) - len(deduped)
        if removed > 0:
            logger.info(f"Deduplication: removed {removed} duplicate chains")

        # Secondary pass — collapse `same-source-name × same-sink-name × same-vuln`
        # chains that differ only in line numbers. SAML/HTML-render code declares
        # the same parameter name (`artifact`, `samlRequest`, ...) in 5+ method
        # signatures; each of those flows to the same logical sink (`samlClient`,
        # `response`, ...) called from many call-sites. Without this collapse a
        # single logical flow inflates into N×M near-identical chains in the
        # unclassified bucket. Within the same file, we treat them as one flow
        # and keep the shortest / most confident representative.
        coalesced: Dict[tuple, TaintChain] = {}
        for chain in deduped:
            src_file, _src_line = _loc(chain.source)
            sink_file, _sink_line = _loc(chain.sink)
            key = (
                chain.source.variable_name,
                src_file,
                chain.sink.variable_name,
                sink_file,
                chain.vulnerability_type,
            )
            existing = coalesced.get(key)
            if existing is None:
                coalesced[key] = chain
                continue
            new_len = len(chain.path) if chain.path else 0
            old_len = len(existing.path) if existing.path else 0
            if new_len < old_len or (
                new_len == old_len and chain.confidence > existing.confidence
            ):
                coalesced[key] = chain

        coalesced_chains = list(coalesced.values())
        coalesced_removed = len(deduped) - len(coalesced_chains)
        if coalesced_removed > 0:
            logger.info(
                f"Secondary dedup: collapsed {coalesced_removed} sink-line "
                f"duplicates"
            )

        # Hub-node filter: drop chains whose path travels through framework
        # container objects (session, responseBuilder, ...) AS INTERMEDIATE
        # nodes. These are class fields shared across every method body —
        # path discovery routes spurious cross-method "flows" through them
        # because the graph treats them as connectors. Endpoint usage
        # (source or sink) is fine; only the intermediate role is suspect.
        # Generic shared-connector field names common to many Java web/MVC
        # frameworks (not specific to any product).
        _HUB_NODES = frozenset({
            "session", "responseBuilder", "clientSession", "clientSessionCtx",
            "userSession", "event", "auditEvent", "context", "builder",
        })
        kept: List[TaintChain] = []
        hub_dropped = 0
        for chain in coalesced_chains:
            path = chain.path or []
            if len(path) >= 4:
                # `path` is List[PathNode]; PathNode has .variable_name
                names = [
                    getattr(n, "variable_name", None) or str(n)
                    for n in path
                ]
                intermediates = names[1:-1]
                if any(name in _HUB_NODES for name in intermediates):
                    hub_dropped += 1
                    continue
            kept.append(chain)
        if hub_dropped > 0:
            logger.info(
                f"Hub-node filter: dropped {hub_dropped} chains routed "
                f"through framework containers"
            )
        return kept

    # Confidence multiplier matrix: (SourceCategory, SinkCategory) -> multiplier
    #
    # New columns: EVENT_LOGGING (audit/logger calls — almost never a real sink),
    # BENIGN (Base64 encode, StringBuilder, etc. — never a sink for taint).
    # Lowered (INTERNAL_API|SESSION_DATA, FRAMEWORK_API) to filter framework
    # constructors/setters that previously squeaked through.
    _RISK_MATRIX = {
        # user_input → highest risk
        (SourceCategory.USER_INPUT, SinkCategory.DIRECT_EXECUTION): 1.0,
        (SourceCategory.USER_INPUT, SinkCategory.OUTPUT_RENDERING): 1.0,
        (SourceCategory.USER_INPUT, SinkCategory.RESOURCE_ACCESS): 1.0,
        (SourceCategory.USER_INPUT, SinkCategory.DATA_STORAGE): 0.7,
        (SourceCategory.USER_INPUT, SinkCategory.FRAMEWORK_API): 0.5,
        (SourceCategory.USER_INPUT, SinkCategory.EVENT_LOGGING): 0.15,
        (SourceCategory.USER_INPUT, SinkCategory.BENIGN): 0.05,
        # external_data → high risk
        (SourceCategory.EXTERNAL_DATA, SinkCategory.DIRECT_EXECUTION): 0.9,
        (SourceCategory.EXTERNAL_DATA, SinkCategory.OUTPUT_RENDERING): 0.85,
        (SourceCategory.EXTERNAL_DATA, SinkCategory.RESOURCE_ACCESS): 0.9,
        (SourceCategory.EXTERNAL_DATA, SinkCategory.DATA_STORAGE): 0.7,
        (SourceCategory.EXTERNAL_DATA, SinkCategory.FRAMEWORK_API): 0.4,
        (SourceCategory.EXTERNAL_DATA, SinkCategory.EVENT_LOGGING): 0.1,
        (SourceCategory.EXTERNAL_DATA, SinkCategory.BENIGN): 0.05,
        # session_data → medium risk
        (SourceCategory.SESSION_DATA, SinkCategory.DIRECT_EXECUTION): 0.6,
        (SourceCategory.SESSION_DATA, SinkCategory.OUTPUT_RENDERING): 0.55,
        (SourceCategory.SESSION_DATA, SinkCategory.RESOURCE_ACCESS): 0.5,
        (SourceCategory.SESSION_DATA, SinkCategory.DATA_STORAGE): 0.3,
        (SourceCategory.SESSION_DATA, SinkCategory.FRAMEWORK_API): 0.10,
        (SourceCategory.SESSION_DATA, SinkCategory.EVENT_LOGGING): 0.05,
        (SourceCategory.SESSION_DATA, SinkCategory.BENIGN): 0.03,
        # internal_api → low risk (catch-all when classifier doesn't match)
        (SourceCategory.INTERNAL_API, SinkCategory.DIRECT_EXECUTION): 0.5,
        (SourceCategory.INTERNAL_API, SinkCategory.OUTPUT_RENDERING): 0.4,
        (SourceCategory.INTERNAL_API, SinkCategory.RESOURCE_ACCESS): 0.4,
        (SourceCategory.INTERNAL_API, SinkCategory.DATA_STORAGE): 0.2,
        (SourceCategory.INTERNAL_API, SinkCategory.FRAMEWORK_API): 0.08,
        (SourceCategory.INTERNAL_API, SinkCategory.EVENT_LOGGING): 0.03,
        (SourceCategory.INTERNAL_API, SinkCategory.BENIGN): 0.02,
        # database → low risk
        (SourceCategory.DATABASE, SinkCategory.DIRECT_EXECUTION): 0.5,
        (SourceCategory.DATABASE, SinkCategory.OUTPUT_RENDERING): 0.5,
        (SourceCategory.DATABASE, SinkCategory.RESOURCE_ACCESS): 0.4,
        (SourceCategory.DATABASE, SinkCategory.DATA_STORAGE): 0.2,
        (SourceCategory.DATABASE, SinkCategory.FRAMEWORK_API): 0.15,
        (SourceCategory.DATABASE, SinkCategory.EVENT_LOGGING): 0.05,
        (SourceCategory.DATABASE, SinkCategory.BENIGN): 0.02,
    }

    @staticmethod
    def _adjust_chain_confidence(
        chains: List[TaintChain], min_confidence: float
    ) -> List[TaintChain]:
        """Adjust chain confidence based on source/sink category risk matrix.

        Multiplies chain confidence by a risk factor determined by the
        source and sink categories. Chains that fall below min_confidence
        after adjustment are filtered out.

        Args:
            chains: List of TaintChain objects.
            min_confidence: Minimum confidence threshold.

        Returns:
            Filtered list of TaintChain objects with adjusted confidence.
        """
        adjusted = []
        for chain in chains:
            src_cat = getattr(chain.source, "source_category", None) or SourceCategory.UNKNOWN
            sink_cat = getattr(chain.sink, "sink_category", None) or SinkCategory.UNKNOWN

            # UNKNOWN categories get no penalty (backward-compatible)
            if src_cat == SourceCategory.UNKNOWN or sink_cat == SinkCategory.UNKNOWN:
                multiplier = 1.0
            else:
                multiplier = SimplePipeline._RISK_MATRIX.get((src_cat, sink_cat), 0.8)

            new_confidence = chain.confidence * multiplier
            if new_confidence >= min_confidence:
                chain.confidence = new_confidence
                adjusted.append(chain)
            else:
                logger.info(
                    f"Filtered low-risk chain: {chain.source.variable_name} -> "
                    f"{chain.sink.variable_name} ({src_cat.value} -> {sink_cat.value}, "
                    f"confidence {chain.confidence:.2f} * {multiplier} = {new_confidence:.2f})"
                )
        filtered = len(chains) - len(adjusted)
        if filtered > 0:
            logger.info(
                f"Category filter: removed {filtered} low-risk chains "
                f"(below {min_confidence} after adjustment)"
            )
        return adjusted

    async def _run_stages(
        self,
        source_code: str,
        sources: List,
        sinks: List,
        sanitizers: List,
    ) -> Dict[str, Any]:
        """Run Stages 2-4 on already-extracted specs.

        Args:
            source_code: Source code to analyze (single file or concatenated).
            sources: List of Source objects.
            sinks: List of Sink objects.
            sanitizers: List of Sanitizer objects.

        Returns:
            Dictionary with verified_chains, explanations, metrics, total_chains.
        """
        # ============ STAGE 2: Graph-based Path Discovery ============
        logger.info(
            f"Stage 2: Building graph and discovering paths "
            f"(algorithm: {self.config.pathfinding_algorithm})..."
        )

        # Build control/data flow graph
        if self.config.use_llm_graph_builder:
            logger.debug("Using LLMGraphBuilder (AST + LLM enrichment)")
            self.graph_builder = LLMGraphBuilder(
                llm_client=self.llm_client, config=self.config
            )
            graph = self.graph_builder.build_graph(source_code, sources, sinks)
            graph = await self.graph_builder.enrich_graph(
                graph, source_code, sources, sinks
            )
        elif self.config.use_joern:
            logger.debug("Using JoernWrapper for graph building")
            joern = JoernWrapper()
            graph = joern.build_graph(source_code, sources, sinks)
            self.graph_builder = joern
        elif self.config.pathfinding_algorithm == "astar":
            logger.debug("Using EnhancedGraphBuilder for A* pathfinding")
            self.graph_builder = EnhancedGraphBuilder()
            graph = self.graph_builder.build_graph(source_code, sources, sinks)
        else:
            logger.debug("Using SimpleGraphBuilder for BFS pathfinding")
            self.graph_builder = SimpleGraphBuilder()
            graph = self.graph_builder.build_graph(source_code, sources, sinks)

        logger.debug(
            f"Built graph: {graph.number_of_nodes()} nodes, "
            f"{graph.number_of_edges()} edges"
        )

        # Find all chains using selected algorithm
        if self.config.pathfinding_algorithm == "astar":
            logger.debug("Using A* with semantic heuristic for path discovery")
            if self.config.use_semantic_heuristic:
                self.semantic_heuristic = SemanticHeuristic()
                self.path_finder = AStarPathFinder(
                    graph,
                    semantic_heuristic=self.semantic_heuristic,
                    use_semantic=True,
                )
            else:
                logger.debug("Semantic heuristic disabled, using basic A*")
                self.path_finder = AStarPathFinder(
                    graph,
                    use_semantic=False,
                )
        else:
            logger.debug("Using BFS for path discovery")
            self.path_finder = SimpleBFSPathFinder(graph)

        chains = self.path_finder.find_all_chains(
            sources=sources,
            sinks=sinks,
            max_length=self.config.max_path_length,
            sanitizers=sanitizers,
        )

        # Drop hallucinated chains whose snippets don't match the variable name
        chains = self._filter_low_quality_chains(chains)

        # Deduplicate chains
        chains = self._deduplicate_chains(chains)

        # Adjust confidence based on source/sink categories
        chains = self._adjust_chain_confidence(chains, self.config.min_confidence)

        logger.info(f"✓ Stage 2 complete: Found {len(chains)} taint chains")

        # ============ STAGE 3: CFG-based Verification ============
        if self.config.verification_enabled and chains:
            if self.config.verification_level in ("symbolic", "both"):
                logger.info(
                    f"Stage 3: Verifying chains with verification_level='{self.config.verification_level}' "
                    f"(timeout={self.config.symbolic_timeout}s)..."
                )
                self.verification_engine = VerificationEngine(
                    config=self.config,
                    max_loop_iterations=10,
                    symbolic_timeout=self.config.symbolic_timeout
                )
                verification_results = self.verification_engine.verify_all_chains(
                    chains, source_code
                )
            else:  # cfg
                logger.info("Stage 3: Verifying chain reachability with CFG...")
                self.verifier = SimpleCFGVerifier(graph)
                verification_results = self.verifier.verify_all_chains(chains)

            verified_chains = verification_results["verified"]
            verification_rate = verification_results["verification_rate"]

            if "unverifiable" in verification_results:
                unverifiable_count = len(verification_results["unverifiable"])
                if unverifiable_count > 0:
                    logger.info(
                        f"  ({unverifiable_count} chains unverifiable - "
                        f"set verification_level='symbolic' or 'both' for higher confidence)"
                    )

            logger.info(
                f"✓ Stage 3 complete: {len(verified_chains)} chains verified "
                f"({verification_rate:.1%})"
            )
        else:
            verified_chains = chains
            logger.info("Stage 3: Verification disabled, using all chains")

        # ============ STAGE 4: Explanation Generation ============
        if verified_chains:
            logger.info("Stage 4: Generating explanations...")
            explanations = self.explainer.generate_explanations_batch(verified_chains)
            logger.info(f"✓ Stage 4 complete: Generated {len(explanations)} explanations")
        else:
            explanations = {}
            logger.info("Stage 4: No chains to explain")

        # ============ Compile Results ============
        metrics = {
            "sources_found": len(sources),
            "sinks_found": len(sinks),
            "sanitizers_found": len(sanitizers),
            "chains_found": len(chains),
            "chains_verified": len(verified_chains),
            "verification_rate": (
                len(verified_chains) / len(chains) if chains else 0.0
            ),
            "explanations_generated": len(explanations),
            "graph_nodes": graph.number_of_nodes(),
            "graph_edges": graph.number_of_edges(),
        }

        result = {
            "total_chains": len(chains),
            "verified_chains": verified_chains,
            "explanations": explanations,
            "metrics": metrics,
        }

        logger.info("✓ Pipeline execution completed successfully")
        logger.info(f"Summary: {len(chains)} chains, {len(verified_chains)} verified")

        return result

    def _read_source_file(self, file_path: str) -> str:
        """Read source file content with error handling.

        Args:
            file_path: Path to source file.

        Returns:
            File content as string.

        Raises:
            FileNotFoundError: If file does not exist.
            IOError: If file cannot be read.
        """
        try:
            file = Path(file_path)

            if not file.exists():
                logger.error(f"Source file not found: {file_path}")
                raise FileNotFoundError(f"Source file not found: {file_path}")

            if not file.is_file():
                logger.error(f"Path is not a file: {file_path}")
                raise ValueError(f"Path is not a file: {file_path}")

            with open(file, "r", encoding="utf-8") as f:
                content = f.read()

            logger.debug(f"Read {len(content)} bytes from {file_path}")
            return content

        except IOError as e:
            logger.error(f"Failed to read file {file_path}: {str(e)}")
            raise

    def create_result(
        self,
        run_output: Dict[str, Any],
        source_file: str,
    ) -> PipelineResult:
        """Create a PipelineResult from run output.

        Args:
            run_output: Dictionary returned from run().
            source_file: Path to analyzed source file.

        Returns:
            PipelineResult instance.
        """
        result = PipelineResult(
            source_file=source_file,
            total_chains=run_output["total_chains"],
            verified_chains=run_output["verified_chains"],
            explanations=run_output["explanations"],
            metrics=run_output["metrics"],
        )

        logger.debug(f"Created PipelineResult with {result.total_chains} chains")
        return result
