"""Main pipeline orchestrator for security analysis."""

import asyncio
import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import networkx as nx

from src.core.config import PipelineConfig
from src.core.exceptions import TaintAnalysisError
from src.core.models import (
    Sink,
    SinkCategory,
    Source,
    SourceCategory,
    Specification,
    TaintChain,
)
from src.pipeline.result import PipelineResult
from src.stage1_llm_inference.client_factory import create_llm_client
from src.stage1_llm_inference.spec_cache import SpecCache, default_cache_dir
from src.stage1_llm_inference.specification_extractor import SimpleSpecificationExtractor
from src.stage2_path_discovery.astar_search import (
    AStarPathFinder,
    SemanticHeuristic,
)
from src.stage2_path_discovery.graph_builder import EnhancedGraphBuilder
from src.stage2_path_discovery.joern_wrapper import JoernWrapper
from src.stage2_path_discovery.llm_graph_builder import LLMGraphBuilder
from src.stage2_path_discovery.simple_path_finder import (
    SimpleBFSPathFinder,
    SimpleGraphBuilder,
)
from src.stage3_verification.simple_verifier import SimpleCFGVerifier
from src.stage3_verification.verification_engine import VerificationEngine
from src.stage4_explanation.explanation_generator import ExplanationGenerator
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

    # A full project graph keeps source text, AST-derived metadata and NetworkX
    # objects for every file. Above this size, retain graph state only for files
    # where Stage 1 found an endpoint. These are resource limits, not benchmark
    # hints: they are independent of labels, CWE ids and expected locations.
    FULL_PROJECT_GRAPH_FILE_LIMIT = 20_000
    MAX_ENDPOINT_GRAPH_FILES = 10_000
    STAGE1_BATCH_MULTIPLIER = 4
    GRAPH_BATCH_MULTIPLIER = 2

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

        # The static backend is a standalone baseline and must not initialize,
        # authenticate, or accidentally call an LLM provider.
        self.llm_client = (
            None if config.analysis_backend == "static" else create_llm_client(config)
        )

        # Optional persistent cache for Stage 1 specifications. Resolved here
        # (not in __init__ args) because the default location depends on the
        # *target* source path, which is only known at run-time. Callers that
        # need a specific dir set ``config.cache_dir``; otherwise it's
        # resolved against the source path on the first run_* call.
        self.spec_cache: Optional[SpecCache] = None
        if config.cache_enabled and config.cache_dir:
            self.spec_cache = SpecCache(
                cache_dir=Path(config.cache_dir), enabled=True
            )

        self.spec_extractor = SimpleSpecificationExtractor(
            llm_client=self.llm_client,
            confidence_threshold=config.min_confidence,
            spec_cache=self.spec_cache,
            llm_provider=config.llm_provider,
            max_concurrent_functions=config.max_concurrent_functions,
            batch_max_chars=config.llm_batch_max_chars,
            truncation_max_tokens=config.llm_truncation_max_tokens,
            analysis_backend=config.analysis_backend,
            analysis_mode=config.llm_analysis_mode,
            cache_read_enabled=config.cache_read_enabled,
        )

        # Stage 2-3 components initialized in run()
        self.graph_builder: Optional[Any] = None  # SimpleGraphBuilder or EnhancedGraphBuilder
        self.path_finder: Optional[Any] = None  # SimpleBFSPathFinder or AStarPathFinder
        self.semantic_heuristic: Optional[SemanticHeuristic] = None
        self.verifier: Optional[SimpleCFGVerifier] = None
        self.verification_engine: Optional[VerificationEngine] = None
        self._encoding_warning_paths: set[str] = set()
        self._global_method_owner: Optional[Dict[str, str]] = None

        # Stage 4 components
        self.explainer = ExplanationGenerator(llm_client=self.llm_client)

        logger.info(
            f"Initialized SimplePipeline with config: "
            f"analysis_backend={config.analysis_backend}, "
            f"model={config.llm_model}, "
            f"max_path_length={config.max_path_length}, "
            f"min_confidence={config.min_confidence}, "
            f"pathfinding_algorithm={config.pathfinding_algorithm}, "
            f"use_joern={config.use_joern}"
        )

    def _ensure_spec_cache(self, source_path: str) -> None:
        """Resolve and wire the default cache once the analysis target is known."""
        if not self.config.cache_enabled or self.spec_cache is not None:
            return
        cache_path = (
            Path(self.config.cache_dir)
            if self.config.cache_dir
            else default_cache_dir(source_path)
        )
        self.spec_cache = SpecCache(cache_dir=cache_path, enabled=True)
        self.spec_extractor.spec_cache = self.spec_cache

    async def aclose(self) -> None:
        """Release the LLM client's persistent HTTP resources."""
        if self.llm_client is not None:
            await self.llm_client.aclose()

    def release_run_state(self) -> None:
        """Drop per-run graphs before reusing this pipeline for another target."""
        if self.semantic_heuristic is not None:
            self.semantic_heuristic.clear_cache()
        self.graph_builder = None
        self.path_finder = None
        self.semantic_heuristic = None
        self.verifier = None
        self.verification_engine = None
        self._global_method_owner = None

    async def run(
        self,
        source_file: str,
        on_stage1_complete: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """Execute complete pipeline on source file.

        Runs all 4 stages in sequence:
        1. Extract specifications (sources, sinks)
        2. Discover data flow paths
        3. Verify chain reachability
        4. Generate explanations

        Args:
            source_file: Path to Java source file to analyze.
            on_stage1_complete: Optional callback fired after Stage 1 with a
                snapshot dict ``{files_analyzed, file_list, sources, sinks,
                sanitizers}``. Used by the CLI to write an incremental JSON
                snapshot so a Stage 2-4 crash leaves the LLM-extracted
                source/sink inventory durable on disk.

        Returns:
            Dictionary containing results from all stages with metrics.

        Raises:
            TaintAnalysisError: If any stage fails critically.
            FileNotFoundError: If source file not found.
        """
        logger.info(f"Starting pipeline execution on {source_file}")
        self._ensure_spec_cache(source_file)

        try:
            # Read source file
            source_code = self._read_source_file(source_file)
            logger.debug(f"Read {len(source_code)} bytes from {source_file}")

            # ============ STAGE 1: LLM-based Specification Extraction ============
            logger.info("Stage 1: Extracting specifications...")

            if source_code.strip():
                specification = await self.spec_extractor.extract(
                    source_code=source_code,
                    file_path=source_file,
                    model=self.config.llm_model,
                )
            else:
                logger.info(f"Skipping empty source file: {source_file}")
                specification = self._empty_specification()

            sources = specification.sources
            sinks = specification.sinks
            sanitizers = specification.sanitizers

            logger.info(
                f"✓ Stage 1 complete: Found {len(sources)} sources, {len(sinks)} sinks, "
                f"{len(sanitizers)} sanitizers"
            )

            if on_stage1_complete is not None:
                try:
                    on_stage1_complete({
                        "files_analyzed": 1,
                        "files_llm_extracted": int(
                            self.config.analysis_backend != "static"
                        ),
                        "files_skipped": 0,
                        "file_list": [source_file],
                        "sources": list(sources),
                        "sinks": list(sinks),
                        "sanitizers": list(sanitizers),
                    })
                except Exception as cb_err:
                    logger.warning(
                        f"on_stage1_complete callback failed: {cb_err}"
                    )

            # ============ STAGES 2-4: Path Discovery, Verification, Explanation ============
            result = await self._run_stages(source_code, sources, sinks, sanitizers)
            result["file"] = source_file
            result["metrics"]["extraction_complete"] = specification.extraction_complete
            result["metrics"]["extraction_errors"] = list(
                specification.extraction_errors
            )
            result["metrics"]["analysis_backend"] = self.config.analysis_backend
            result["metrics"]["llm_analysis_mode"] = self.config.llm_analysis_mode
            result["metrics"]["analysis_errors"] = []
            result["metrics"]["analysis_complete"] = bool(
                specification.extraction_complete
            )

            return result

        except FileNotFoundError:
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

    def _partition_file_paths(
        self, java_files: List[str]
    ) -> Tuple[List[str], List[str]]:
        """Partition paths without retaining every source file in memory."""
        relevant: List[str] = []
        irrelevant: List[str] = []

        for java_file in java_files:
            code = self._read_source_file(java_file)
            if self._is_security_relevant(code):
                relevant.append(java_file)
            else:
                irrelevant.append(java_file)

        logger.info(
            f"File priority: {len(relevant)}/{len(java_files)} files match known "
            f"security patterns (analyzed first); {len(irrelevant)} analyzed after"
        )
        return relevant, irrelevant

    def _select_taint_reachable_files(
        self,
        java_files: List[str],
        endpoint_code: Dict[str, str],
        file_sources: Dict[str, List[Source]],
        file_sinks: Dict[str, List[Sink]],
    ) -> Tuple[Dict[str, str], bool]:
        """Select the complete supported call slice between endpoint files.

        The inter-file graph builder only creates caller-argument to callee-
        parameter edges for uniquely resolved method names. A compact global
        method index therefore lets us prove that files outside the forward /
        reverse intersection cannot participate in any supported taint path.
        """
        source_files = {path for path, values in file_sources.items() if values}
        sink_files = {path for path, values in file_sinks.items() if values}
        if not source_files or not sink_files:
            self._global_method_owner = {}
            return dict(endpoint_code), True

        parser = self.spec_extractor.ast_parser
        definitions: Dict[str, set[str]] = {}
        calls_by_file: Dict[str, set[str]] = {}
        code_cache = dict(endpoint_code)
        index_complete = True

        for index, path in enumerate(java_files, 1):
            try:
                code = code_cache.get(path)
                if code is None:
                    code = self._read_source_file(path)
                method_names = {
                    str(method.get("name", ""))
                    for method in parser.extract_functions(code)
                    if method.get("name")
                }
                calls = {
                    str(call.get("name", ""))
                    for call in parser.extract_method_calls(code)
                    if call.get("name")
                }
                calls_by_file[path] = calls
                for method_name in method_names:
                    definitions.setdefault(method_name, set()).add(path)
            except Exception as error:
                index_complete = False
                logger.warning(
                    f"Call-index extraction failed for {path}: "
                    f"{type(error).__name__}: {error}"
                )
            if index % 10_000 == 0:
                logger.info(
                    f"Large-project call index: {index}/{len(java_files)} files"
                )

        unique_owner = {
            method_name: next(iter(owners))
            for method_name, owners in definitions.items()
            if len(owners) == 1
        }
        self._global_method_owner = unique_owner
        forward_graph: Dict[str, set[str]] = {}
        reverse_graph: Dict[str, set[str]] = {}
        for caller, calls in calls_by_file.items():
            for method_name in calls:
                target = unique_owner.get(method_name)
                if target is None or target == caller:
                    continue
                forward_graph.setdefault(caller, set()).add(target)
                reverse_graph.setdefault(target, set()).add(caller)

        def distances(
            seeds: set[str], adjacency: Dict[str, set[str]]
        ) -> Dict[str, int]:
            found = {seed: 0 for seed in seeds}
            queue = list(sorted(seeds))
            cursor = 0
            while cursor < len(queue):
                current = queue[cursor]
                cursor += 1
                depth = found[current]
                if depth >= self.config.max_path_length:
                    continue
                for neighbor in sorted(adjacency.get(current, ())):
                    if neighbor in found:
                        continue
                    found[neighbor] = depth + 1
                    queue.append(neighbor)
            return found

        forward = distances(source_files, forward_graph)
        backward = distances(sink_files, reverse_graph)
        selected = set(endpoint_code) | (set(forward) & set(backward))
        ordered = sorted(
            selected,
            key=lambda path: (
                forward.get(path, self.config.max_path_length + 1)
                + backward.get(path, self.config.max_path_length + 1),
                path,
            ),
        )
        selection_complete = index_complete
        if len(ordered) > self.MAX_ENDPOINT_GRAPH_FILES:
            ordered = ordered[: self.MAX_ENDPOINT_GRAPH_FILES]
            selection_complete = False
            logger.warning(
                "Taint-reachable graph slice exceeds retention limit: "
                f"keeping {len(ordered)}/{len(selected)} files"
            )

        selected_code = {
            path: code_cache[path] if path in code_cache else self._read_source_file(path)
            for path in ordered
        }
        logger.info(
            f"Large-project call slice: {len(selected_code)}/{len(java_files)} "
            f"files can participate in a supported source-to-sink call path"
        )
        return selected_code, selection_complete

    def _empty_specification(self) -> Specification:
        """Return a complete no-endpoint result for an empty input file."""
        return Specification(
            sources=[],
            sinks=[],
            sanitizers=[],
            llm_model=self.config.llm_model,
            extraction_backend=self.config.analysis_backend,
        )

    async def run_project(
        self,
        java_files: List[str],
        show_progress: bool = False,
        on_stage1_complete: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """Execute pipeline in project mode with per-file graph scoping.

        Stage 1 runs per-file on security-relevant files only (concurrent).
        Stages 2-4 use *scoped* graphs so that identically-named variables
        in different files remain distinct nodes, preventing false cross-file
        taint chains.

        Args:
            java_files: List of paths to Java source files.
            show_progress: If True, render a progress bar to stderr.
            on_stage1_complete: Optional callback fired after Stage 1 with a
                snapshot dict ``{files_analyzed, files_llm_extracted,
                files_skipped, file_list, sources, sinks, sanitizers}``. Used by
                the CLI to write an incremental JSON snapshot so a Stage 2-4
                crash leaves the LLM-extracted inventory durable on disk.

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

        if java_files:
            common_path = os.path.commonpath(java_files)
            if Path(common_path).suffix:
                common_path = str(Path(common_path).parent)
            self._ensure_spec_cache(common_path)

        try:
            # Partition files by security relevance — used for ORDERING, not
            # exclusion. Analyzing only keyword-matching files blinds the
            # detector to 0-day patterns in files using unfamiliar APIs, so
            # every file is analyzed (security-matching ones first). The old
            # exclude-irrelevant behavior is opt-in via VTC_FAST_PREFILTER
            # (debug/CI only).
            relevant, irrelevant = self._partition_file_paths(java_files)
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

            skipped_files = list(irrelevant)
            large_project_mode = (
                len(java_files) > self.FULL_PROJECT_GRAPH_FILE_LIMIT
            )
            if large_project_mode:
                logger.info(
                    "Large-project memory mode: Stage 1 analyzes every selected "
                    "file; Stage 2 builds a compact source-to-sink call slice"
                )

            # Stage 1: concurrent per-file extraction on relevant files only
            all_sources: List = []
            all_sinks: List = []
            all_sanitizers: List = []
            # Per-file maps for scoped graph building
            file_code_map: Dict[str, str] = {}
            file_sources: Dict[str, List[Source]] = {}
            file_sinks: Dict[str, List[Sink]] = {}
            extraction_errors: Dict[str, List[str]] = {}

            max_concurrent = self.config.max_concurrent_files
            semaphore = asyncio.Semaphore(max_concurrent)
            total_relevant = len(relevant)
            completed = 0
            resource_limit_reached = False
            start_time = time.monotonic()

            progress: Optional[ProgressReporter] = None
            if show_progress and total_relevant > 0:
                progress = ProgressReporter(total_relevant, "Stage 1: Extracting specs")

            async def extract_one(idx: int, java_file: str) -> Tuple[str, str, Any]:
                nonlocal completed
                async with semaphore:
                    elapsed = time.monotonic() - start_time
                    avg = elapsed / completed if completed > 0 else 0
                    remaining = total_relevant - completed
                    eta = f", ETA ~{avg * remaining:.0f}s" if completed > 0 else ""
                    file_name = Path(java_file).name
                    progress_log = (
                        logger.info
                        if idx == 1 or idx == total_relevant or idx % 100 == 0
                        else logger.debug
                    )
                    progress_log(
                        f"Stage 1 [{idx}/{total_relevant}]: "
                        f"Extracting from {file_name}... "
                        f"(avg {avg:.1f}s/file{eta})"
                    )
                    code = self._read_source_file(java_file)
                    if code.strip():
                        spec = await self.spec_extractor.extract(
                            source_code=code,
                            file_path=java_file,
                            model=self.config.llm_model,
                        )
                    else:
                        logger.info(f"Skipping empty source file: {java_file}")
                        spec = self._empty_specification()
                    completed += 1
                    if progress is not None:
                        progress.update()
                    return java_file, code, spec

            # Bound both pending coroutine count and retained source/spec data.
            # Creating one task per file caused six-figure projects to retain
            # the entire corpus until the last extraction completed.
            stage1_batch_size = max(
                1, max_concurrent * self.STAGE1_BATCH_MULTIPLIER
            )
            for batch_start in range(0, total_relevant, stage1_batch_size):
                batch_paths = relevant[
                    batch_start : batch_start + stage1_batch_size
                ]
                results = await asyncio.gather(
                    *(
                        extract_one(batch_start + offset, java_file)
                        for offset, java_file in enumerate(batch_paths, 1)
                    )
                )

                for java_file, code, spec in results:
                    all_sources.extend(spec.sources)
                    all_sinks.extend(spec.sinks)
                    all_sanitizers.extend(spec.sanitizers)
                    has_endpoint = bool(spec.sources or spec.sinks)
                    retain_file = not large_project_mode or has_endpoint
                    if (
                        retain_file
                        and large_project_mode
                        and java_file not in file_code_map
                        and len(file_code_map) >= self.MAX_ENDPOINT_GRAPH_FILES
                    ):
                        resource_limit_reached = True
                        retain_file = False
                    if retain_file:
                        file_code_map[java_file] = code
                        file_sources[java_file] = list(spec.sources)
                        file_sinks[java_file] = list(spec.sinks)
                    if not spec.extraction_complete:
                        extraction_errors[java_file] = list(
                            spec.extraction_errors
                        )

            if progress is not None:
                progress.finish()

            # The provider already retries individual requests. Retrying the
            # complete file once more catches transient connection failures
            # after the provider/client retry budget without rerunning healthy
            # files or caching an incomplete extraction.
            for java_file in list(extraction_errors):
                logger.warning(
                    f"Retrying incomplete Stage 1 file once: {java_file}"
                )
                code = self._read_source_file(java_file)
                try:
                    retry_spec = await self.spec_extractor.extract(
                        source_code=code,
                        file_path=java_file,
                        model=self.config.llm_model,
                    )
                except Exception as retry_error:
                    logger.warning(
                        "Stage 1 file retry failed: "
                        f"{type(retry_error).__name__}: {retry_error}"
                    )
                    continue
                if not retry_spec.extraction_complete:
                    extraction_errors[java_file] = list(
                        retry_spec.extraction_errors
                    )
                    continue

                all_sources = [
                    source
                    for source in all_sources
                    if source.location.file_path != java_file
                ] + list(retry_spec.sources)
                all_sinks = [
                    sink
                    for sink in all_sinks
                    if sink.location.file_path != java_file
                ] + list(retry_spec.sinks)
                all_sanitizers = [
                    sanitizer
                    for sanitizer in all_sanitizers
                    if sanitizer.location.file_path != java_file
                ] + list(retry_spec.sanitizers)
                extraction_errors.pop(java_file, None)

                has_endpoint = bool(retry_spec.sources or retry_spec.sinks)
                if not large_project_mode or has_endpoint:
                    if (
                        java_file in file_code_map
                        or len(file_code_map) < self.MAX_ENDPOINT_GRAPH_FILES
                    ):
                        file_code_map[java_file] = code
                        file_sources[java_file] = list(retry_spec.sources)
                        file_sinks[java_file] = list(retry_spec.sinks)
                    else:
                        resource_limit_reached = True
                logger.info(f"Stage 1 retry recovered {java_file}")

            # Include irrelevant files' code for graph building (no LLM calls)
            if not large_project_mode:
                for java_file in skipped_files:
                    file_code_map[java_file] = self._read_source_file(java_file)
                    file_sources.setdefault(java_file, [])
                    file_sinks.setdefault(java_file, [])

            graph_selection_complete = not resource_limit_reached
            if large_project_mode:
                selected_code, call_slice_complete = self._select_taint_reachable_files(
                    java_files,
                    file_code_map,
                    file_sources,
                    file_sinks,
                )
                file_code_map = selected_code
                file_sources = {
                    path: file_sources.get(path, []) for path in file_code_map
                }
                file_sinks = {
                    path: file_sinks.get(path, []) for path in file_code_map
                }
                graph_selection_complete = (
                    graph_selection_complete and call_slice_complete
                )

            graph_file_count = len(file_code_map)
            elapsed_total = time.monotonic() - start_time
            stage1_status = "complete"
            logger.info(
                f"Stage 1 {stage1_status} (project): Found "
                f"{len(all_sources)} sources, "
                f"{len(all_sinks)} sinks, {len(all_sanitizers)} sanitizers "
                f"across {completed}/{total_relevant} relevant files "
                f"({len(skipped_files)} skipped) in {elapsed_total:.1f}s"
            )

            if on_stage1_complete is not None:
                try:
                    on_stage1_complete({
                        "files_analyzed": len(java_files),
                        "files_llm_extracted": (
                            completed
                            if self.config.analysis_backend != "static"
                            else 0
                        ),
                        "files_skipped": len(skipped_files),
                        "file_list": java_files,
                        "sources": list(all_sources),
                        "sinks": list(all_sinks),
                        "sanitizers": list(all_sanitizers),
                        "stage1_complete": True,
                        "resource_limit_reached": resource_limit_reached,
                    })
                except Exception as cb_err:
                    logger.warning(
                        f"on_stage1_complete callback failed: {cb_err}"
                    )

            # Stages 2-4: scoped graph analysis
            result = await self._run_stages_project(
                file_code_map, file_sources, file_sinks,
                all_sources, all_sinks, all_sanitizers,
                allow_interfile_bridges=True,
            )
            result["file"] = f"project ({len(java_files)} files)"
            result["files_analyzed"] = len(java_files)
            result["files_llm_extracted"] = (
                total_relevant if self.config.analysis_backend != "static" else 0
            )
            result["files_skipped"] = len(skipped_files)
            result["file_list"] = java_files
            result["metrics"]["extraction_complete"] = not extraction_errors
            result["metrics"]["extraction_errors"] = extraction_errors
            result["metrics"]["analysis_backend"] = self.config.analysis_backend
            result["metrics"]["llm_analysis_mode"] = self.config.llm_analysis_mode
            result["metrics"]["graph_scope_mode"] = (
                "taint_reachable_call_slice"
                if large_project_mode
                else "full_project"
            )
            result["metrics"]["graph_candidate_files"] = graph_file_count
            result["metrics"]["graph_files_omitted"] = (
                len(java_files) - graph_file_count
            )
            result["metrics"]["interfile_bridges_enabled"] = (
                True
            )
            analysis_errors: List[str] = []
            if large_project_mode and not graph_selection_complete:
                analysis_errors.append(
                    "Stage 2 source-to-sink call slice was incomplete"
                )
            if resource_limit_reached:
                analysis_errors.append(
                    "Stage 2 endpoint-file retention limit was reached"
                )
            result["metrics"]["analysis_errors"] = analysis_errors
            result["metrics"]["analysis_complete"] = (
                not extraction_errors and not analysis_errors
            )

            return result

        except Exception as e:
            logger.error(f"Project-mode analysis failed: {str(e)}")
            raise TaintAnalysisError(f"Pipeline error: {str(e)}") from e

    async def collect_sinks(
        self,
        java_files: List[str],
        show_progress: bool = False,
        on_file_done: Optional[Callable[[str, List[Sink]], None]] = None,
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
            on_file_done: Optional callback ``(file_path, sinks)`` invoked after
                each file finishes Stage 1. Used by the CLI to write incremental
                JSON snapshots so partial results survive interruption on long
                project runs. Asyncio is single-threaded so concurrent extracts
                cannot interleave callbacks — no locking required.

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

        if java_files:
            common_path = os.path.commonpath(java_files)
            if Path(common_path).suffix:
                common_path = str(Path(common_path).parent)
            self._ensure_spec_cache(common_path)

        try:
            # Partition for ORDERING only (security-matching files first); every
            # file is analyzed unless VTC_FAST_PREFILTER opts into the old skip.
            relevant, irrelevant = self._partition_file_paths(java_files)
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

            skipped_count = len(irrelevant)

            max_concurrent = self.config.max_concurrent_files
            semaphore = asyncio.Semaphore(max_concurrent)
            total_relevant = len(relevant)
            completed = 0
            start_time = time.monotonic()

            progress: Optional[ProgressReporter] = None
            if show_progress and total_relevant > 0:
                progress = ProgressReporter(total_relevant, "Stage 1: Extracting sinks")

            async def extract_one(idx: int, java_file: str) -> Tuple[str, Any]:
                nonlocal completed
                async with semaphore:
                    elapsed = time.monotonic() - start_time
                    avg = elapsed / completed if completed > 0 else 0
                    remaining = total_relevant - completed
                    eta = f", ETA ~{avg * remaining:.0f}s" if completed > 0 else ""
                    file_name = Path(java_file).name
                    progress_log = (
                        logger.info
                        if idx == 1 or idx == total_relevant or idx % 100 == 0
                        else logger.debug
                    )
                    progress_log(
                        f"Stage 1 [{idx}/{total_relevant}]: "
                        f"Extracting from {file_name}... "
                        f"(avg {avg:.1f}s/file{eta})"
                    )
                    code = self._read_source_file(java_file)
                    if code.strip():
                        spec = await self.spec_extractor.extract(
                            source_code=code,
                            file_path=java_file,
                            model=self.config.llm_model,
                        )
                    else:
                        logger.info(f"Skipping empty source file: {java_file}")
                        spec = self._empty_specification()
                    completed += 1
                    if progress is not None:
                        progress.update()
                    if on_file_done is not None:
                        try:
                            on_file_done(java_file, list(spec.sinks))
                        except Exception as cb_err:
                            logger.warning(
                                f"on_file_done callback failed for "
                                f"{java_file}: {cb_err}"
                            )
                    return java_file, spec

            collected: List[Tuple[str, Sink]] = []
            extraction_errors: Dict[str, List[str]] = {}
            stage1_batch_size = max(
                1, max_concurrent * self.STAGE1_BATCH_MULTIPLIER
            )
            for batch_start in range(0, total_relevant, stage1_batch_size):
                batch_paths = relevant[
                    batch_start : batch_start + stage1_batch_size
                ]
                results = await asyncio.gather(
                    *(
                        extract_one(batch_start + offset, java_file)
                        for offset, java_file in enumerate(batch_paths, 1)
                    )
                )
                for java_file, spec in results:
                    for snk in spec.sinks:
                        collected.append((java_file, snk))
                    if not spec.extraction_complete:
                        extraction_errors[java_file] = list(
                            spec.extraction_errors
                        )

            if progress is not None:
                progress.finish()

            elapsed_total = time.monotonic() - start_time
            logger.info(
                f"✓ Sink inventory complete: {len(collected)} sinks across "
                f"{total_relevant} files ({skipped_count} skipped) "
                f"in {elapsed_total:.1f}s"
            )

            return {
                "files_analyzed": len(java_files),
                "files_llm_extracted": (
                    total_relevant if self.config.analysis_backend != "static" else 0
                ),
                "files_skipped": skipped_count,
                "sinks": collected,
                "extraction_complete": not extraction_errors,
                "extraction_errors": extraction_errors,
            }

        except Exception as e:
            logger.error(f"Sink-inventory analysis failed: {str(e)}")
            raise TaintAnalysisError(f"Pipeline error: {str(e)}") from e

    async def _build_scoped_graph(
        self,
        file_code_map: Dict[str, str],
        file_sources: Dict[str, List[Source]],
        file_sinks: Dict[str, List[Sink]],
        allow_interfile_bridges: bool = True,
    ) -> Tuple[nx.DiGraph, Dict[int, str]]:
        """Build a merged graph with per-file scoped node names.

        Each file gets its own sub-graph built by the configured graph builder.
        Nodes are then relabelled with the normalized absolute file path so
        identically-named files and variables in different modules stay distinct.

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
        joern = JoernWrapper() if self.config.use_joern else None

        if not use_llm_builder and (joern is None or not joern.joern_available):
            if self.config.pathfinding_algorithm == "astar":
                builder_cls = EnhancedGraphBuilder
            else:
                builder_cls = SimpleGraphBuilder

        def _file_scope(fpath: str) -> str:
            # Basename/parent scoping collides in multi-module repositories.
            # abspath is lexical (unlike resolve) and therefore also works for
            # benchmark checkouts containing symlinked or temporarily absent paths.
            return os.path.normcase(os.path.abspath(fpath)).replace("\\", "/")

        def _endpoint_name(kind: str, index: int) -> str:
            return f"__vtc_{kind}_{index}"

        def _annotate_local_graph(
            graph: nx.DiGraph,
            fpath: str,
            code: str,
            sources: List[Source],
            sinks: List[Sink],
        ) -> None:
            """Attach source coordinates and keep equal-name endpoints distinct."""
            lines = code.splitlines()
            function_ranges = []
            for function in self.spec_extractor.ast_parser.extract_functions(code):
                start = int(function.get("start_line", 0) or 0)
                end = int(function.get("end_line", start) or start)
                function_ranges.append((start, end, function.get("name")))

            def function_for_line(line_number: int) -> Optional[str]:
                return next(
                    (
                        name
                        for start, end, name in function_ranges
                        if start <= line_number <= end
                    ),
                    None,
                )

            # Populate a deterministic best-effort location for intermediate
            # identifiers. AST edges may later provide a more precise location.
            local_nodes = {str(node): node for node in graph.nodes}
            seen: set[str] = set()
            for line_number, line in enumerate(lines, 1):
                for identifier in re.findall(r"\b[A-Za-z_$][\w$]*\b", line):
                    node = local_nodes.get(identifier)
                    if node is None or identifier in seen:
                        continue
                    data = graph.nodes[node]
                    data.setdefault("file_path", fpath)
                    data.setdefault("line", line_number)
                    data.setdefault("function_name", function_for_line(line_number))
                    data.setdefault("code_snippet", line.strip())
                    data.setdefault("variable_name", identifier)
                    seen.add(identifier)

            for node, data in graph.nodes(data=True):
                data.setdefault("file_path", fpath)
                data.setdefault("line", 1)
                data.setdefault("variable_name", str(data.get("label", node)))

            # A file-level variable graph cannot represent several endpoint
            # occurrences with the same identifier. Dedicated boundary nodes
            # preserve the exact endpoint identity while retaining the local
            # variable as the data-flow entry/exit.
            for kind, endpoints in (("source", sources), ("sink", sinks)):
                for index, endpoint in enumerate(endpoints):
                    base = endpoint.variable_name
                    if base not in graph:
                        graph.add_node(
                            base,
                            type="intermediate",
                            file_path=fpath,
                            line=endpoint.location.line_number,
                            function_name=endpoint.location.function_name,
                            variable_name=base,
                            code_snippet=endpoint.code_snippet,
                        )
                    boundary = _endpoint_name(kind, index)
                    base_data = graph.nodes[base]
                    graph.add_node(
                        boundary,
                        type=kind,
                        endpoint=endpoint,
                        file_path=endpoint.location.file_path or fpath,
                        line=endpoint.location.line_number,
                        function_name=endpoint.location.function_name,
                        class_name=endpoint.location.class_name,
                        variable_name=endpoint.variable_name,
                        code_snippet=endpoint.code_snippet,
                        confidence=endpoint.confidence,
                        is_field=base_data.get("is_field", False),
                    )
                    edge_data = {
                        "edge_type": "endpoint_binding",
                        "function_name": endpoint.location.function_name,
                        "line": endpoint.location.line_number,
                    }
                    if kind == "source":
                        graph.add_edge(boundary, base, **edge_data)
                    else:
                        graph.add_edge(base, boundary, **edge_data)

        merged = nx.DiGraph()
        scope_map: Dict[int, str] = {}  # id(Source/Sink obj) -> scoped node id
        graph_semaphore = asyncio.Semaphore(self.config.max_concurrent_files)

        async def _build_one(fpath: str, code: str) -> Tuple[str, nx.DiGraph]:
            sources_f = file_sources.get(fpath, [])
            sinks_f = file_sinks.get(fpath, [])

            async with graph_semaphore:
                if joern is not None and joern.joern_available:
                    g = await asyncio.to_thread(
                        joern.build_graph, code, sources_f, sinks_f
                    )
                elif use_llm_builder:
                    llm_builder = LLMGraphBuilder(
                        llm_client=self.llm_client, config=self.config
                    )
                    g = llm_builder.build_graph(code, sources_f, sinks_f)
                else:
                    builder = builder_cls()
                    g = builder.build_graph(code, sources_f, sinks_f)

                # Enrichment cannot create a useful taint chain when either
                # endpoint class is absent, so avoid an expensive no-op call.
                if (
                    use_llm_builder
                    and self.config.llm_graph_enrichment_enabled
                    and sources_f
                    and sinks_f
                ):
                    llm_builder = LLMGraphBuilder(
                        llm_client=self.llm_client, config=self.config
                    )
                    g = await llm_builder.enrich_graph(
                        g, code, sources_f, sinks_f
                    )
                _annotate_local_graph(g, fpath, code, sources_f, sinks_f)
                return fpath, g

        graph_batch_size = max(
            1,
            self.config.max_concurrent_files * self.GRAPH_BATCH_MULTIPLIER,
        )
        graph_items = list(file_code_map.items())
        for batch_start in range(0, len(graph_items), graph_batch_size):
            batch = graph_items[batch_start : batch_start + graph_batch_size]
            built_graphs = await asyncio.gather(
                *(_build_one(fpath, code) for fpath, code in batch)
            )

            for fpath, g in built_graphs:
                sources_f = file_sources.get(fpath, [])
                sinks_f = file_sinks.get(fpath, [])

                prefix = _file_scope(fpath)
                mapping = {n: f"{prefix}:{n}" for n in g.nodes()}
                nx.relabel_nodes(g, mapping, copy=False)

                # Record scoped IDs for source/sink objects.
                for index, src in enumerate(sources_f):
                    scope_map[id(src)] = f"{prefix}:{_endpoint_name('source', index)}"
                for index, snk in enumerate(sinks_f):
                    scope_map[id(snk)] = f"{prefix}:{_endpoint_name('sink', index)}"

                # Merge incrementally. nx.compose_all retained the full list of
                # local graphs and then copied every graph a second time.
                merged.add_nodes_from(g.nodes(data=True))
                merged.add_edges_from(g.edges(data=True))

            del built_graphs

        # Inter-file bridges are derived from actual call sites and positional
        # formal parameters. Equal variable names alone are not data flow.
        ast_parser = self.spec_extractor.ast_parser
        method_defs: Dict[str, List[Tuple[str, List[str], Optional[str]]]] = {}
        class_to_file: Dict[str, str] = {}
        superclass_by_file: Dict[str, Optional[str]] = {}
        if allow_interfile_bridges:
            for fpath, code in file_code_map.items():
                classes = ast_parser.extract_classes(code)
                if classes:
                    class_name = classes[0].get("name")
                    if class_name:
                        class_to_file[class_name] = fpath
                    superclass_by_file[fpath] = classes[0].get("superclass")
                for method in ast_parser.extract_functions(code):
                    params: List[str] = []
                    for raw in method.get("parameters", []):
                        cleaned = re.sub(r"@\w+(?:\([^)]*\))?\s*", "", raw)
                        names = re.findall(r"\b[A-Za-z_$][\w$]*\b", cleaned)
                        if names:
                            params.append(names[-1])
                    method_defs.setdefault(method.get("name", ""), []).append(
                        (fpath, params, method.get("class_name"))
                    )

        bridge_count = 0
        caller_files = file_code_map.items() if allow_interfile_bridges else ()
        for caller_path, code in caller_files:
            caller_prefix = _file_scope(caller_path)
            for call in ast_parser.extract_method_calls(code):
                targets = [
                    target for target in method_defs.get(call["name"], [])
                    if target[0] != caller_path
                ]
                if self._global_method_owner is not None:
                    owner = self._global_method_owner.get(call["name"])
                    targets = [target for target in targets if target[0] == owner]
                if call.get("receiver") == "super":
                    superclass = superclass_by_file.get(caller_path)
                    super_file = class_to_file.get(superclass or "")
                    targets = [target for target in targets if target[0] == super_file]
                elif len(targets) > 1:
                    # Without type resolution, multiple overload owners are
                    # ambiguous and must not be connected speculatively.
                    continue

                for target_path, params, _class_name in targets:
                    target_prefix = _file_scope(target_path)
                    for argument, parameter in zip(call["arguments"], params):
                        identifiers = re.findall(r"\b[A-Za-z_$][\w$]*\b", argument)
                        if not identifiers:
                            continue
                        argument_sources = [
                            source
                            for source in file_sources.get(caller_path, [])
                            if source.variable_name == identifiers[0]
                            and source.location.function_name
                        ]
                        call_function = call.get("function_name")
                        if (
                            argument_sources
                            and call_function
                            and not any(
                                source.location.function_name == call_function
                                for source in argument_sources
                            )
                        ):
                            # File-level graph nodes merge equal identifiers.
                            # Do not let a source from another method borrow this
                            # call site merely because its variable has the same name.
                            continue
                        # The first identifier is the tainted value/receiver in
                        # both `name` and `file.getOriginalFilename()`.
                        argument_node = f"{caller_prefix}:{identifiers[0]}"
                        parameter_node = f"{target_prefix}:{parameter}"
                        if argument_node not in merged or parameter_node not in merged:
                            continue
                        merged.add_edge(
                            argument_node,
                            parameter_node,
                            weight=1.0,
                            bridge=True,
                            bridge_type="argument_binding",
                            caller_function=call_function,
                            caller_file=caller_path,
                            call_line=call.get("line", 0),
                        )
                        bridge_count += 1
                        logger.debug(
                            f"Argument bridge: {argument_node} -> {parameter_node}"
                        )

        logger.info(
            f"Scoped graph: {merged.number_of_nodes()} nodes, "
            f"{merged.number_of_edges()} edges across {len(file_code_map)} files "
            f"({bridge_count} call-binding bridges; "
            f"inter-file={'enabled' if allow_interfile_bridges else 'disabled'})"
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
        allow_interfile_bridges: bool = True,
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
            allow_interfile_bridges=allow_interfile_bridges,
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
            max_chains=self.config.max_candidate_chains,
        )
        candidate_chains_truncated = bool(
            getattr(self.path_finder, "limit_exceeded", False)
        )

        # Drop hallucinated chains whose snippets don't match the variable name
        chains = self._filter_cross_function_chains(chains, graph, scope_map)
        chains = self._filter_low_quality_chains(chains)

        # Deduplicate chains
        chains = self._deduplicate_chains(chains)

        # Adjust confidence based on source/sink categories
        chains = self._adjust_chain_confidence(chains, self.config.min_confidence)

        logger.info(f"✓ Stage 2 complete: Found {len(chains)} taint chains")

        # ============ STAGE 3: Verification ============
        if self.config.verification_enabled and chains:
            logger.info(
                f"Stage 3: Verifying chains with independent source CFG "
                f"(verification_level='{self.config.verification_level}', "
                f"timeout={self.config.symbolic_timeout}s)..."
            )
            self.verification_engine = VerificationEngine(
                config=self.config,
                max_loop_iterations=10,
                symbolic_timeout=self.config.symbolic_timeout,
            )
            verification_results = self.verification_engine.verify_all_chains_scoped(
                chains, file_code_map,
            )

            verified_chains = list(verification_results["verified"])
            unverifiable_chains = list(
                verification_results.get("unverifiable", [])
            )
            rejected_chains = list(verification_results.get("false", []))
            verification_rate = verification_results["verification_rate"]
            verification_evidence = verification_results.get("results", [])

            logger.info(
                f"Stage 3 complete: {len(verified_chains)} confirmed, "
                f"{len(unverifiable_chains)} unverifiable, "
                f"{len(rejected_chains)} rejected "
                f"(confirmation rate {verification_rate:.1%})"
            )
        elif not chains:
            verified_chains = []
            unverifiable_chains = []
            rejected_chains = []
            verification_rate = 0.0
            verification_evidence = []
            logger.info("Stage 3: No candidate chains to verify")
        else:
            verified_chains = []
            unverifiable_chains = list(chains)
            rejected_chains = []
            verification_rate = 0.0
            verification_evidence = []
            logger.warning(
                "Stage 3: Verification disabled; candidate chains remain "
                "unverified and will not be reported as confirmed"
            )

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
            "chains_unverifiable": len(unverifiable_chains),
            "chains_rejected": len(rejected_chains),
            "verification_rate": verification_rate,
            "chains_cfg_reachable": sum(
                result.cfg_status.value == "verified"
                for result in verification_evidence
            ),
            "chains_symbolically_verified": sum(
                result.symbolic_status is not None
                and result.symbolic_status.value == "verified"
                for result in verification_evidence
            ),
            "explanations_generated": len(explanations),
            "graph_nodes": graph.number_of_nodes(),
            "graph_edges": graph.number_of_edges(),
            "candidate_chains_truncated": candidate_chains_truncated,
            "candidate_selection_limited": candidate_chains_truncated,
            "candidate_pairs_ranked": int(
                getattr(self.path_finder, "candidate_pairs_ranked", len(chains))
            ),
            "candidate_pairs_ranked_out": int(
                getattr(self.path_finder, "ranked_out_count", 0)
            ),
            "reachable_pairs_seen": int(
                getattr(self.path_finder, "reachable_pairs_seen", len(chains))
            ),
        }

        result = {
            "total_chains": len(chains),
            "verified_chains": verified_chains,
            "unverifiable_chains": unverifiable_chains,
            "rejected_chains": rejected_chains,
            "explanations": explanations,
            "metrics": metrics,
        }

        logger.info("✓ Pipeline execution completed successfully")
        logger.info(f"Summary: {len(chains)} chains, {len(verified_chains)} verified")

        return result

    @staticmethod
    def _filter_cross_function_chains(
        chains: List[TaintChain],
        graph: Optional[nx.DiGraph] = None,
        node_id_map: Optional[Dict[int, str]] = None,
    ) -> List[TaintChain]:
        """Reject cross-method name collisions unless a class field carries flow."""
        kept: List[TaintChain] = []
        node_id_map = node_id_map or {}
        for chain in chains:
            source_location = chain.source.location
            sink_location = chain.sink.location
            same_file = (
                source_location.file_path
                and source_location.file_path == sink_location.file_path
            )
            different_functions = (
                source_location.function_name
                and sink_location.function_name
                and source_location.function_name != sink_location.function_name
            )
            endpoint_nodes = (
                node_id_map.get(id(chain.source), chain.source.variable_name),
                node_id_map.get(id(chain.sink), chain.sink.variable_name),
            )
            has_field_bridge = bool(graph) and any(
                node in graph and graph.nodes[node].get("is_field", False)
                for node in endpoint_nodes
            )
            if same_file and different_functions and not has_field_bridge:
                logger.info(
                    "Filtered cross-function name collision: "
                    f"{source_location.function_name}:{chain.source.variable_name} -> "
                    f"{sink_location.function_name}:{chain.sink.variable_name}"
                )
                continue
            kept.append(chain)
        return kept

    @staticmethod
    def _filter_low_quality_chains(chains: List[TaintChain]) -> List[TaintChain]:
        """Drop chains where BOTH source and sink snippets fail to mention their variables.

        When the LLM hallucinates line numbers, the populated ``code_snippets``
        end up unrelated to the reported variables on **both** sides
        For example, a model may report endpoint names that occur nowhere in
        the snippets attached to either side of a chain.
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

        # Secondary pass: collapse chains with identical scoped endpoints and
        # vulnerability type that differ only in line metadata.
        coalesced: Dict[tuple, TaintChain] = {}
        for chain in deduped:
            src_file, _src_line = _loc(chain.source)
            sink_file, _sink_line = _loc(chain.sink)
            src_function = getattr(chain.source.location, "function_name", None)
            sink_function = getattr(chain.sink.location, "function_name", None)
            key = (
                chain.source.variable_name,
                src_file,
                src_function,
                chain.sink.variable_name,
                sink_file,
                sink_function,
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

        return coalesced_chains

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

            # Once the LLM selected both endpoints and the graph proved a data
            # path, origin categories such as session/configuration must not
            # erase the finding. Only explicitly benign/logging operations get
            # a strong penalty; all security-capable sinks retain LLM confidence.
            if sink_cat in (SinkCategory.BENIGN, SinkCategory.EVENT_LOGGING):
                multiplier = 0.1
            elif (
                sink_cat in (SinkCategory.DATA_STORAGE, SinkCategory.FRAMEWORK_API)
                and src_cat in (
                    SourceCategory.SESSION_DATA,
                    SourceCategory.INTERNAL_API,
                    SourceCategory.DATABASE,
                )
            ):
                multiplier = 0.3
            else:
                multiplier = 1.0

            new_confidence = chain.confidence * multiplier
            if new_confidence >= min_confidence:
                chain.confidence = new_confidence
                adjusted.append(chain)
            else:
                logger.debug(
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

        if not sources or not sinks:
            logger.info("Stage 2 skipped: at least one endpoint class is empty")
            return {
                "total_chains": 0,
                "verified_chains": [],
                "explanations": {},
                "metrics": {
                    "sources_found": len(sources),
                    "sinks_found": len(sinks),
                    "sanitizers_found": len(sanitizers),
                    "chains_found": 0,
                    "chains_verified": 0,
                    "verification_rate": 0.0,
                    "explanations_generated": 0,
                    "graph_nodes": 0,
                    "graph_edges": 0,
                },
            }

        # Build control/data flow graph
        if self.config.use_joern:
            logger.debug("Using JoernWrapper for graph building")
            joern = JoernWrapper()
            if joern.joern_available:
                graph = await asyncio.to_thread(
                    joern.build_graph, source_code, sources, sinks
                )
                self.graph_builder = joern
            elif self.config.use_llm_graph_builder:
                self.graph_builder = LLMGraphBuilder(
                    llm_client=self.llm_client, config=self.config
                )
                graph = self.graph_builder.build_graph(source_code, sources, sinks)
            elif self.config.pathfinding_algorithm == "astar":
                self.graph_builder = EnhancedGraphBuilder()
                graph = self.graph_builder.build_graph(source_code, sources, sinks)
            else:
                self.graph_builder = SimpleGraphBuilder()
                graph = self.graph_builder.build_graph(source_code, sources, sinks)

            if (
                self.config.use_llm_graph_builder
                and self.config.llm_graph_enrichment_enabled
                and joern.joern_available
            ):
                enricher = LLMGraphBuilder(
                    llm_client=self.llm_client, config=self.config
                )
                graph = await enricher.enrich_graph(
                    graph, source_code, sources, sinks
                )
        elif self.config.use_llm_graph_builder:
            logger.debug("Using LLMGraphBuilder (AST + LLM enrichment)")
            self.graph_builder = LLMGraphBuilder(
                llm_client=self.llm_client, config=self.config
            )
            graph = self.graph_builder.build_graph(source_code, sources, sinks)
            if self.config.llm_graph_enrichment_enabled:
                graph = await self.graph_builder.enrich_graph(
                    graph, source_code, sources, sinks
                )
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
            max_chains=self.config.max_candidate_chains,
        )
        candidate_chains_truncated = bool(
            getattr(self.path_finder, "limit_exceeded", False)
        )

        # Drop hallucinated chains whose snippets don't match the variable name
        chains = self._filter_cross_function_chains(chains, graph)
        chains = self._filter_low_quality_chains(chains)

        # Deduplicate chains
        chains = self._deduplicate_chains(chains)

        # Adjust confidence based on source/sink categories
        chains = self._adjust_chain_confidence(chains, self.config.min_confidence)

        logger.info(f"✓ Stage 2 complete: Found {len(chains)} taint chains")

        # ============ STAGE 3: CFG-based Verification ============
        if self.config.verification_enabled and chains:
            logger.info(
                "Stage 3: Verifying chains with independent source CFG "
                f"(verification_level='{self.config.verification_level}', "
                f"timeout={self.config.symbolic_timeout}s)..."
            )
            self.verification_engine = VerificationEngine(
                config=self.config,
                max_loop_iterations=10,
                symbolic_timeout=self.config.symbolic_timeout,
            )
            verification_results = self.verification_engine.verify_all_chains(
                chains, source_code
            )

            verified_chains = list(verification_results["verified"])
            unverifiable_chains = list(
                verification_results.get("unverifiable", [])
            )
            rejected_chains = list(verification_results.get("false", []))
            verification_rate = verification_results["verification_rate"]
            verification_evidence = verification_results.get("results", [])

            logger.info(
                f"Stage 3 complete: {len(verified_chains)} confirmed, "
                f"{len(unverifiable_chains)} unverifiable, "
                f"{len(rejected_chains)} rejected "
                f"(confirmation rate {verification_rate:.1%})"
            )
        elif not chains:
            verified_chains = []
            unverifiable_chains = []
            rejected_chains = []
            verification_rate = 0.0
            verification_evidence = []
            logger.info("Stage 3: No candidate chains to verify")
        else:
            verified_chains = []
            unverifiable_chains = list(chains)
            rejected_chains = []
            verification_rate = 0.0
            verification_evidence = []
            logger.warning(
                "Stage 3: Verification disabled; candidate chains remain "
                "unverified and will not be reported as confirmed"
            )

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
            "chains_unverifiable": len(unverifiable_chains),
            "chains_rejected": len(rejected_chains),
            "verification_rate": verification_rate,
            "chains_cfg_reachable": sum(
                result.cfg_status.value == "verified"
                for result in verification_evidence
            ),
            "chains_symbolically_verified": sum(
                result.symbolic_status is not None
                and result.symbolic_status.value == "verified"
                for result in verification_evidence
            ),
            "explanations_generated": len(explanations),
            "graph_nodes": graph.number_of_nodes(),
            "graph_edges": graph.number_of_edges(),
            "candidate_chains_truncated": candidate_chains_truncated,
            "candidate_selection_limited": candidate_chains_truncated,
            "candidate_pairs_ranked": int(
                getattr(self.path_finder, "candidate_pairs_ranked", len(chains))
            ),
            "candidate_pairs_ranked_out": int(
                getattr(self.path_finder, "ranked_out_count", 0)
            ),
            "reachable_pairs_seen": int(
                getattr(self.path_finder, "reachable_pairs_seen", len(chains))
            ),
        }

        result = {
            "total_chains": len(chains),
            "verified_chains": verified_chains,
            "unverifiable_chains": unverifiable_chains,
            "rejected_chains": rejected_chains,
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

            raw = file.read_bytes()
            if b"\x00" in raw:
                logger.warning(
                    f"Skipping binary-looking Java file containing NUL bytes: "
                    f"{file_path}"
                )
                return ""

            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError as error:
                if file_path not in self._encoding_warning_paths:
                    logger.warning(
                        "Decoding non-UTF-8 Java file with replacement "
                        f"characters: {file_path} (byte offset {error.start})"
                    )
                    self._encoding_warning_paths.add(file_path)
                content = raw.decode("utf-8", errors="replace")

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
