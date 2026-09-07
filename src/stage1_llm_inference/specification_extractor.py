"""Specification extractor using LLM for source and sink detection."""

import asyncio
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from src.core.models import (
    CodeLocation,
    Sanitizer,
    Source,
    Sink,
    SinkCategory,
    Specification,
    VulnerabilityType,
)
from src.core.source_sink_classifier import classify_source, classify_sink
from src.core.exceptions import ParsingError, LLMError
from src.stage1_llm_inference.llm_client import SimpleLLMClient
from src.stage1_llm_inference.ast_parser import JavaASTParser
from src.stage1_llm_inference.prompt_templates import (
    build_combined_prompt,
    build_missing_source_repair_prompt,
)
from src.stage1_llm_inference.sanitizer_detector import StaticSanitizerDetector
from src.stage1_llm_inference.spec_cache import SpecCache
from src.utils.logger import get_logger

logger = get_logger()


class SimpleSpecificationExtractor:
    """Extract sources, sinks, and sanitizers from Java code using an LLM.

    This extractor splits code into functions and analyzes each for sources and sinks
    using an LLM client.

    Attributes:
        llm_client: SimpleLLMClient instance for LLM queries.
        confidence_threshold: Minimum confidence to include sources/sinks (default 0.5).
    """

    def __init__(
        self,
        llm_client: Optional[SimpleLLMClient],
        confidence_threshold: float = 0.5,
        spec_cache: Optional[SpecCache] = None,
        llm_provider: str = "",
        max_concurrent_functions: int = 1,
        batch_max_chars: int = 0,
        analysis_backend: str = "llm",
        analysis_mode: str = "exhaustive",
        cache_read_enabled: bool = True,
    ) -> None:
        """Initialize the specification extractor.

        Args:
            llm_client: SimpleLLMClient instance for LLM-based analysis.
            confidence_threshold: Minimum confidence score (0.0-1.0) to include items.
            spec_cache: Optional ``SpecCache`` for persistent per-file caching.
                When provided, ``extract`` returns cached results on content
                match and writes new results back. Pass ``None`` to disable.
            llm_provider: Provider identifier (``"openai"`` / ``"ollama"``).
                Used as part of the cache key so the same model on different
                providers (e.g. OpenAI vs local proxy) can't collide. Required
                when ``spec_cache`` is set; ignored otherwise.

        Raises:
            ValueError: If confidence_threshold is not in [0.0, 1.0].
        """
        if not 0.0 <= confidence_threshold <= 1.0:
            raise ValueError("confidence_threshold must be between 0.0 and 1.0")

        self.llm_client = llm_client
        self.confidence_threshold = confidence_threshold
        self.ast_parser = JavaASTParser()
        self.sanitizer_detector = StaticSanitizerDetector()
        self.spec_cache = spec_cache
        self.llm_provider = llm_provider
        self.max_concurrent_functions = max_concurrent_functions
        self.batch_max_chars = batch_max_chars
        if analysis_backend not in ("llm", "static", "hybrid"):
            raise ValueError(
                "analysis_backend must be 'llm', 'static', or 'hybrid'"
            )
        if analysis_backend in ("llm", "hybrid") and llm_client is None:
            raise ValueError(f"analysis_backend='{analysis_backend}' requires an LLM client")
        if analysis_mode not in ("targeted", "exhaustive"):
            raise ValueError(
                "analysis_mode must be 'targeted' or 'exhaustive'"
            )
        self.analysis_backend = analysis_backend
        self.analysis_mode = analysis_mode
        self.cache_read_enabled = cache_read_enabled

        logger.info(
            f"Initialized SimpleSpecificationExtractor with threshold={confidence_threshold}"
        )
        logger.debug("AST parser initialized for improved code analysis")

    # Regex to detect security-relevant patterns at function level
    _FUNC_SECURITY_RE = re.compile(
        r"getParameter|getHeader|getCookies|getInputStream|getReader|getQueryString"
        r"|@RequestParam|@PathVariable|@RequestBody|@RequestHeader|@CookieValue"
        r"|@QueryParam|@FormParam|@HeaderParam|@PathParam"
        r"|HttpServletRequest|HttpServletResponse"
        r"|executeQuery|executeUpdate|prepareStatement|createStatement|execute\("
        r"|createNativeQuery|createQuery"
        r"|Runtime\.getRuntime|ProcessBuilder|exec\("
        r"|setAttribute|getRequestDispatcher|sendRedirect|addCookie|\.write\("
        r"|innerHTML|document\.write|\.html\("
        r"|new\s+File\(|new\s+FileInputStream|Paths\.get|Files\."
        r"|DocumentBuilder|SAXParser|XMLReader|TransformerFactory"
        r"|URL\(|HttpURLConnection|HttpClient|openConnection"
        r"|ObjectInputStream|readObject|XMLDecoder|classForName|\.deserialize\s*\("
        r"|getAttribute"
        r"|RuntimeException|throw\s+new"
    )

    _EMPTY_REVIEW_SOURCE_RE = re.compile(
        r"getParameter|getHeader|getCookies|getInputStream|getReader|getQueryString"
        r"|@RequestParam|@PathVariable|@RequestBody|@RequestHeader|@CookieValue"
        r"|@QueryParam|@FormParam|@HeaderParam|@PathParam"
        r"|\b(?:public|protected)\b[^{};]*\([^)]*[A-Za-z_$][\w$]*[^)]*\)"
    )
    _EMPTY_REVIEW_SINK_RE = re.compile(
        r"executeQuery|executeUpdate|Runtime\.getRuntime|ProcessBuilder|\.exec\s*\("
        r"|sendRedirect"
        r"|new\s+File\s*\(|Files\.(?:copy|write|move)|openConnection"
        r"|classForName|\.deserialize\s*\(|\.readValue\s*\("
    )

    @staticmethod
    def _is_trivial_function(func_code: str) -> bool:
        """True if a function structurally cannot contain taint logic.

        Structural (not keyword-based) so it never hides a 0-day: a function
        is trivial only when its body has no method/constructor calls and is
        at most two statements — i.e. an empty body, a plain field accessor
        (`return this.x;` / `this.x = x;`), or a constant return. Anything
        that calls into other code is analyzed.
        """
        brace = func_code.find("{")
        if brace == -1:
            # No braces: either an abstract/interface decl or a regex-fallback
            # code chunk. Treat the whole text as the "body" and let the
            # call/statement heuristic decide — never blanket-skip, so a
            # brace-less chunk that still contains a sink is not hidden.
            body = func_code
        else:
            body = func_code[brace + 1:]
            rb = body.rfind("}")
            if rb != -1:
                body = body[:rb]
        # A call site is `name(` — distinct from control keywords. If the body
        # invokes anything, treat it as non-trivial (could reach a sink).
        if re.search(r"\b[A-Za-z_]\w*\s*\(", body):
            return False
        statements = [s for s in body.split(";") if s.strip()]
        return len(statements) <= 2

    def _has_potential_sinks(self, source_code: str) -> bool:
        """True if the file structurally COULD contain a sink.

        A sink is, by definition, a method invocation (or constructor call)
        that consumes tainted data. A file with **zero** method invocations
        / object creations anywhere — pure DTOs, marker interfaces, enums
        without methods, ``package-info.java``, empty class shells —
        provably cannot contain a sink.

        We therefore skip the entire LLM call on such files. This is strict-
        ly stronger than the keyword regex prefilter (which guards 0-day
        coverage by definition): "no method invocations" is an AST fact, not
        a heuristic. It cannot hide a sink that uses an unfamiliar API.

        Falls back to ``True`` (analyze) when tree-sitter is unavailable so
        the prefilter never introduces false negatives in degraded mode.
        """
        parser = self.ast_parser.parser
        if parser is None:
            # No AST → be conservative: pretend it could have sinks.
            return True
        try:
            tree = parser.parse(source_code.encode("utf-8"))
        except Exception as e:  # noqa: BLE001 — never block extraction on this
            logger.debug(f"AST parse for prefilter failed: {e}; assuming sinks possible")
            return True

        # Iterative BFS — Python recursion limit could bite on deeply nested
        # generics or lambdas. The call set is small; either we find a call
        # node quickly or there are truly zero.
        stack = [tree.root_node]
        # ``method_invocation`` and ``object_creation_expression`` cover
        # ``foo.bar(x)`` and ``new Foo(x)`` — the only ways to consume tainted
        # data in Java. Annotations are intentionally NOT counted: they're
        # syntactically calls but don't execute application code.
        call_node_types = {"method_invocation", "object_creation_expression"}
        while stack:
            node = stack.pop()
            if node.type in call_node_types:
                return True
            stack.extend(node.children)
        return False

    async def extract(
        self, source_code: str, file_path: str = "", model: str = "gpt-4-turbo"
    ) -> Specification:
        """Extract security specification from Java source code.

        Cache- and prefilter-aware wrapper. Order of checks (cheap→expensive):

        1. ``spec_cache.get`` — if a prior identical run cached this file's
           specification, replay it verbatim (no LLM call).
        2. ``_has_potential_sinks`` — if the file structurally has no method
           invocations, return an empty specification (no LLM call). The
           result is cached so subsequent runs short-circuit at step 1.
        3. ``_extract_uncached`` — the original full LLM-driven pipeline. The
           result is cached for next time.

        Args:
            source_code: Java source code to analyze.
            file_path: Optional file path for code location tracking.
            model: LLM model name to use.

        Returns:
            Specification object containing extracted sources and sinks.

        Raises:
            ValueError: If source_code is empty.
            LLMError: If LLM analysis fails.
        """
        if not source_code or not source_code.strip():
            raise ValueError("source_code cannot be empty")

        cache_kwargs = self._cache_kwargs(model)

        # Step 1: cache hit?
        if (
            self.cache_read_enabled
            and self.spec_cache is not None
            and cache_kwargs is not None
        ):
            cached = self.spec_cache.get(source_code, **cache_kwargs)
            if cached is not None:
                logger.info(
                    f"Cache hit for {file_path or 'inline code'} "
                    f"(skipping Stage 1 LLM)"
                )
                for source in cached.sources:
                    source.source_category = classify_source(source)
                for sink in cached.sinks:
                    sink.sink_category = classify_sink(sink)
                plausible = [sink for sink in cached.sinks if self._is_plausible_sink(sink)]
                if len(plausible) != len(cached.sinks):
                    cached = cached.model_copy(update={"sinks": plausible})
                return cached

        # Step 2: AST prefilter — zero possibility of a sink in this file.
        if not self._has_potential_sinks(source_code):
            logger.info(
                f"Skipping {file_path or 'inline code'}: AST prefilter "
                f"found no method invocations (sink impossible)"
            )
            empty = Specification(
                sources=[],
                sinks=[],
                sanitizers=[],
                llm_model=model if self.analysis_backend != "static" else "",
                extraction_backend=self.analysis_backend,
            )
            if self.spec_cache is not None and cache_kwargs is not None:
                self.spec_cache.put(source_code, empty, **cache_kwargs)
            return empty

        # Step 3: the full LLM-driven extraction (original logic).
        spec = await self._extract_uncached(source_code, file_path, model)
        if (
            spec.extraction_complete
            and self.spec_cache is not None
            and cache_kwargs is not None
        ):
            self.spec_cache.put(source_code, spec, **cache_kwargs)
        elif not spec.extraction_complete:
            logger.warning(
                f"Not caching incomplete extraction for {file_path or 'inline code'}"
            )
        return spec

    def _cache_kwargs(self, model: str) -> Optional[Dict[str, Any]]:
        """Build the keyword args used to compute a stable cache key.

        Returns ``None`` if no provider was wired in — caching is skipped
        rather than producing keys that could collide across providers.
        """
        if not self.llm_provider:
            return None
        return {
            "llm_provider": self.llm_provider,
            "llm_model": model,
            "min_confidence": self.confidence_threshold,
            "extractor_options": (
                f"analysis_backend={self.analysis_backend};"
                f"analysis_mode={self.analysis_mode};"
                f"batch_max_chars={self.batch_max_chars}"
            ),
        }

    async def _extract_uncached(
        self, source_code: str, file_path: str = "", model: str = "gpt-4-turbo"
    ) -> Specification:
        """Original LLM-driven extraction pipeline (no cache, no prefilter).

        Split out from ``extract`` so the cache/prefilter layer can wrap it
        without touching the LLM logic.
        """
        logger.info(f"Starting extraction from {file_path or 'inline code'}")

        # Extract global context (imports, classes)
        imports = self._extract_imports(source_code)
        classes = self._extract_classes(source_code)
        logger.debug(f"Extracted {len(imports)} imports and {len(classes)} classes")

        # Split code into functions
        functions = self._split_into_functions(source_code)
        logger.debug(f"Split code into {len(functions)} functions")

        # Targeted mode bounds provider cost by sending only known security
        # boundaries/operations. Exhaustive mode keeps novel-API coverage by
        # analyzing every non-trivial function. Backend selection is orthogonal:
        # static never calls the model, while llm/hybrid do.
        # VTC_FAST_PREFILTER additionally enables project-level file exclusion.
        fast_prefilter = os.getenv("VTC_FAST_PREFILTER", "false").lower() in (
            "true", "1", "yes", "on"
        )
        targeted = self.analysis_mode == "targeted" or fast_prefilter
        use_llm = self.analysis_backend in ("llm", "hybrid")

        analyzable: List[Tuple[str, str, int, Optional[Dict[str, Any]]]] = []
        skipped_funcs = 0
        for entry in functions:
            func_name, func_code = entry[0], entry[1]
            if self._is_trivial_function(func_code):
                skipped_funcs += 1
                continue
            if not use_llm:
                skipped_funcs += 1
                continue
            if targeted and not self._FUNC_SECURITY_RE.search(func_code):
                logger.debug(
                    f"[{self.analysis_mode}] Skipping {func_name}: "
                    "no security boundary or operation"
                )
                skipped_funcs += 1
                continue
            analyzable.append(entry)

        # Stable-sort: security-pattern hits first, original order preserved
        # within each group.
        analyzable.sort(
            key=lambda e: 0 if self._FUNC_SECURITY_RE.search(e[1]) else 1
        )

        analysis_entries = analyzable
        if self.batch_max_chars and analyzable:
            analysis_entries = self._build_llm_batches(
                source_code, analyzable, self.batch_max_chars
            )
            logger.info(
                f"Batched {len(analyzable)} functions into "
                f"{len(analysis_entries)} LLM request(s)"
            )

        all_sources: List[Source] = []
        all_sinks: List[Sink] = []
        all_sanitizers: List[Sanitizer] = []

        semaphore = asyncio.Semaphore(self.max_concurrent_functions)

        async def _analyze_function(
            entry: Tuple[str, str, int, Optional[Dict[str, Any]]]
        ) -> Tuple[List[Source], List[Sink], List[Sanitizer], Optional[str]]:
            func_name, func_code, line_offset, func_info = entry
            try:
                async with semaphore:
                    with logger.contextualize(
                        target=file_path or "inline-code",
                        function_name=func_name,
                    ):
                        logger.debug(f"Analyzing function: {func_name}")

                        # Build context for this function
                        class_info = classes[0] if classes else None

                        combined_prompt = build_combined_prompt(
                            code=func_code,
                            function_info=func_info,
                            class_info=class_info,
                            imports=imports,
                        )

                        # A parse retry asks the model to regenerate malformed JSON.
                        # Transport and empty-response retries are handled by the client.
                        response = None
                        for attempt in range(2):
                            try:
                                response = await self.llm_client.chat_with_json_prompt(
                                    combined_prompt
                                )
                                break
                            except ParsingError:
                                if attempt == 0:
                                    logger.warning(
                                        f"JSON parse failed for {func_name}, retrying..."
                                    )
                                else:
                                    raise

                sources: List[Source] = []
                sinks: List[Sink] = []
                sanitizers: List[Sanitizer] = []
                if response and "sources" in response:
                    sources = self._parse_llm_sources(
                        response, file_path, line_offset,
                        function_name=func_name,
                    )
                    logger.debug(f"Found {len(sources)} sources in {func_name}")

                if response and "sinks" in response:
                    sinks = self._parse_llm_sinks(
                        response, file_path, line_offset,
                        function_name=func_name,
                    )
                    logger.debug(f"Found {len(sinks)} sinks in {func_name}")
                    sources.extend(self._parse_llm_sink_attributed_sources(
                        response, file_path, line_offset,
                        function_name=func_name,
                    ))
                    sources = self._deduplicate_sources(sources)
                if sinks and not sources:
                    try:
                        async with semaphore:
                            with logger.contextualize(
                                target=file_path or "inline-code",
                                function_name=func_name,
                            ):
                                repair_response = await self.llm_client.chat_with_json_prompt(
                                    build_missing_source_repair_prompt(
                                        func_code, response.get("sinks", [])
                                    )
                                )
                        sources = self._parse_llm_sources(
                            repair_response, file_path, line_offset,
                            function_name=func_name,
                        )
                        logger.info(
                            f"Source consistency repair for {func_name}: "
                            f"recovered {len(sources)} source(s)"
                        )
                    except Exception as e:
                        # The complete first-pass answer remains usable; this
                        # bounded repair is recall enhancement, not extraction.
                        logger.warning(
                            f"Source consistency repair failed for {func_name}: "
                            f"{type(e).__name__}: {e}"
                        )
                if response and "sanitizers" in response:
                    sanitizers = self._parse_llm_sanitizers(
                        response, file_path, line_offset,
                        function_name=func_name,
                    )
                    logger.debug(
                        f"Found {len(sanitizers)} sanitizers in {func_name}"
                    )
                return sources, sinks, sanitizers, None

            except (ParsingError, LLMError) as e:
                logger.warning(f"Failed to analyze function {func_name}: {str(e)}")
                logger.debug(f"Raw error details for {func_name}: {repr(e)}")
                return [], [], [], f"{func_name}: {e}"
            except Exception as e:
                logger.error(f"Unexpected error analyzing {func_name}: {str(e)}")
                logger.debug(f"Raw error details for {func_name}: {repr(e)}")
                return [], [], [], f"{func_name}: {type(e).__name__}: {e}"

        # gather preserves input order while allowing a bounded number of calls.
        initial_results = await asyncio.gather(
            *(_analyze_function(entry) for entry in analysis_entries)
        )
        function_results: List[
            Tuple[List[Source], List[Sink], List[Sanitizer], Optional[str]]
        ] = []
        retry_entries: List[Tuple[str, str, int, Optional[Dict[str, Any]]]] = []
        for entry, result in zip(analysis_entries, initial_results):
            if result[3] is None:
                function_results.append(result)
                continue

            split_entries = self._split_failed_llm_batch(
                source_code,
                analyzable,
                entry,
                self.batch_max_chars,
            )
            if len(split_entries) > 1:
                logger.warning(
                    f"Retrying failed {entry[0]} as {len(split_entries)} "
                    "smaller LLM batches"
                )
                retry_entries.extend(split_entries)
            else:
                function_results.append(result)

        if retry_entries:
            function_results.extend(await asyncio.gather(
                *(_analyze_function(entry) for entry in retry_entries)
            ))

        extraction_errors: List[str] = []
        for sources, sinks, sanitizers, error in function_results:
            all_sources.extend(sources)
            all_sinks.extend(sinks)
            all_sanitizers.extend(sanitizers)
            if error:
                extraction_errors.append(error)

        if extraction_errors:
            logger.warning(
                f"Stage 1 incomplete for {file_path or 'inline code'}: "
                f"{len(extraction_errors)}/{len(analysis_entries)} LLM requests failed"
            )

        if skipped_funcs:
            logger.info(
                f"Analyzed {len(analyzable)}/{len(functions)} functions; "
                f"skipped {skipped_funcs} "
                f"({self.analysis_mode} analysis)"
            )

        if self.analysis_backend in ("static", "hybrid"):
            # These candidates are an explicit baseline/augmentation, never an
            # implicit part of an LLM result.
            static_sources, static_sinks = self._extract_static_candidates(
                source_code, file_path, functions
            )
            logger.info(
                f"Static backend contributed {len(static_sources)} sources and "
                f"{len(static_sinks)} sinks"
            )
            # Deterministic candidates carry exact operation lines. In hybrid
            # mode they win only duplicate endpoint identities.
            all_sources = self._deduplicate_sources(static_sources + all_sources)
            all_sinks = self._deduplicate_sinks(static_sinks + all_sinks)
            all_sanitizers.extend(
                self.sanitizer_detector.detect(source_code, file_path)
            )

        # Populate code_snippet from source code and classify categories.
        # LLMs often report a slightly-off line number (function header instead
        # of body, off-by-one, etc.). Scan a small window around the reported
        # line for the variable name to recover the real declaration site.
        source_lines = source_code.splitlines()

        def _scope_for_line(line_number: int) -> Tuple[Optional[str], Optional[str]]:
            for func_name, func_code, offset, info in functions:
                info = info or {}
                start = info.get("start_line", offset + 1)
                end = info.get("end_line", start + func_code.count("\n"))
                if start <= line_number <= end:
                    return func_name, info.get("class_name")
            return None, None

        def _resolve_snippet(
            line_number: int,
            variable_name: str,
            *,
            prefer_sink_operation: bool = False,
            function_name: Optional[str] = None,
        ) -> Tuple[str, int]:
            n = len(source_lines)
            primary_idx = line_number - 1
            if not (0 <= primary_idx < n):
                primary_idx = 0
            primary = source_lines[primary_idx] if 0 <= primary_idx < n else ""

            scoped_info = None
            if function_name and not function_name.startswith(("__batch_", "__file__")):
                scoped_info = next(
                    (
                        entry[3] or {}
                        for entry in functions
                        if entry[0] == function_name
                    ),
                    None,
                )
            scope_start = max(0, (scoped_info or {}).get("start_line", 1) - 1)
            scope_end = min(n, (scoped_info or {}).get("end_line", n))

            def in_scope(idx: int) -> bool:
                return scoped_info is None or scope_start <= idx < scope_end

            def is_candidate(line: str) -> bool:
                stripped = line.strip()
                if re.match(r"^(?:(?:import|package)\b|//|/\*|\*)", stripped):
                    return False
                if (
                    variable_name
                    and not self._mentions_identifier(line, variable_name)
                ):
                    return False
                return not (
                    prefer_sink_operation
                    and self._is_non_operation_sink_text(line, variable_name)
                )

            if in_scope(primary_idx) and is_candidate(primary):
                return primary.strip(), line_number if 1 <= line_number <= n else primary_idx + 1
            for offset in (1, -1, 2, -2, 3, -3, 4, -4, 5, -5):
                idx = primary_idx + offset
                if 0 <= idx < n and in_scope(idx) and is_candidate(source_lines[idx]):
                    return source_lines[idx].strip(), idx + 1
            if scoped_info:
                for idx in range(scope_start, scope_end):
                    if is_candidate(source_lines[idx]):
                        return source_lines[idx].strip(), idx + 1
            # Last resort: full-file scan for the variable's first appearance.
            # Handles cases where the LLM reports the wrong absolute line
            # (e.g. function-relative line never recombined with offset).
            for idx, line in enumerate(source_lines):
                if is_candidate(line):
                    return line.strip(), idx + 1
            return primary.strip(), line_number

        def _normalize_source(src: Source) -> None:
            snippet, resolved_line = _resolve_snippet(
                src.location.line_number,
                src.variable_name,
                function_name=src.location.function_name,
            )
            src.code_snippet = snippet
            update: Dict[str, Any] = {}
            if resolved_line != src.location.line_number:
                update["line_number"] = resolved_line
            if (src.location.function_name or "").startswith(("__batch_", "__file__")):
                function_name, class_name = _scope_for_line(resolved_line)
                update["function_name"] = function_name
                update["class_name"] = class_name
            if update:
                src.location = src.location.model_copy(
                    update=update
                )
            src.source_category = classify_source(src)

        def _normalize_sink(snk: Sink) -> None:
            snippet, resolved_line = _resolve_snippet(
                snk.location.line_number,
                snk.variable_name,
                prefer_sink_operation=True,
                function_name=snk.location.function_name,
            )
            snk.code_snippet = snippet
            update = {}
            if resolved_line != snk.location.line_number:
                update["line_number"] = resolved_line
            if (snk.location.function_name or "").startswith(("__batch_", "__file__")):
                function_name, class_name = _scope_for_line(resolved_line)
                update["function_name"] = function_name
                update["class_name"] = class_name
            if update:
                snk.location = snk.location.model_copy(
                    update=update
                )
            terminal = self._find_terminal_sink_use(
                source_lines, functions, snk, resolved_line
            )
            if terminal is not None:
                terminal_line, terminal_snippet = terminal
                snk.location = snk.location.model_copy(
                    update={"line_number": terminal_line}
                )
                snk.code_snippet = terminal_snippet
            snk.sink_category = classify_sink(snk)

        for src in all_sources:
            _normalize_source(src)

        for snk in all_sinks:
            _normalize_sink(snk)

        if use_llm:
            source_functions = {
                source.location.function_name for source in all_sources
            }
            sink_functions = {
                sink.location.function_name
                for sink in all_sinks
                if self._is_plausible_sink(sink)
            }
            uncovered_entries = [
                entry for entry in analyzable
                if self._needs_empty_security_review(entry[1])
                and (
                    entry[0] not in source_functions
                    or entry[0] not in sink_functions
                )
            ][:4]
            if uncovered_entries:
                coverage_results = await asyncio.gather(*(
                    _analyze_function(entry) for entry in uncovered_entries
                ))
                recovered = 0
                for sources, sinks, sanitizers, _error in coverage_results:
                    for source in sources:
                        _normalize_source(source)
                    for sink in sinks:
                        _normalize_sink(sink)
                    all_sources.extend(sources)
                    all_sinks.extend(sinks)
                    all_sanitizers.extend(sanitizers)
                    recovered += len(sources) + len(sinks)
                logger.info(
                    f"Method coverage review recovered {recovered} endpoint(s) "
                    f"across {len(uncovered_entries)} scope(s)"
                )

        for sanitizer in all_sanitizers:
            variable = sanitizer.variable_name or ""
            snippet, resolved_line = _resolve_snippet(
                sanitizer.location.line_number,
                variable,
                function_name=sanitizer.location.function_name,
            )
            sanitizer.code_snippet = snippet
            update = {}
            if resolved_line != sanitizer.location.line_number:
                update["line_number"] = resolved_line
            if (sanitizer.location.function_name or "").startswith(
                ("__batch_", "__file__")
            ):
                function_name, class_name = _scope_for_line(resolved_line)
                update["function_name"] = function_name
                update["class_name"] = class_name
            if update:
                sanitizer.location = sanitizer.location.model_copy(update=update)

        if use_llm:
            source_functions = {
                source.location.function_name
                for source in all_sources
                if source.location.function_name
            }
            function_entries = {
                name: (code, offset)
                for name, code, offset, _info in functions
            }
            missing_source_scopes: Dict[str, List[Sink]] = {}
            for sink in all_sinks:
                function_name = sink.location.function_name
                entry = function_entries.get(function_name or "")
                if (
                    function_name
                    and function_name not in source_functions
                    and entry is not None
                    and self._needs_empty_security_review(entry[0])
                    and self._is_plausible_sink(sink)
                ):
                    missing_source_scopes.setdefault(function_name, []).append(sink)

            async def _repair_method_sources(
                function_name: str, method_sinks: List[Sink]
            ) -> List[Source]:
                func_code, line_offset = function_entries[function_name]
                sink_payload = [
                    {
                        "line": max(1, sink.location.line_number - line_offset),
                        "variable": sink.variable_name,
                        "type": sink.type,
                        "vulnerability_type": sink.vulnerability_type.value,
                        "reasoning": sink.reasoning or "",
                    }
                    for sink in method_sinks
                ]
                try:
                    async with semaphore:
                        response = await self.llm_client.chat_with_json_prompt(
                            build_missing_source_repair_prompt(
                                func_code, sink_payload
                            )
                        )
                    return self._parse_llm_sources(
                        response,
                        file_path,
                        line_offset,
                        function_name=function_name,
                    )
                except Exception as error:
                    logger.warning(
                        f"Method source consistency repair failed for "
                        f"{function_name}: {type(error).__name__}: {error}"
                    )
                    return []

            if missing_source_scopes:
                repaired_groups = await asyncio.gather(*(
                    _repair_method_sources(function_name, method_sinks)
                    for function_name, method_sinks in list(
                        missing_source_scopes.items()
                    )[:4]
                ))
                for repaired_sources in repaired_groups:
                    for source in repaired_sources:
                        snippet, resolved_line = _resolve_snippet(
                            source.location.line_number,
                            source.variable_name,
                            function_name=source.location.function_name,
                        )
                        source.code_snippet = snippet
                        if resolved_line != source.location.line_number:
                            source.location = source.location.model_copy(
                                update={"line_number": resolved_line}
                            )
                        source.source_category = classify_source(source)
                    all_sources.extend(repaired_sources)
                logger.info(
                    "Method source consistency review recovered "
                    f"{sum(map(len, repaired_groups))} source(s) across "
                    f"{len(repaired_groups)} scope(s)"
                )

        # Batch endpoints initially carry a synthetic scope. Deduplicate again
        # after mapping them back to AST methods so static and LLM endpoints do
        # not survive as two copies of the same source/sink.
        all_sources = self._deduplicate_sources(all_sources)
        plausible_sinks = [sink for sink in all_sinks if self._is_plausible_sink(sink)]
        rejected_sinks = len(all_sinks) - len(plausible_sinks)
        if rejected_sinks:
            logger.info(
                f"Structural sink filter removed {rejected_sinks} non-operation endpoints"
            )
        all_sinks = self._deduplicate_sinks(plausible_sinks)

        logger.info(
            f"Extraction complete: {len(all_sources)} sources, {len(all_sinks)} sinks, "
            f"{len(all_sanitizers)} sanitizers"
        )

        return Specification(
            sources=all_sources,
            sinks=all_sinks,
            sanitizers=all_sanitizers,
            llm_model=model if use_llm else "",
            extraction_backend=self.analysis_backend,
            extraction_complete=not extraction_errors,
            extraction_errors=extraction_errors,
        )

    @classmethod
    def _needs_empty_security_review(cls, func_code: str) -> bool:
        """Route suspicious empty first passes to one more LLM review."""
        return bool(
            cls._EMPTY_REVIEW_SOURCE_RE.search(func_code)
            and cls._EMPTY_REVIEW_SINK_RE.search(func_code)
        )

    @staticmethod
    def _find_terminal_sink_use(
        source_lines: List[str],
        functions: List[Tuple[str, str, int, Optional[Dict[str, Any]]]],
        sink: Sink,
        current_line: int,
    ) -> Optional[Tuple[int, str]]:
        """Move an LLM-selected sink variable to its concrete terminal use."""
        variable = sink.variable_name
        function_name = sink.location.function_name
        if not variable or not function_name:
            return None

        info = next(
            (entry[3] or {} for entry in functions if entry[0] == function_name),
            None,
        )
        if not info:
            return None
        start = max(1, info.get("start_line", current_line))
        end = min(len(source_lines), info.get("end_line", current_line))
        escaped = re.escape(variable)
        vuln = sink.vulnerability_type
        if vuln is VulnerabilityType.COMMAND_INJECTION:
            pattern = re.compile(
                rf"(?:\.exec|ProcessBuilder)\s*\([^;]*\b{escaped}\b"
            )
        elif vuln is VulnerabilityType.OPEN_REDIRECT:
            pattern = re.compile(
                rf"(?:sendRedirect|redirect)\s*\([^;]*\b{escaped}\b"
                rf"|setHeader\s*\(\s*[\"']Location[\"'][^;]*\b{escaped}\b"
            )
        elif vuln is VulnerabilityType.XSS:
            pattern = re.compile(
                rf"(?:print|write|sendError)\w*\s*\([^;]*\b{escaped}\b"
            )
        else:
            return None

        candidates = [
            (line_number, source_lines[line_number - 1].strip())
            for line_number in range(start, end + 1)
            if pattern.search(source_lines[line_number - 1])
        ]
        if not candidates:
            return None
        later = [candidate for candidate in candidates if candidate[0] >= current_line]
        return (later or candidates)[-1]

    @staticmethod
    def _build_llm_batches(
        source_code: str,
        functions: List[Tuple[str, str, int, Optional[Dict[str, Any]]]],
        max_chars: int,
    ) -> List[Tuple[str, str, int, Optional[Dict[str, Any]]]]:
        """Group functions into contiguous source slices with stable line offsets."""
        if len(source_code) <= max_chars:
            return [("__file__", source_code, 0, None)]

        source_lines = source_code.splitlines(keepends=True)
        spans: List[Tuple[int, int]] = []
        for _name, func_code, offset, info in functions:
            info = info or {}
            start = max(1, info.get("start_line", offset + 1))
            end = max(start, info.get("end_line", start + func_code.count("\n")))
            spans.append((start, min(len(source_lines), end)))
        spans.sort()

        groups: List[Tuple[int, int]] = []
        for start, end in spans:
            if not groups:
                groups.append((start, end))
                continue
            group_start, group_end = groups[-1]
            projected_end = max(group_end, end)
            projected = "".join(source_lines[group_start - 1:projected_end])
            if len(projected) <= max_chars:
                groups[-1] = (group_start, projected_end)
            else:
                groups.append((start, end))

        batches: List[Tuple[str, str, int, Optional[Dict[str, Any]]]] = []
        for index, (start, end) in enumerate(groups, 1):
            code = "".join(source_lines[start - 1:end])
            batches.append((f"__batch_{index}", code, start - 1, None))
        return batches

    @classmethod
    def _split_failed_llm_batch(
        cls,
        source_code: str,
        functions: List[Tuple[str, str, int, Optional[Dict[str, Any]]]],
        failed_entry: Tuple[str, str, int, Optional[Dict[str, Any]]],
        max_chars: int,
    ) -> List[Tuple[str, str, int, Optional[Dict[str, Any]]]]:
        """Split one failed synthetic batch into smaller method-aligned chunks.

        This is a recovery path for providers that return truncated or malformed
        JSON for a large prompt. Individual method entries are left untouched:
        retrying an identical prompt after the normal parse retry would only add
        latency without changing its size.
        """
        failed_name, failed_code, failed_offset, _failed_info = failed_entry
        if max_chars <= 1 or not failed_name.startswith("__"):
            return [failed_entry]

        failed_start = failed_offset + 1
        failed_end = failed_offset + max(1, failed_code.count("\n") + 1)
        members = []
        for entry in functions:
            _name, func_code, offset, info = entry
            info = info or {}
            start = max(1, info.get("start_line", offset + 1))
            end = max(start, info.get("end_line", start + func_code.count("\n")))
            if start >= failed_start and end <= failed_end:
                members.append(entry)

        if len(members) < 2:
            return [failed_entry]

        retry_limit = max(1, max_chars // 2)
        split_entries = cls._build_llm_batches(source_code, members, retry_limit)
        return split_entries if len(split_entries) > 1 else [failed_entry]

    def _extract_static_candidates(
        self,
        source_code: str,
        file_path: str,
        functions: List[Tuple[str, str, int, Optional[Dict[str, Any]]]],
    ) -> Tuple[List[Source], List[Sink]]:
        """Extract high-signal endpoints that do not require model inference."""
        lines = source_code.splitlines()
        sources: List[Source] = []
        sinks: List[Sink] = []

        def context_for_line(line_number: int) -> Tuple[Optional[str], Optional[str]]:
            for func_name, func_code, offset, info in functions:
                if not info:
                    continue
                start = info.get("start_line", offset + 1)
                end = info.get("end_line", start + func_code.count("\n"))
                if start <= line_number <= end:
                    return func_name, info.get("class_name")
            return None, None

        def location(line_number: int) -> CodeLocation:
            func_name, class_name = context_for_line(line_number)
            return CodeLocation(
                file_path=file_path,
                line_number=max(1, line_number),
                function_name=func_name,
                class_name=class_name,
            )

        external_annotations = re.compile(
            r"@(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|"
            r"FormParam|QueryParam|HeaderParam)\b"
        )
        dangerous_body = re.compile(
            r"Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder|new\s+File\s*\(|"
            r"Paths\.get\s*\(|classForName\s*\(|\.deserialize\s*\(|"
            r"\.readObject\s*\(|\.readValue\s*\(|"
            r"\.(?:print|write|sendRedirect)\s*\("
        )
        excluded_parameter_types = re.compile(
            r"(Session|Listener|Request|Response|Context|Principal|Realm|Client|User)\b"
        )

        # Formal parameters are reliable framework entry points when explicitly
        # annotated. For sink-bearing utility methods, plain scalar parameters
        # are conservative fallback sources.
        for func_name, func_code, _offset, info in functions:
            if not info:
                continue
            for raw_param in info.get("parameters", []):
                cleaned = re.sub(r"@\w+(?:\([^)]*\))?\s*", "", raw_param).strip()
                identifiers = re.findall(r"\b[A-Za-z_$][\w$]*\b", cleaned)
                if len(identifiers) < 2:
                    continue
                variable = identifiers[-1]
                annotated = bool(external_annotations.search(raw_param))
                trusted_annotation = bool(re.search(r"@(Value|Autowired)\b", raw_param))
                header = func_code.split("{", 1)[0]
                boundary_utility = bool(
                    re.search(r"\bprivate\b|\bpublic\s+static\b", header)
                )
                sink_reaching_param = (
                    dangerous_body.search(func_code)
                    and variable in func_code
                    and not excluded_parameter_types.search(cleaned)
                    and boundary_utility
                    and not trusted_annotation
                )
                if not annotated and not sink_reaching_param:
                    continue
                start = max(1, info.get("start_line", 1))
                end = min(len(lines), start + 20)
                param_line = next(
                    (
                        number
                        for number in range(start, end + 1)
                        if re.search(rf"\b{re.escape(variable)}\b", lines[number - 1])
                    ),
                    start,
                )
                command_boundary = bool(re.search(
                    r"Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder",
                    func_code,
                ))
                sources.append(Source(
                    location=location(param_line),
                    variable_name=variable,
                    type=(
                        "user_input" if annotated
                        else "external_data" if command_boundary
                        else "internal_parameter"
                    ),
                    confidence=0.92 if annotated else 0.72,
                    code_snippet=lines[param_line - 1].strip(),
                    reasoning="Deterministic framework/taint-bearing parameter",
                ))

        source_call = re.compile(
            r"\b(?:var|[A-Za-z_$][\w$<>?\[\].]*)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            r"[^;]*(getParameter|getHeader|getQueryString|readLine|readAllBytes|"
            r"readObject)\s*\("
        )
        for line_number, line in enumerate(lines, 1):
            match = source_call.search(line)
            if match:
                sources.append(Source(
                    location=location(line_number),
                    variable_name=match.group(1),
                    type="external_data",
                    confidence=0.86,
                    code_snippet=line.strip(),
                    reasoning=f"Deterministic input API: {match.group(2)}",
                ))

        def add_sink(
            variable: str,
            line_number: int,
            vuln: VulnerabilityType,
            sink_type: str,
            snippet: str,
            confidence: float = 0.9,
        ) -> None:
            if not variable:
                return
            sinks.append(Sink(
                location=location(line_number),
                variable_name=variable,
                type=sink_type,
                confidence=confidence,
                code_snippet=snippet.strip(),
                vulnerability_type=vuln,
                reasoning="Deterministic dangerous-operation pattern",
            ))

        # Work on complete semicolon-terminated statements so multiline calls
        # and declarations retain their assignment targets and arguments.
        for match in re.finditer(r"[^;{}]+;", source_code, re.DOTALL):
            statement = match.group(0)
            line_number = source_code.count("\n", 0, match.start()) + 1
            compact = re.sub(r"\s+", " ", statement)

            exec_match = re.search(
                r"(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(\s*"
                r"([A-Za-z_$][\w$]*)",
                compact,
            )
            if exec_match:
                add_sink(
                    exec_match.group(1), line_number,
                    VulnerabilityType.COMMAND_INJECTION, "command_execution", statement,
                )

            assignment = re.search(
                r"\b(?:var|[A-Za-z_$][\w$<>?\[\].]*)\s+([A-Za-z_$][\w$]*)\s*=\s*(.*)",
                compact,
            )
            if assignment:
                target, rhs = assignment.group(1), assignment.group(2)
                if re.search(r"new\s+File\s*\(|Paths\.get\s*\(", rhs):
                    add_sink(target, line_number, VulnerabilityType.PATH_TRAVERSAL, "file_path", statement)
                elif re.search(r"classForName\s*\(", rhs):
                    add_sink(target, line_number, VulnerabilityType.CODE_INJECTION, "dynamic_class_loading", statement)
                elif re.search(r"\.deserialize\s*\(|\.readObject\s*\(|\.readValue\s*\(", rhs):
                    add_sink(target, line_number, VulnerabilityType.UNSAFE_DESERIALIZATION, "deserialization", statement)

            deserialize_arg = re.search(
                r"(?:\.deserialize|\.readValue)\s*\(\s*([A-Za-z_$][\w$]*)",
                compact,
            )
            if deserialize_arg and not assignment:
                add_sink(deserialize_arg.group(1), line_number, VulnerabilityType.UNSAFE_DESERIALIZATION, "deserialization", statement)

            output_call = re.search(
                r"\b(?:out|writer|response)\.(?:print|println|write)\s*\((.*)\)\s*;",
                compact,
            )
            if output_call:
                argument = re.sub(r'\"(?:\\.|[^\"\\])*\"', "", output_call.group(1))
                variables = {
                    match.group(0)
                    for match in re.finditer(r"\b[A-Za-z_$][\w$]*\b", argument)
                    if not re.match(r"\s*\(", argument[match.end():])
                    and match.group(0) not in {"this", "null", "true", "false"}
                }
                for variable in sorted(variables):
                    add_sink(variable, line_number, VulnerabilityType.XSS, "html_output", statement)

            redirect_arg = re.search(
                r"(?:sendRedirect|redirect)\s*\(\s*([A-Za-z_$][\w$]*)",
                compact,
            )
            if redirect_arg:
                add_sink(redirect_arg.group(1), line_number, VulnerabilityType.OPEN_REDIRECT, "redirect", statement)

            sql_arg = re.search(
                r"(?:executeQuery|executeUpdate|createQuery|createNativeQuery)\s*"
                r"\(\s*([A-Za-z_$][\w$]*)",
                compact,
            )
            if sql_arg:
                add_sink(
                    sql_arg.group(1), line_number,
                    VulnerabilityType.SQL_INJECTION, "query_execution", statement,
                )

        logger.info(
            f"Static endpoint pass: {len(sources)} sources, {len(sinks)} sinks"
        )
        return sources, sinks

    @staticmethod
    def _deduplicate_sources(sources: List[Source]) -> List[Source]:
        result: List[Source] = []
        seen = set()
        for source in sources:
            key = (
                source.location.file_path,
                source.location.function_name,
                source.variable_name,
            )
            if key not in seen:
                seen.add(key)
                result.append(source)
        return result

    @staticmethod
    def _deduplicate_sinks(sinks: List[Sink]) -> List[Sink]:
        result: List[Sink] = []
        seen = set()
        deterministic_scopes = {
            (
                sink.location.file_path,
                sink.location.function_name,
                sink.vulnerability_type,
            )
            for sink in sinks
            if (sink.reasoning or "").startswith("Deterministic dangerous-operation")
            and sink.location.function_name
        }
        for sink in sinks:
            key = (
                sink.location.file_path,
                sink.location.function_name,
                sink.variable_name,
            )
            scope = (
                sink.location.file_path,
                sink.location.function_name,
                sink.vulnerability_type,
            )
            deterministic = (sink.reasoning or "").startswith(
                "Deterministic dangerous-operation"
            )
            if not deterministic and scope in deterministic_scopes:
                continue
            if key not in seen:
                seen.add(key)
                result.append(sink)
        return result

    @staticmethod
    def _is_plausible_sink(sink: Sink) -> bool:
        """Reject LLM endpoints that are declarations, signatures, or comments."""
        if (sink.reasoning or "").startswith("Deterministic dangerous-operation"):
            return True

        text = sink.code_snippet or ""
        compact = re.sub(r"\s+", " ", text).strip()
        if re.match(
            rf"^this\.{re.escape(sink.variable_name)}\s*=\s*"
            rf"{re.escape(sink.variable_name)}\s*;\s*$",
            compact,
        ):
            return False
        if re.search(r"\.writeValueAs(?:Bytes|String)\s*\(", compact):
            return False
        if (
            sink.vulnerability_type is VulnerabilityType.OTHER
            and sink.sink_category is SinkCategory.DATA_STORAGE
        ):
            return False
        if sink.vulnerability_type is VulnerabilityType.SSRF:
            outbound = re.search(
                r"(?:openConnection|send|execute|postText)\s*\(",
                compact,
            )
            passive = re.search(
                r"=\s*new\s+(?:URL|URI|[A-Za-z_$][\w$]*(?:Runnable|Builder|Request))\b"
                r"|\b(?:persist|save|store|cache)[A-Za-z_$0-9]*\s*\(",
                compact,
            )
            if passive and not outbound:
                return False
        if (
            sink.vulnerability_type is VulnerabilityType.SSRF
            and re.search(r"\.getURL\s*\(", compact)
            and not re.search(
                r"(?:openConnection|send|execute)\s*\(", compact
            )
        ):
            return False
        if (
            sink.vulnerability_type in (
                VulnerabilityType.OTHER,
                VulnerabilityType.OPEN_REDIRECT,
            )
            and re.search(
                rf"\b{re.escape(sink.variable_name)}\s*=\s*"
                r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\."
                r"(?:get|is)[A-Z_$][\w$]*\s*\(",
                compact,
            )
        ):
            return False
        if (
            sink.vulnerability_type is VulnerabilityType.OPEN_REDIRECT
            and re.search(
                r"\b(?:persist|save|store|cache)[A-Za-z_$0-9]*\s*\(",
                compact,
            )
            and not re.search(
                r"(?:sendRedirect|redirect|setHeader)\s*\(",
                compact,
            )
        ):
            return False
        if (
            sink.sink_category is SinkCategory.FRAMEWORK_API
            and re.search(r"=\s*new\s+[A-Za-z_$][\w$<>.]*\s*\(", compact)
            and not re.search(
                rf"\b{re.escape(sink.variable_name)}\s*=", compact
            )
        ):
            return False

        return not SimpleSpecificationExtractor._is_non_operation_sink_text(
            text, sink.variable_name
        )

    @staticmethod
    def _is_non_operation_sink_text(text: str, variable_name: str) -> bool:
        """Return true when a line names a value but performs no sink operation."""

        text = text.strip()
        if not text:
            return False
        if (
            variable_name
            and len(variable_name) > 1
            and not SimpleSpecificationExtractor._mentions_identifier(
                text, variable_name
            )
        ):
            return True
        if re.match(r"^(?:(?:import|package)\b|//|/\*|\*)", text):
            return True
        if re.match(r"^(?:if|for|while|switch|catch)\s*\(", text):
            return True
        if re.match(
            r"^(?:public|protected|private)\b[^{};]*\)\s*"
            r"(?:throws\s+[^{]+)?\{\s*$",
            text,
        ):
            return True
        if re.match(
            rf"^(?:final\s+)?[A-Za-z_$][\w$<>?.\[\]]*\s+"
            rf"{re.escape(variable_name)}\s*[,)]\s*$",
            text,
        ):
            return True

        declaration = re.match(
            r"^(?:(?:public|protected|private|static|final)\s+)*"
            r"[\w$<>,?.\[\] ]+\s+([A-Za-z_$][\w$]*)\s*"
            r"(?:=\s*(.*))?;\s*$",
            text,
            re.DOTALL,
        )
        if declaration and declaration.group(1) == variable_name:
            rhs = (declaration.group(2) or "").strip()
            if not rhs:
                return True
            # A model-selected call result may be a novel sink. Reject only
            # plain copies/literals, not unfamiliar invocations via an allowlist.
            return not bool(re.search(
                r"\bnew\s+[A-Za-z_$][\w$<>.]*\s*\(|"
                r"[A-Za-z_$][\w$]*\s*\(",
                rhs,
            ))
        assignment = re.match(
            rf"^{re.escape(variable_name)}\s*=\s*(.*);\s*$",
            text,
            re.DOTALL,
        )
        if assignment:
            return not bool(re.search(
                r"\bnew\s+[A-Za-z_$][\w$<>.]*\s*\(|"
                r"[A-Za-z_$][\w$]*\s*\(",
                assignment.group(1),
            ))
        return False

    @staticmethod
    def _mentions_identifier(text: str, variable_name: str) -> bool:
        """Match a Java identifier without accepting longer-name substrings."""
        if not variable_name:
            return False
        # Do not bind an endpoint to a word that occurs only inside a literal
        # or a trailing comment.
        text = re.sub(r'"(?:\\.|[^"\\])*"', "", text)
        text = re.sub(r"'(?:\\.|[^'\\])*'", "", text)
        text = re.sub(r"//.*$", "", text)
        return bool(re.search(
            rf"(?<![A-Za-z0-9_$]){re.escape(variable_name)}(?![A-Za-z0-9_$])",
            text,
        ))

    def _split_into_functions(
        self, code: str
    ) -> List[Tuple[str, str, int, Optional[Dict[str, Any]]]]:
        """Split Java code into individual functions using AST parsing.

        Uses tree-sitter AST parser for accurate function extraction, falls back
        to regex if AST parsing is unavailable. Each result is a tuple of
        (function_name, function_code, line_offset, function_info).

        Args:
            code: Java source code.

        Returns:
            List of tuples (function_name, function_code, line_offset, function_info).
        """
        functions: List[Tuple[str, str, int, Optional[Dict[str, Any]]]] = []

        # Try to use AST parser for accurate extraction
        try:
            ast_functions = self.ast_parser.extract_functions(code)

            if ast_functions:
                for func_info in ast_functions:
                    func_name = func_info.get("name", "unknown")
                    func_code = func_info.get("body", "")
                    line_offset = func_info.get("start_line", 0) - 1

                    if func_code:
                        functions.append((func_name, func_code, line_offset, func_info))

                logger.debug(f"Extracted {len(functions)} functions using AST parser")
                return functions

        except Exception as e:
            logger.warning(f"AST-based extraction failed: {str(e)}, falling back to regex")

        # Fallback to regex-based extraction
        logger.debug("Using regex-based function extraction")

        # Simple pattern to match Java methods
        # Matches: [modifiers] [return_type] function_name(...)
        pattern = r"(public|private|protected)?\s+(static\s+)?(\w+)\s+(\w+)\s*\("

        for match in re.finditer(pattern, code):
            start_pos = match.start()
            func_name = match.group(4)  # function_name
            return_type = match.group(3)  # return_type

            # Find line number of this match
            line_num = code[:start_pos].count("\n")

            # Find the function body (simple approach: from here to next method or end)
            start_brace = code.find("{", match.end())
            if start_brace == -1:
                continue

            # Count braces to find end of function
            brace_count = 0
            end_pos = start_brace
            for i, char in enumerate(code[start_brace:], start=start_brace):
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break

            func_code = code[match.start() : end_pos]

            # Build function info dict for context
            func_info_dict: Dict[str, Any] = {
                "name": func_name,
                "return_type": return_type,
                "parameters": [],
                "start_line": line_num + 1,
            }

            functions.append((func_name, func_code, line_num, func_info_dict))

        logger.debug(f"Found {len(functions)} functions in code")

        # If no functions found, treat entire code as one function
        if not functions:
            logger.debug("No functions found, treating entire code as single unit")
            functions.append(("main", code, 0, {"name": "main"}))

        return functions

    def _parse_llm_sources(
        self, response: dict, file_path: str, line_offset: int = 0,
        function_name: Optional[str] = None,
    ) -> List[Source]:
        """Parse LLM response and create Source objects.

        Args:
            response: LLM response as dict (should contain 'sources' key).
            file_path: File path for code locations.
            line_offset: Line number offset for this code segment.
            function_name: Name of the function this source belongs to.

        Returns:
            List of Source objects filtered by confidence threshold.

        Raises:
            ParsingError: If response format is invalid.
        """
        if not isinstance(response, dict):
            raise ParsingError("Response must be a dictionary")

        if "sources" not in response:
            raise ParsingError("Response missing 'sources' key")

        sources: List[Source] = []

        for source_data in response.get("sources", []):
            if not isinstance(source_data, dict):
                logger.warning("Skipping non-object source entry")
                continue
            try:
                # Extract required fields
                line = source_data.get("line")
                raw_variable = source_data.get("variable")
                variable = self._normalize_llm_source_identifier(raw_variable)
                source_type = source_data.get("type")
                confidence = float(source_data.get("confidence", 0.8))

                # Validate required fields
                if not line or not raw_variable or not source_type:
                    logger.warning("Skipping source with missing required fields")
                    continue
                if variable is None:
                    logger.debug("Skipping non-identifier source variable")
                    continue

                # Filter by confidence threshold
                if confidence < self.confidence_threshold:
                    logger.debug(
                        f"Skipping source '{variable}' with confidence {confidence}"
                    )
                    continue

                # Create Source object
                location = CodeLocation(
                    file_path=file_path,
                    line_number=line + line_offset,
                    function_name=function_name,
                )

                source = Source(
                    location=location,
                    variable_name=variable,
                    type=source_type,
                    confidence=confidence,
                    code_snippet="",  # Could be populated from code
                    reasoning=source_data.get("reasoning"),
                )

                sources.append(source)
                logger.debug(f"Parsed source: {variable} at line {line + line_offset}")

            except (KeyError, ValueError, TypeError) as e:
                logger.warning(f"Error parsing source entry ({type(e).__name__})")
                continue

        logger.debug(f"Parsed {len(sources)} sources from LLM response")
        return sources

    def _parse_llm_sinks(
        self, response: dict, file_path: str, line_offset: int = 0,
        function_name: Optional[str] = None,
    ) -> List[Sink]:
        """Parse LLM response and create Sink objects.

        Args:
            response: LLM response as dict (should contain 'sinks' key).
            file_path: File path for code locations.
            line_offset: Line number offset for this code segment.
            function_name: Name of the function this sink belongs to.

        Returns:
            List of Sink objects filtered by confidence threshold.

        Raises:
            ParsingError: If response format is invalid.
        """
        if not isinstance(response, dict):
            raise ParsingError("Response must be a dictionary")

        if "sinks" not in response:
            raise ParsingError("Response missing 'sinks' key")

        sinks: List[Sink] = []

        for sink_data in response.get("sinks", []):
            if not isinstance(sink_data, dict):
                logger.warning("Skipping non-object sink entry")
                continue
            try:
                # Extract required fields
                line = sink_data.get("line")
                variable = sink_data.get("variable")
                sink_type = sink_data.get("type")
                # Open-vocabulary: do NOT default to a concrete class. An
                # absent/unknown label must normalize to OTHER, never silently
                # to SQL_INJECTION.
                vulnerability_type_str = sink_data.get("vulnerability_type", "")
                raw_label = (vulnerability_type_str or "").strip() or None
                cwe_id = sink_data.get("cwe_id")
                if isinstance(cwe_id, (int, float)):
                    # Some models emit `"cwe_id": 601` instead of "CWE-601".
                    cwe_id = f"CWE-{int(cwe_id)}"
                elif isinstance(cwe_id, str):
                    cwe_id = cwe_id.strip() or None
                else:
                    cwe_id = None
                confidence = float(sink_data.get("confidence", 0.8))

                # Validate required fields
                if not line or not variable or not sink_type:
                    logger.warning("Skipping sink with missing required fields")
                    continue
                if not self._is_java_identifier(variable):
                    logger.debug("Skipping non-identifier sink variable")
                    continue

                # Filter by confidence threshold
                if confidence < self.confidence_threshold:
                    logger.debug(f"Skipping sink '{variable}' with confidence {confidence}")
                    continue

                # Normalize the open-vocabulary label to a canonical enum
                # token. This is a deterministic post-step ONLY: the raw
                # label and CWE id are preserved on the Sink regardless.
                try:
                    vuln_type = VulnerabilityType(
                        (vulnerability_type_str or "").strip().lower()
                    )
                except (ValueError, AttributeError):
                    vuln_type = self._infer_vulnerability_type(
                        vulnerability_type_str, sink_type, cwe_id
                    )
                    if vuln_type is VulnerabilityType.OTHER:
                        logger.info(
                            f"Open-vocabulary vuln class kept as OTHER: "
                            f"label={raw_label!r} cwe={cwe_id!r}"
                        )
                    else:
                        logger.debug(
                            f"Normalized vuln label {vulnerability_type_str!r} "
                            f"-> {vuln_type.value}"
                        )

                # Create Sink object
                location = CodeLocation(
                    file_path=file_path,
                    line_number=line + line_offset,
                    function_name=function_name,
                )

                sink = Sink(
                    location=location,
                    variable_name=variable,
                    type=sink_type,
                    confidence=confidence,
                    code_snippet="",  # Could be populated from code
                    vulnerability_type=vuln_type,
                    vulnerability_label=raw_label,
                    cwe_id=cwe_id,
                    reasoning=sink_data.get("reasoning"),
                )

                sinks.append(sink)
                logger.debug(f"Parsed sink: {variable} at line {line + line_offset}")

            except (KeyError, ValueError, TypeError) as e:
                logger.warning(f"Error parsing sink entry ({type(e).__name__})")
                continue

        logger.debug(f"Parsed {len(sinks)} sinks from LLM response")
        return sinks

    def _parse_llm_sanitizers(
        self, response: dict, file_path: str, line_offset: int = 0,
        function_name: Optional[str] = None,
    ) -> List[Sanitizer]:
        """Parse model-reported controls without inventing static sanitizers."""
        if not isinstance(response, dict):
            raise ParsingError("Response must be a dictionary")

        sanitizers: List[Sanitizer] = []
        for sanitizer_data in response.get("sanitizers", []):
            if not isinstance(sanitizer_data, dict):
                logger.warning("Skipping non-object sanitizer entry")
                continue
            try:
                line = sanitizer_data.get("line")
                variable = sanitizer_data.get("variable")
                sanitizer_type = sanitizer_data.get("type")
                confidence = float(sanitizer_data.get("confidence", 0.8))
                effectiveness = float(
                    sanitizer_data.get("effectiveness", confidence)
                )
                vulnerability_types = sanitizer_data.get(
                    "vulnerability_types", []
                )
                if not line or not variable or not sanitizer_type:
                    logger.warning("Skipping sanitizer with missing required fields")
                    continue
                if not self._is_java_identifier(variable):
                    logger.debug("Skipping non-identifier sanitizer variable")
                    continue
                if confidence < self.confidence_threshold:
                    continue
                if not isinstance(vulnerability_types, list):
                    vulnerability_types = [str(vulnerability_types)]

                sanitizers.append(Sanitizer(
                    location=CodeLocation(
                        file_path=file_path,
                        line_number=int(line) + line_offset,
                        function_name=function_name,
                    ),
                    type=str(sanitizer_type),
                    confidence=max(0.0, min(1.0, confidence)),
                    code_snippet="",
                    variable_name=variable,
                    vulnerability_types=[
                        str(item).strip().lower()
                        for item in vulnerability_types if str(item).strip()
                    ],
                    effectiveness=max(0.0, min(1.0, effectiveness)),
                ))
            except (ValueError, TypeError) as e:
                logger.warning(f"Error parsing sanitizer entry ({type(e).__name__})")

        return sanitizers

    def _parse_llm_sink_attributed_sources(
        self, response: dict, file_path: str, line_offset: int = 0,
        function_name: Optional[str] = None,
    ) -> List[Source]:
        """Read sources the model explicitly attached to its sink findings."""
        attributed: List[dict] = []
        for sink_data in response.get("sinks", []) if isinstance(response, dict) else []:
            candidates = sink_data.get("taint_sources", [])
            if not isinstance(candidates, list):
                continue
            attributed.extend(
                candidate for candidate in candidates
                if isinstance(candidate, dict)
            )
        if not attributed:
            return []
        return self._parse_llm_sources(
            {"sources": attributed}, file_path, line_offset, function_name
        )

    # Maps a CWE id to its canonical enum bucket. Used only as a
    # normalization aid when the free-text label is unrecognized but the LLM
    # supplied a CWE — never to invent or override a finding.
    _CWE_TO_VULN = {
        "89": VulnerabilityType.SQL_INJECTION,
        "79": VulnerabilityType.XSS,
        "78": VulnerabilityType.COMMAND_INJECTION,
        "22": VulnerabilityType.PATH_TRAVERSAL,
        "611": VulnerabilityType.XXE,
        "918": VulnerabilityType.SSRF,
        "502": VulnerabilityType.UNSAFE_DESERIALIZATION,
        "94": VulnerabilityType.CODE_INJECTION,
        "95": VulnerabilityType.CODE_INJECTION,
        "917": VulnerabilityType.CODE_INJECTION,
        "601": VulnerabilityType.OPEN_REDIRECT,
    }

    @classmethod
    def _infer_vulnerability_type(
        cls, raw_type: str, sink_type: str, cwe_id: Optional[str] = None
    ) -> VulnerabilityType:
        """Normalize a raw LLM label (+ optional CWE) to a canonical enum.

        Deterministic post-normalization only. Unrecognized classes resolve
        to OTHER (NOT SQL_INJECTION) so genuinely novel / 0-day findings stay
        visible instead of being silently mislabeled.

        Args:
            raw_type: Raw, open-vocabulary vulnerability label from the LLM.
            sink_type: Sink type string from the LLM.
            cwe_id: Optional CWE id from the LLM (e.g. "CWE-601").

        Returns:
            Canonical VulnerabilityType; OTHER when no confident mapping.
        """
        combined = f"{raw_type} {sink_type}".lower()

        # Deserialization / code-injection checks come first because their
        # keywords (`deserialize`, `readValue`, `classForName`) are highly
        # specific — placing them after the broader XSS/command rules would
        # let `deserialize` get swallowed by the `output`/`reflect` heuristic.
        if any(k in combined for k in (
            "deserialize", "deserialization", "readobject", "readvalue",
            "objectinputstream", "xmldecoder"
        )):
            return VulnerabilityType.UNSAFE_DESERIALIZATION
        if any(k in combined for k in (
            "code_injection", "code injection", "el_injection",
            "expression_language", "classforname", "class_loading",
            "arbitrary_class", "reflection", "reflective", "scriptengine",
            "groovyshell"
        )):
            return VulnerabilityType.CODE_INJECTION
        if any(k in combined for k in ("xss", "cross-site", "html", "script", "output")):
            return VulnerabilityType.XSS
        if any(k in combined for k in ("command", "exec", "process", "runtime", "shell")):
            return VulnerabilityType.COMMAND_INJECTION
        if any(k in combined for k in ("path", "traversal", "file", "directory")):
            return VulnerabilityType.PATH_TRAVERSAL
        if any(k in combined for k in ("xxe", "xml", "entity")):
            return VulnerabilityType.XXE
        # Open-redirect MUST be checked before SSRF: a label like
        # "url_redirection" contains the bare substring "url", which the SSRF
        # rule would otherwise greedily claim. "redirect" is the stronger,
        # more specific signal.
        if any(k in combined for k in ("open_redirect", "open redirect", "redirect", "sendredirect")):
            return VulnerabilityType.OPEN_REDIRECT
        if any(k in combined for k in ("ssrf", "url", "http_client", "request_forgery")):
            return VulnerabilityType.SSRF
        if any(k in combined for k in ("sql", "query", "database", "jdbc")):
            return VulnerabilityType.SQL_INJECTION

        # Free-text didn't match; try the LLM-supplied CWE before giving up.
        # Strip leading zeros so zero-padded ids ("CWE-079") match the
        # unpadded keys — must stay consistent with evaluate._cwe_digits.
        if cwe_id:
            digits = re.sub(r"\D", "", str(cwe_id)).lstrip("0")
            mapped = cls._CWE_TO_VULN.get(digits)
            if mapped is not None:
                return mapped

        # Genuinely unrecognized: keep it visible as OTHER (0-day candidate).
        return VulnerabilityType.OTHER

    @staticmethod
    def _is_java_identifier(value: Any) -> bool:
        """Return whether an LLM endpoint is a graph-addressable Java symbol."""
        return isinstance(value, str) and bool(
            re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", value.strip())
        )

    @classmethod
    def _normalize_llm_source_identifier(cls, value: Any) -> Optional[str]:
        """Normalize a model-selected accessor to its graphable receiver."""
        if not isinstance(value, str):
            return None
        value = value.strip()
        if cls._is_java_identifier(value):
            return value
        this_field = re.fullmatch(r"this\.([A-Za-z_$][\w$]*)", value)
        if this_field:
            return this_field.group(1)
        accessor = re.fullmatch(
            r"([A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*(?:\([^()]*\))?)+",
            value,
        )
        return accessor.group(1) if accessor else None

    def _extract_imports(self, code: str) -> List[str]:
        """Extract import statements from Java code.

        Args:
            code: Java source code.

        Returns:
            List of import statement strings.
        """
        imports: List[str] = []
        import_pattern = r"import\s+(?:static\s+)?([^;]+);"

        for match in re.finditer(import_pattern, code):
            import_stmt = match.group(1).strip()
            if import_stmt:
                imports.append(import_stmt)

        logger.debug(f"Extracted {len(imports)} import statements")
        return imports

    def _extract_classes(self, code: str) -> List[Dict[str, Any]]:
        """Extract class definitions from Java code.

        Args:
            code: Java source code.

        Returns:
            List of class info dictionaries.
        """
        try:
            classes = self.ast_parser.extract_classes(code)
            logger.debug(f"Extracted {len(classes)} classes using AST parser")
            return classes
        except Exception as e:
            logger.debug(f"AST class extraction failed: {str(e)}, using regex fallback")

        # Fallback to regex-based extraction
        classes_list: List[Dict[str, Any]] = []
        class_pattern = r"(public|private)?\s+class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([^{]+))?"

        for match in re.finditer(class_pattern, code):
            class_name = match.group(2)
            extends = match.group(3)
            implements_str = match.group(4)
            implements = (
                [iface.strip() for iface in implements_str.split(",")]
                if implements_str
                else []
            )

            class_info: Dict[str, Any] = {
                "name": class_name,
                "extends": extends,
                "implements": implements,
            }

            classes_list.append(class_info)

        logger.debug(f"Extracted {len(classes_list)} classes using regex")
        return classes_list
