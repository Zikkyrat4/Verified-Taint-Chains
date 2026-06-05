"""Specification extractor using LLM for source and sink detection."""

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from src.core.models import (
    CodeLocation,
    Source,
    Sink,
    Specification,
    VulnerabilityType,
)
from src.core.source_sink_classifier import classify_source, classify_sink
from src.core.exceptions import ParsingError, LLMError
from src.stage1_llm_inference.llm_client import SimpleLLMClient
from src.stage1_llm_inference.ast_parser import JavaASTParser
from src.stage1_llm_inference.prompt_templates import (
    build_source_prompt,
    build_sink_prompt,
    build_combined_prompt,
)
from src.stage1_llm_inference.sanitizer_detector import StaticSanitizerDetector
from src.stage1_llm_inference.spec_cache import SpecCache
from src.utils.logger import get_logger

logger = get_logger()


class SimpleSpecificationExtractor:
    """Extracts security specification (sources, sinks) from Java code using LLM.

    This extractor splits code into functions and analyzes each for sources and sinks
    using an LLM client.

    Attributes:
        llm_client: SimpleLLMClient instance for LLM queries.
        confidence_threshold: Minimum confidence to include sources/sinks (default 0.5).
    """

    def __init__(
        self,
        llm_client: SimpleLLMClient,
        confidence_threshold: float = 0.5,
        spec_cache: Optional[SpecCache] = None,
        llm_provider: str = "",
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

        logger.info(
            f"Initialized SimpleSpecificationExtractor with threshold={confidence_threshold}"
        )
        logger.debug("AST parser initialized for improved code analysis")

    # Regex to detect security-relevant patterns at function level
    _FUNC_SECURITY_RE = re.compile(
        r"getParameter|getHeader|getCookies|getInputStream|getReader|getQueryString"
        r"|@RequestParam|@PathVariable|@RequestBody|@RequestHeader|@CookieValue"
        r"|HttpServletRequest|HttpServletResponse"
        r"|executeQuery|executeUpdate|prepareStatement|createStatement|execute\("
        r"|createNativeQuery|createQuery"
        r"|Runtime\.getRuntime|ProcessBuilder|exec\("
        r"|setAttribute|getRequestDispatcher|sendRedirect|addCookie|\.write\("
        r"|innerHTML|document\.write|\.html\("
        r"|new\s+File\(|new\s+FileInputStream|Paths\.get|Files\."
        r"|DocumentBuilder|SAXParser|XMLReader|TransformerFactory"
        r"|URL\(|HttpURLConnection|HttpClient|openConnection"
        r"|ObjectInputStream|readObject|XMLDecoder"
        r"|getAttribute|RuntimeException|throw\s+new"
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
        if self.spec_cache is not None and cache_kwargs is not None:
            cached = self.spec_cache.get(source_code, **cache_kwargs)
            if cached is not None:
                logger.info(
                    f"Cache hit for {file_path or 'inline code'} "
                    f"(skipping Stage 1 LLM)"
                )
                return cached

        # Step 2: AST prefilter — zero possibility of a sink in this file.
        if not self._has_potential_sinks(source_code):
            logger.info(
                f"Skipping {file_path or 'inline code'}: AST prefilter "
                f"found no method invocations (sink impossible)"
            )
            empty = Specification(
                sources=[], sinks=[], sanitizers=[], llm_model=model,
            )
            if self.spec_cache is not None and cache_kwargs is not None:
                self.spec_cache.put(source_code, empty, **cache_kwargs)
            return empty

        # Step 3: the full LLM-driven extraction (original logic).
        spec = await self._extract_uncached(source_code, file_path, model)
        if self.spec_cache is not None and cache_kwargs is not None:
            self.spec_cache.put(source_code, spec, **cache_kwargs)
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

        # Prioritization, NOT exclusion. A keyword-based filter that *drops*
        # functions blinds the detector to 0-day patterns that use unfamiliar
        # APIs. Instead: analyze every non-trivial function, ordered so that
        # functions matching known security patterns go first (useful when a
        # MAX_FILES/time budget truncates a huge project). Structurally
        # trivial functions (empty / pure accessors with no calls) carry no
        # taint logic and are skipped to bound cost without hiding behavior.
        # `VTC_FAST_PREFILTER=true` restores the old hard skip (debug/CI only).
        fast_prefilter = os.getenv("VTC_FAST_PREFILTER", "false").lower() in (
            "true", "1", "yes", "on"
        )

        analyzable: List[Tuple[str, str, int, Optional[Dict[str, Any]]]] = []
        skipped_funcs = 0
        for entry in functions:
            func_name, func_code = entry[0], entry[1]
            if self._is_trivial_function(func_code):
                skipped_funcs += 1
                continue
            if fast_prefilter and not self._FUNC_SECURITY_RE.search(func_code):
                logger.debug(f"[fast] Skipping {func_name}: no security patterns")
                skipped_funcs += 1
                continue
            analyzable.append(entry)

        # Stable-sort: security-pattern hits first, original order preserved
        # within each group.
        analyzable.sort(
            key=lambda e: 0 if self._FUNC_SECURITY_RE.search(e[1]) else 1
        )

        all_sources: List[Source] = []
        all_sinks: List[Sink] = []

        # Analyze each function with context — single combined LLM call
        for func_name, func_code, line_offset, func_info in analyzable:
            try:
                logger.debug(f"Analyzing function: {func_name}")

                # Build context for this function
                class_info = None
                if classes:
                    class_info = classes[0]  # Use first class as context

                # Single combined prompt for sources + sinks
                combined_prompt = build_combined_prompt(
                    code=func_code,
                    function_info=func_info,
                    class_info=class_info,
                    imports=imports,
                )

                # Try LLM call with one retry on parse failure
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

                # Parse sources from combined response
                if response and "sources" in response:
                    sources = self._parse_llm_sources(
                        response, file_path, line_offset,
                        function_name=func_name,
                    )
                    all_sources.extend(sources)
                    logger.debug(f"Found {len(sources)} sources in {func_name}")

                # Parse sinks from combined response
                if response and "sinks" in response:
                    sinks = self._parse_llm_sinks(
                        response, file_path, line_offset,
                        function_name=func_name,
                    )
                    all_sinks.extend(sinks)
                    logger.debug(f"Found {len(sinks)} sinks in {func_name}")

            except (ParsingError, LLMError) as e:
                logger.warning(f"Failed to analyze function {func_name}: {str(e)}")
                logger.debug(f"Raw error details for {func_name}: {repr(e)}")
                continue
            except Exception as e:
                logger.error(f"Unexpected error analyzing {func_name}: {str(e)}")
                logger.debug(f"Raw error details for {func_name}: {repr(e)}")
                continue

        if skipped_funcs:
            logger.info(
                f"Analyzed {len(analyzable)}/{len(functions)} functions; "
                f"skipped {skipped_funcs} "
                f"({'fast-prefilter' if fast_prefilter else 'structurally trivial only'})"
            )

        # Syntactic pre-pass: JSP-tag setter parameters as USER_INPUT sources.
        # `_FUNC_SECURITY_RE` skips trivial setters, so the LLM never sees them —
        # but JSP containers populate `setX(String x)` with attacker-controlled
        # tag attributes. Scoped to JSP tag classes only (suffix `Tag` or
        # `javax.servlet.jsp.tagext` import) to avoid FP-explosion on Spring/POJO.
        setter_sources = self._extract_jsp_setter_sources(
            source_code, file_path, imports, classes
        )
        if setter_sources:
            logger.info(
                f"JSP-tag setter pre-pass: added {len(setter_sources)} "
                f"USER_INPUT sources"
            )
            all_sources.extend(setter_sources)

        # Populate code_snippet from source code and classify categories.
        # LLMs often report a slightly-off line number (function header instead
        # of body, off-by-one, etc.). Scan a small window around the reported
        # line for the variable name to recover the real declaration site.
        source_lines = source_code.splitlines()

        def _resolve_snippet(line_number: int, variable_name: str) -> Tuple[str, int]:
            n = len(source_lines)
            primary_idx = line_number - 1
            if not (0 <= primary_idx < n):
                primary_idx = 0
            primary = source_lines[primary_idx] if 0 <= primary_idx < n else ""
            if not variable_name or len(variable_name) <= 1 or variable_name in primary:
                return primary.strip(), line_number if 1 <= line_number <= n else primary_idx + 1
            for offset in (1, -1, 2, -2, 3, -3, 4, -4, 5, -5):
                idx = primary_idx + offset
                if 0 <= idx < n and variable_name in source_lines[idx]:
                    return source_lines[idx].strip(), idx + 1
            # Last resort: full-file scan for the variable's first appearance.
            # Handles cases where the LLM reports the wrong absolute line
            # (e.g. function-relative line never recombined with offset).
            for idx, line in enumerate(source_lines):
                if variable_name in line:
                    return line.strip(), idx + 1
            return primary.strip(), line_number

        for src in all_sources:
            snippet, resolved_line = _resolve_snippet(
                src.location.line_number, src.variable_name
            )
            src.code_snippet = snippet
            if resolved_line != src.location.line_number:
                src.location = CodeLocation(
                    file_path=src.location.file_path,
                    line_number=resolved_line,
                )
            src.source_category = classify_source(src)

        for snk in all_sinks:
            snippet, resolved_line = _resolve_snippet(
                snk.location.line_number, snk.variable_name
            )
            snk.code_snippet = snippet
            if resolved_line != snk.location.line_number:
                snk.location = CodeLocation(
                    file_path=snk.location.file_path,
                    line_number=resolved_line,
                )
            snk.sink_category = classify_sink(snk)
            # Snippet patterns are a LAST-RESORT normalizer, not an override:
            # the LLM owns the classification. Only step in when the LLM gave
            # nothing recognizable (normalized to OTHER) — never overrule a
            # confident label. This keeps detection LLM-driven.
            if snk.vulnerability_type is VulnerabilityType.OTHER:
                ctx_lo = max(0, resolved_line - 4)
                ctx_hi = min(len(source_lines), resolved_line + 3)
                window = "\n".join(source_lines[ctx_lo:ctx_hi])
                corrected = self._correct_vuln_type_from_snippet(snippet, window)
                if corrected is not None:
                    snk.vulnerability_type = corrected

        # Detect sanitizers using static pattern matching
        all_sanitizers = self.sanitizer_detector.detect(source_code, file_path)

        logger.info(
            f"Extraction complete: {len(all_sources)} sources, {len(all_sinks)} sinks, "
            f"{len(all_sanitizers)} sanitizers"
        )

        return Specification(
            sources=all_sources,
            sinks=all_sinks,
            sanitizers=all_sanitizers,
            llm_model=model,
        )

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

    # JSP-tag setter: `public void setX(Type x)` on one line. Captures the
    # parameter name as a USER_INPUT source. Container populates these from
    # tag-attribute strings supplied by the page author / request data.
    _JSP_SETTER_RE = re.compile(
        r"^\s*public\s+void\s+(set[A-Z]\w*)\s*\(\s*"
        r"(?:final\s+)?"
        r"(?:String|Integer|Long|Boolean|Double|Float|Object|"
        r"int|long|boolean|double|float)\s+"
        r"(\w+)\s*\)\s*$"
    )

    @staticmethod
    def _is_jsp_tag_class(imports: List[str], classes: List[Dict[str, Any]]) -> bool:
        """Detect whether a file declares a JSP tag handler class.

        Heuristic: matches if any import resolves into the JSP tag-ext API or
        any class name ends with ``Tag``. Conservative on purpose — falling
        outside the scope yields no setter sources rather than wrong ones.
        """
        for imp in imports:
            if "servlet.jsp.tagext" in imp or "wiki.tags" in imp:
                return True
        for cls in classes:
            name = cls.get("name") or ""
            if name.endswith("Tag"):
                return True
        return False

    def _extract_jsp_setter_sources(
        self,
        source_code: str,
        file_path: str,
        imports: List[str],
        classes: List[Dict[str, Any]],
    ) -> List[Source]:
        """Emit USER_INPUT sources for JSP-tag setter parameters.

        Args:
            source_code: Full Java source text.
            file_path: File path for code location tracking.
            imports: List of import statements (used for scoping).
            classes: Extracted class metadata (used for scoping).

        Returns:
            List of synthesized Source objects (may be empty).
        """
        if not self._is_jsp_tag_class(imports, classes):
            return []

        sources: List[Source] = []
        for line_idx, raw_line in enumerate(source_code.splitlines(), start=1):
            match = self._JSP_SETTER_RE.match(raw_line)
            if not match:
                continue
            setter_name = match.group(1)
            param_name = match.group(2)
            sources.append(
                Source(
                    location=CodeLocation(
                        file_path=file_path,
                        line_number=line_idx,
                        function_name=setter_name,
                    ),
                    variable_name=param_name,
                    type="user_input",
                    confidence=0.85,
                    code_snippet=raw_line.strip(),
                    reasoning=(
                        f"JSP tag setter '{setter_name}': container-populated "
                        f"attribute value, attacker-controlled (CWE-079 vector)"
                    ),
                )
            )
        return sources

    # Variable names that are known false-positive sources (internal Java objects)
    FALSE_POSITIVE_SOURCES = {
        "rs", "resultset",
        "conn", "connection",
        "stmt", "statement", "ps", "pstmt", "preparedstatement",
        "ds", "datasource",
        "ctx", "context",
        "session", "sess",
        "out", "writer", "pw",
        "sb", "stringbuilder", "stringbuffer",
    }

    # Variable names that are known false-positive sinks
    FALSE_POSITIVE_SINKS = {
        "logger", "log", "LOGGER", "LOG",
        "model", "modelmap", "modelandview",
        "result", "ret",
        "list", "map", "set", "array",
        "sb", "stringbuilder", "stringbuffer",
        "e", "ex", "exception", "err",
    }

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
            try:
                # Extract required fields
                line = source_data.get("line")
                variable = source_data.get("variable")
                source_type = source_data.get("type")
                confidence = float(source_data.get("confidence", 0.8))

                # Validate required fields
                if not line or not variable or not source_type:
                    logger.warning(f"Skipping source with missing fields: {source_data}")
                    continue

                # Filter known false-positive source variable names
                if variable.lower() in self.FALSE_POSITIVE_SOURCES:
                    logger.debug(
                        f"Skipping false-positive source '{variable}' "
                        f"(known internal Java object)"
                    )
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
                logger.warning(f"Error parsing source {source_data}: {str(e)}")
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
                    logger.warning(f"Skipping sink with missing fields: {sink_data}")
                    continue

                # Filter known false-positive sink variable names
                if variable.lower() in self.FALSE_POSITIVE_SINKS:
                    logger.debug(
                        f"Skipping false-positive sink '{variable}' "
                        f"(known benign variable)"
                    )
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
                logger.warning(f"Error parsing sink {sink_data}: {str(e)}")
                continue

        logger.debug(f"Parsed {len(sinks)} sinks from LLM response")
        return sinks

    # Snippet patterns that strongly imply a specific vulnerability class —
    # used to overrule the LLM's vuln_type label (which is unreliable for
    # deserialization and reflection-style code injection).
    _DESERIALIZATION_SINK_RE = re.compile(
        r"\.\s*readObject\s*\("
        r"|\.\s*readValue\s*\("
        r"|\.\s*deserialize\s*\("
        r"|\bObjectInputStream\b"
        r"|\bXMLDecoder\b"
        r"|JsonSerialization\s*\.\s*readValue\s*\("
        r"|ObjectMapper\s*\(\s*\)?\s*\.\s*readValue\s*\("
    )
    _CODE_INJECTION_SINK_RE = re.compile(
        r"Reflections\s*\.\s*classForName\s*\("
        r"|Class\s*\.\s*forName\s*\("
        r"|ScriptEngine"
        r"|GroovyShell"
        r"|\bMethod\s*\.\s*invoke\s*\("
        r"|new\s+ExpressionParser\s*\("
    )

    @classmethod
    def _correct_vuln_type_from_snippet(
        cls, snippet: str, context_window: str = ""
    ) -> Optional[VulnerabilityType]:
        """Reclassify a sink's vulnerability_type based on snippet patterns.

        Args:
            snippet: The single-line snippet at the sink location.
            context_window: Optional broader text (e.g. ±3 lines around the
                sink) to capture cases where `_resolve_snippet` snapped to
                the line *after* the actual taint sink (return statement,
                follow-on assignment, etc).

        Returns:
            *None* to leave the LLM's label intact. Only matches strong,
            unambiguous patterns — avoids overruling on weak heuristics.
        """
        haystack = f"{snippet}\n{context_window}" if context_window else snippet
        if not haystack:
            return None
        if cls._DESERIALIZATION_SINK_RE.search(haystack):
            return VulnerabilityType.UNSAFE_DESERIALIZATION
        if cls._CODE_INJECTION_SINK_RE.search(haystack):
            return VulnerabilityType.CODE_INJECTION
        return None

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
            "expression_language", "classforname", "scriptengine", "groovyshell"
        )):
            return VulnerabilityType.CODE_INJECTION
        if any(k in combined for k in ("xss", "cross-site", "html", "script", "output", "reflect")):
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
