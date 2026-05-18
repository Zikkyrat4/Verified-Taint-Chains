"""Regex-based classifier for source and sink categories.

Runs AFTER LLM extraction to assign categories based on code_snippet and type fields.
Categories drive confidence adjustment to reduce false positives on framework code.
"""

import re
from typing import List, Tuple

from src.core.models import Source, Sink, SourceCategory, SinkCategory


# ============================================================================
# SOURCE CLASSIFICATION PATTERNS
# ============================================================================
# Order matters: first match wins. More specific patterns come first.

_SOURCE_PATTERNS: List[Tuple[re.Pattern, SourceCategory]] = [
    # USER_INPUT — HTTP params, headers, cookies, form data, annotations
    # Covers Servlet API, JAX-RS, Spring MVC.
    (re.compile(
        r"getParameter\(|getHeader\(|getCookies\(|getInputStream\(|getQueryString\("
        r"|@RequestParam|@PathVariable|@RequestBody|@CookieValue|@RequestHeader"
        r"|@QueryParam|@FormParam|@HeaderParam|@PathParam|@MatrixParam"
        r"|getFormParameters\(|getDecodedFormParameters\("
        r"|getReader\(|getRemoteUser\(|getRemoteAddr\("
    ), SourceCategory.USER_INPUT),

    # EXTERNAL_DATA — file reads, network responses, deserialization,
    # XML/JSON parsing of untrusted documents
    (re.compile(
        r"FileReader\(|readLine\(|readAllBytes\(|InputStream"
        r"|deserialize\(|readObject\(|Scanner\(|BufferedReader\("
        r"|\.readValue\("
    ), SourceCategory.EXTERNAL_DATA),

    # SESSION_DATA — server-side session/identity accessors (product-agnostic)
    (re.compile(
        r"getSession\(|getAttribute\(|getNote\("
        r"|getClaim\(|getAuthenticatedUser\(|getPrincipal\("
        r"|getCredentials\(|session\.get|getRedirectUri\("
    ), SourceCategory.SESSION_DATA),

    # DATABASE — query results, entity properties
    (re.compile(
        r"ResultSet|getString\(|getInt\(|getObject\("
        r"|findBy|getOne\(|findAll\("
    ), SourceCategory.DATABASE),
]

# ============================================================================
# SINK CLASSIFICATION PATTERNS
# ============================================================================
#
# Order matters: more specific patterns must come BEFORE more general ones.
# EVENT_LOGGING and BENIGN are placed before FRAMEWORK_API/DATA_STORAGE to
# capture audit logging (event.detail, logger.info, MDC.put) and obviously
# safe operations (Base64 encode, StringBuilder append) that the original
# regex would otherwise tag as FRAMEWORK_API or DATA_STORAGE.

_SINK_PATTERNS: List[Tuple[re.Pattern, SinkCategory]] = [
    # DIRECT_EXECUTION — SQL execute, Runtime.exec, ProcessBuilder, reflection
    (re.compile(
        r"execute\(|executeQuery\(|executeUpdate\("
        r"|exec\(|ProcessBuilder|Runtime\.getRuntime\("
        r"|createQuery\(|createNativeQuery\(|nativeQuery\("
        r"|Class\.forName\(|classForName\("
        r"|ScriptEngine|GroovyShell|Method\.invoke\("
    ), SinkCategory.DIRECT_EXECUTION),

    # EVENT_LOGGING — audit, structured logging, MDC. Generic Java/Spring/SLF4J/JUL.
    # MUST come before DATA_STORAGE (some loggers use put()) and FRAMEWORK_API.
    (re.compile(
        r"\bevent\.(detail|error|success|client|user)\(|\bauditEvent\."
        r"|\b(LOG|LOGGER|log|logger)\s*\.\s*(info|warn|debug|error|trace|fatal)\("
        r"|\b(slf4j|Slf4j|SLF4J)\b"
        r"|\bMDC\.(put|get)\("
        r"|\bAudit(Event|Log|Logger)\b"
        r"|ServicesLogger\.|adminEvent\."
    ), SinkCategory.EVENT_LOGGING),

    # OUTPUT_RENDERING — response write, print, redirect, HTML output
    (re.compile(
        r"\.write\(|println\(|print\(|sendRedirect\("
        r"|getWriter\(|addAttribute\(|forward\(|include\(|sendError\("
        r"|renderResponse\(|renderTemplate\(|renderLogoutPage\("
        r"|Response\.ok\(|ResponseEntity\.ok\("
    ), SinkCategory.OUTPUT_RENDERING),

    # RESOURCE_ACCESS — file I/O, URL connections, XML parsers
    (re.compile(
        r"FileOutputStream\(|FileWriter\(|new URL\("
        r"|openConnection\(|HttpClient|HttpURLConnection"
        r"|new File\(|Paths\.get\("
        r"|DocumentBuilder|SAXParser|XMLReader"
    ), SinkCategory.RESOURCE_ACCESS),

    # BENIGN — encoding/builders that are NOT execution targets. Must come before
    # the generic FRAMEWORK_API fallback so that StringBuilder.append, Base64
    # encode, etc. don't get the higher framework_api multiplier.
    (re.compile(
        r"\bBase64(Url|Utils)?\.(encode|encodeBytes|encodeToString)\("
        r"|\bHex\.encode(Hex|String)?\("
        r"|\bStringBuilder\b\s*\(\s*\)?|sb\.append\("
        r"|String\.format\("
        r"|\.toString\(\)\s*$"
    ), SinkCategory.BENIGN),

    # DATA_STORAGE — session set, DB write, cache. Internal flag-style setters
    # (setProtocol, setClientNote, setRedirectUri) belong here; we still keep
    # them out of FRAMEWORK_API but score them lower than DB writes via the
    # risk matrix.
    (re.compile(
        r"setAttribute\(|setNote\(|setAuthNote\("
        r"|persist\(|save\(|merge\(|insert\(|update\(|put\("
        r"|setClientNote\(|setProtocol\(|setRedirectUri\("
    ), SinkCategory.DATA_STORAGE),

    # FRAMEWORK_API — constructors, generic setters, framework methods (fallback)
    (re.compile(
        r"new\s+\w+\(|set[A-Z]\w+\("
    ), SinkCategory.FRAMEWORK_API),
]

# ============================================================================
# SOURCE TYPE FIELD KEYWORDS (fallback when code_snippet doesn't match)
# ============================================================================

_SOURCE_TYPE_KEYWORDS: List[Tuple[str, SourceCategory]] = [
    ("user_input", SourceCategory.USER_INPUT),
    ("http", SourceCategory.USER_INPUT),
    ("request", SourceCategory.USER_INPUT),
    ("file", SourceCategory.EXTERNAL_DATA),
    ("network", SourceCategory.EXTERNAL_DATA),
    ("deserialization", SourceCategory.EXTERNAL_DATA),
    ("session", SourceCategory.SESSION_DATA),
    ("auth", SourceCategory.SESSION_DATA),
    ("database", SourceCategory.DATABASE),
    ("query", SourceCategory.DATABASE),
]


def classify_source(source: Source) -> SourceCategory:
    """Classify a source by analyzing its code_snippet and type fields.

    Checks regex patterns against code_snippet first, then falls back to
    keyword matching on the source.type field.

    Args:
        source: Source object to classify.

    Returns:
        The assigned SourceCategory.
    """
    text = source.code_snippet or ""

    # Check code_snippet against patterns
    for pattern, category in _SOURCE_PATTERNS:
        if pattern.search(text):
            return category

    # Fallback: check source.type field
    source_type_lower = (source.type or "").lower()
    for keyword, category in _SOURCE_TYPE_KEYWORDS:
        if keyword in source_type_lower:
            return category

    # Default fallback
    return SourceCategory.INTERNAL_API


def classify_sink(sink: Sink) -> SinkCategory:
    """Classify a sink by analyzing its code_snippet and type fields.

    Checks regex patterns against code_snippet. Falls back to UNKNOWN
    if no pattern matches.

    Args:
        sink: Sink object to classify.

    Returns:
        The assigned SinkCategory.
    """
    text = sink.code_snippet or ""

    # Check code_snippet against patterns
    for pattern, category in _SINK_PATTERNS:
        if pattern.search(text):
            return category

    # Default fallback
    return SinkCategory.UNKNOWN
