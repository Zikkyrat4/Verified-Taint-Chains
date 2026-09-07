"""Static sanitizer detector for known-safe Java patterns.

Detects common sanitization patterns using regex — no LLM calls needed.
Fast, deterministic detection of PreparedStatement, HTML escaping,
path normalization, process builder with args, and input validation.
"""

import re
from typing import List, Tuple

from src.core.models import CodeLocation, Sanitizer
from src.utils.logger import get_logger

logger = get_logger()

# Each pattern: (compiled_regex, sanitizer_type, vulnerability_types, effectiveness)
_SANITIZER_PATTERNS: List[Tuple[re.Pattern, str, List[str], float]] = [
    # SQL injection: PreparedStatement with parameterized queries
    (
        re.compile(r"\.prepareStatement\s*\(", re.IGNORECASE),
        "prepared_statement",
        ["sql_injection"],
        1.0,
    ),
    # SQL injection: setString/setInt/setObject on prepared statement
    (
        re.compile(r"\.\s*set(String|Int|Long|Float|Double|Object|Boolean)\s*\("),
        "parameterized_query",
        ["sql_injection"],
        1.0,
    ),
    # SQL injection: JPA / Hibernate parameterized query (named or positional)
    (
        re.compile(r"\.setParameter\s*\(|\.createNamedQuery\s*\("),
        "jpa_parameter",
        ["sql_injection"],
        0.95,
    ),
    # SQL injection: JdbcTemplate / NamedParameterJdbcTemplate (Spring)
    (
        re.compile(r"NamedParameterJdbcTemplate|jdbcTemplate\.query(ForObject|ForList)?\s*\(\s*[^,]+,\s*\w+,"),
        "jdbc_template_param",
        ["sql_injection"],
        0.9,
    ),
    # XSS: Spring HtmlUtils.htmlEscape
    (
        re.compile(r"HtmlUtils\s*\.\s*htmlEscape\s*\("),
        "html_escape",
        ["xss"],
        0.95,
    ),
    # XSS: Apache Commons StringEscapeUtils
    (
        re.compile(
            r"StringEscapeUtils\s*\.\s*escape(Html3?|Html4?|Xml(10|11)?|EcmaScript|Java(Script)?|Csv)\s*\("
        ),
        "html_escape",
        ["xss"],
        0.95,
    ),
    # XSS: OWASP ESAPI encoding (broader: encode, encodeForHTML, encodeForURL, ...)
    (
        re.compile(
            r"ESAPI\s*\.\s*encoder\s*\(\s*\)\s*\.\s*encode\w*\s*\("
            r"|ESAPI\s*\.\s*encoder\(\)\s*\.\s*(encodeForHTML|encodeForURL|encodeForJavaScript|encodeForXML)\s*\("
        ),
        "esapi_encode",
        ["xss"],
        0.95,
    ),
    # XSS / HTML cleanup: JSoup.clean (whitelist-based)
    (
        re.compile(r"\bJsoup\s*\.\s*clean\s*\("),
        "jsoup_clean",
        ["xss"],
        0.9,
    ),
    # XSS: Spring Web HtmlUtils.htmlEscapeDecimal / charset variants
    (
        re.compile(r"HtmlUtils\s*\.\s*htmlEscape(Decimal|Hex)?\s*\("),
        "html_escape",
        ["xss"],
        0.9,
    ),
    # Normalization alone does not enforce an allowed-root boundary.
    (
        re.compile(r"\.normalize\s*\(\s*\)"),
        "path_normalization",
        ["path_traversal"],
        0.5,
    ),
    # Path traversal: startsWith check (often paired with normalize).
    # Weak signal alone — `.startsWith("/")` checks absolute path, not "..".
    # Real anti-traversal is `getCanonicalPath().startsWith(allowedRoot)`.
    # Keep effectiveness below the 0.9 verifier-reject threshold; combined
    # with normalize/getCanonical the chain still gets a high max() score.
    (
        re.compile(r"\.startsWith\s*\("),
        "path_prefix_check",
        ["path_traversal"],
        0.5,
    ),
    # Path traversal: contains("..") check
    (
        re.compile(r'\.contains\s*\(\s*"\.\."\s*\)'),
        "path_traversal_check",
        ["path_traversal"],
        0.9,
    ),
    (
        re.compile(r'\.replace\s*\(\s*"\.\./"\s*,\s*""\s*\)'),
        "path_segment_removal",
        ["path_traversal"],
        0.9,
    ),
    # Canonicalization alone still permits paths outside the allowed root.
    (
        re.compile(r"\.getCanonical(Path|File)\s*\("),
        "canonical_path",
        ["path_traversal"],
        0.5,
    ),
    # Command injection: ProcessBuilder with multiple args (varargs or list)
    (
        re.compile(r'new\s+ProcessBuilder\s*\(\s*"[^"]*"\s*,'),
        "process_builder_args",
        ["command_injection"],
        0.9,
    ),
    # Command injection: ProcessBuilder with explicit list
    (
        re.compile(r"new\s+ProcessBuilder\s*\(\s*(Arrays\.asList|List\.of|new\s+ArrayList)"),
        "process_builder_list",
        ["command_injection"],
        0.9,
    ),
    # Command injection: Runtime.exec(String[]) — array form is safe
    (
        re.compile(r"\.exec\s*\(\s*new\s+String\s*\["),
        "exec_string_array",
        ["command_injection"],
        0.9,
    ),
    # Command injection: String[] array literal (declares safe command array)
    (
        re.compile(r'String\s*\[\s*\]\s+\w+\s*=\s*\{'),
        "string_array_command",
        ["command_injection"],
        0.9,
    ),
    # Input validation: regex matches check
    (
        re.compile(r'\.matches\s*\(\s*"[^"]*"'),
        "regex_validation",
        ["sql_injection", "xss", "command_injection", "path_traversal"],
        0.9,
    ),
    # Input validation: Pattern.compile + matcher.matches()
    (
        re.compile(r"Pattern\s*\.\s*compile\s*\([^)]+\)\.matcher\s*\([^)]+\)\s*\.\s*matches\s*\("),
        "pattern_matcher_validation",
        ["sql_injection", "xss", "command_injection", "path_traversal"],
        0.9,
    ),
    # Input validation: Bean Validation / Hibernate Validator
    (
        re.compile(r"javax\.validation\.|jakarta\.validation\.|@Valid\b|Validator\s*\.\s*validate\s*\("),
        "bean_validation",
        ["sql_injection", "xss", "command_injection", "path_traversal"],
        0.85,
    ),
    # Input validation: Integer.parseInt / Long.parseLong (numeric-only)
    (
        re.compile(r"(Integer\.parseInt|Long\.parseLong|Double\.parseDouble)\s*\("),
        "numeric_parse",
        ["sql_injection", "command_injection"],
        0.9,
    ),
    # Input validation: UUID.fromString (rejects non-UUID strings)
    (
        re.compile(r"UUID\s*\.\s*fromString\s*\("),
        "uuid_validation",
        ["sql_injection", "command_injection", "path_traversal"],
        0.9,
    ),
]


class StaticSanitizerDetector:
    """Detects known sanitizer patterns in Java source code.

    Uses regex-based pattern matching to identify common sanitization
    and validation patterns without requiring LLM calls.
    """

    def detect(self, source_code: str, file_path: str = "") -> List[Sanitizer]:
        """Detect known sanitizer patterns in code.

        Args:
            source_code: Java source code to scan.
            file_path: Optional file path for code location tracking.

        Returns:
            List of Sanitizer objects for detected patterns.
        """
        sanitizers: List[Sanitizer] = []
        lines = source_code.split("\n")

        for line_idx, line in enumerate(lines):
            line_number = line_idx + 1

            for pattern, san_type, vuln_types, effectiveness in _SANITIZER_PATTERNS:
                match = pattern.search(line)
                if match:
                    variable_name = self._infer_variable(line, match)
                    sanitizer = Sanitizer(
                        location=CodeLocation(
                            file_path=file_path,
                            line_number=line_number,
                        ),
                        type=san_type,
                        confidence=effectiveness,
                        code_snippet=line.strip(),
                        variable_name=variable_name,
                        vulnerability_types=list(vuln_types),
                        effectiveness=effectiveness,
                    )
                    sanitizers.append(sanitizer)
                    logger.debug(
                        f"Detected sanitizer '{san_type}' at line {line_number}: "
                        f"{line.strip()[:60]}"
                    )

        logger.info(f"Static sanitizer detection: found {len(sanitizers)} sanitizers")
        return sanitizers

    @staticmethod
    def _infer_variable(line: str, match: re.Match) -> str | None:
        """Infer the value being validated or transformed on this line."""
        prefix = line[:match.start()]

        # Assignment target for helpers returning a sanitized value.
        assigned = re.search(r"\b([A-Za-z_]\w*)\s*=\s*[^=]*$", prefix)
        if assigned:
            return assigned.group(1)

        # Receiver of ``value.normalize()`` / ``value.replace(...)``.
        receiver = re.search(r"\b([A-Za-z_]\w*)\s*$", prefix)
        if match.group(0).lstrip().startswith(".") and receiver:
            return receiver.group(1)

        # First identifier argument to a static sanitizer call.
        suffix = line[match.end():]
        argument = re.search(r"\(\s*([A-Za-z_]\w*)", suffix)
        return argument.group(1) if argument else None
