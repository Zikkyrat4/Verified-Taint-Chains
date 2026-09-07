"""Enhanced prompt templates for LLM-based source and sink detection with AST context."""

import json
from typing import Optional, List, Dict, Any

# ============================================================================
# ENHANCED SOURCE DETECTION PROMPT
# ============================================================================
ENHANCED_SOURCE_PROMPT = """# Security Analysis: Source Detection

You are a security expert analyzing Java code for untrusted data sources.

## Context Information
{context}

## Code to Analyze
```java
{code}
```

## Task
Identify ALL sources of untrusted data entry points in this code.

### Definition (reason from this, do not just match a list)
A **source** is any expression through which a value that an external,
untrusted actor can influence enters this code: HTTP request data, request
bodies/headers/cookies/parameters, uploaded or read file contents, network
responses, message-queue payloads, deserialized objects, JNDI/LDAP lookups,
parsed XML/JSON, environment/system inputs, or a property of an object that
itself originated from any of the above. If an attacker can affect the value —
even via an API you have not seen before — it is a source.

### Illustrative examples (NON-exhaustive — do not limit yourself to these)
- `request.getParameter()`, `getHeader()`, `getInputStream()`, `getCookies()`
- Parameters annotated `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`
- `request.getAttribute()` when the attribute was populated from user-controlled data upstream
- File/network reads, deserialization, XML/JSON parsing of external data
- A property of a user-controlled object (e.g. `obj.getName()` where `obj` came from a request)

### What is NOT a source:
- Internal JDBC/IO objects: result sets, connections, statements, prepared statements — these are not external input
- Generic in-memory data structures (lists, maps, builders)
- Constants, hardcoded values, configuration objects
- Server-side session/identity accessors and framework configuration getters whose value the server controls (not the attacker)
- Return values of internal service/DAO calls that do not depend on external input
- The source variable is the one that RECEIVES untrusted data (e.g. `username` in `username = request.getParameter("user")`), NOT the API object itself

## Analysis Requirements
For each source, provide:
1. **Line number** where source occurs (relative to function start)
2. **Variable name** holding untrusted data
3. **Source type** from the list above
4. **Source pattern** (e.g., method name, class name)
5. **Confidence score** (0.0-1.0) in your assessment

## Important Notes
- Consider the type signature and imports to understand data flow
- Account for variable assignments and method returns
- Mark indirect sources (where untrusted data flows through helper methods)
- Be precise with line numbers

## Required Output Format
Return ONLY valid JSON with NO additional text:
```json
{{
    "sources": [
        {{
            "line": <line_number>,
            "variable": "<variable_name>",
            "type": "<source_type>",
            "pattern": "<method_or_operation>",
            "confidence": <0.0_to_1.0>,
            "reasoning": "<brief_explanation>"
        }}
    ]
}}
```

If no sources found: `{{"sources": []}}`"""


# ============================================================================
# ENHANCED SINK DETECTION PROMPT
# ============================================================================
ENHANCED_SINK_PROMPT = """# Security Analysis: Sink Detection

You are a security expert analyzing Java code for dangerous operations.

## Context Information
{context}

## Code to Analyze
```java
{code}
```

## Task
Identify ALL dangerous sinks where untrusted data could cause a security
vulnerability.

### Definition (reason from capability, do not just match a list)
A **sink** is any operation that **interprets, executes, transmits, or
renders** a value such that an attacker-controlled value reaching it would
violate confidentiality, integrity, or availability. Ask: "If this value were
fully attacker-controlled, what concretely could go wrong here?" If there is a
concrete security impact, it is a sink — **even if the API or library is one
you have not seen before**. Classify by capability and impact, not by
membership in a fixed list.

### Illustrative capability categories (NON-exhaustive — report novel ones too)
- Query/command interpreters: SQL/JPQL/HQL, OS commands, LDAP, XPath, NoSQL
- Code/expression evaluation & reflection: script engines, EL/template engines, `Class.forName`, `Method.invoke`, dynamic proxies
- Deserialization of untrusted data (native, XML, polymorphic JSON)
- Untrusted XML parsing without entity protection
- Filesystem path construction; file read/write with influenced paths
- Outbound request targets, redirect targets, URL construction
- Response rendering / header / cookie writing without encoding; reflected error or exception messages
- Any other operation where attacker-controlled input crosses a trust or interpretation boundary

### IMPORTANT: What is NOT a sink:
- Pure reads (e.g. `request.getAttribute()`) — reading executes nothing
- Passing data to a view layer that is known to auto-escape it
- Variables used ONLY in null-checks or conditional logic
- Logging statements — unless the log is rendered back to users
- Internal builders/setters that only store data on framework state objects, and event/audit logging calls
- The sink variable is the one that CARRIES untrusted data INTO the dangerous operation, NOT the operation object itself

## Analysis Requirements
For each sink, provide:
1. **Line number** where the sink occurs
2. **Variable** carrying the untrusted data into the operation (NOT the API object)
3. **Sink type** (short operation descriptor)
4. **Vulnerability type** — your own concise snake_case label for the class of
   weakness (use a well-known name when one fits; invent a precise one if the
   class is unusual — do NOT force-fit it into an unrelated category)
5. **CWE id** — best-fitting CWE (e.g. `"CWE-601"`); use `"CWE-UNKNOWN"` only
   if you genuinely cannot determine one
6. **Sink pattern** (method name, class, operation)
7. **Confidence score** (0.0-1.0)
8. **Reasoning** — why an attacker-controlled value here causes that impact

## Required Output Format
Return ONLY valid JSON with NO additional text:
```json
{{
    "sinks": [
        {{
            "line": <line_number>,
            "variable": "<variable_name>",
            "type": "<sink_type>",
            "vulnerability_type": "<your_snake_case_class>",
            "cwe_id": "<CWE-NNN or CWE-UNKNOWN>",
            "pattern": "<method_or_operation>",
            "confidence": <0.0_to_1.0>,
            "reasoning": "<why attacker-controlled data here is dangerous>"
        }}
    ]
}}
```

If no sinks found: `{{"sinks": []}}`"""


# ============================================================================
# ENHANCED COMBINED ANALYSIS PROMPT
# ============================================================================
ENHANCED_COMBINED_PROMPT = """# Security Analysis: Source, Sink, and Sanitizer Detection

You are a security expert analyzing Java code for taint-analysis vulnerabilities.

## Context Information
{context}

## Code to Analyze
```java
{code}
```

## Task
Identify untrusted data SOURCES and dangerous SINKS in this code by reasoning
about data flow and capability — not by matching a fixed catalog. Report a
finding when an attacker-influenced value can reach an operation whose misuse
has a concrete security impact.

### SOURCE — definition (reason from this)
Any expression through which a value an external, untrusted actor can
influence enters this code. Ask: "Can an attacker affect this value?" If yes,
it is a source — including via APIs you have not seen before.
Illustrative (NON-exhaustive): request parameters/headers/cookies/bodies,
`@RequestParam`/`@PathVariable`/`@RequestBody` params, file/network reads,
deserialized/parsed external data, a property of an object that itself came
from any of these.

NOT a source:
- Internal JDBC/IO objects (result sets, connections, statements) and generic in-memory data structures
- Constants and hardcoded values
- Configuration/session/identity values only when the code proves they are
  server-controlled. CI job settings, tenant/client configuration, redirect
  state, and values previously stored from a request remain externally
  influenced and must be reported.
- Return values of internal service/DAO calls that do not depend on external input
- Constants, field names, parameter-name constants, and API key strings are
  never the data they name. A constant key is not a source; the runtime value
  read from external state using that key may be one.

### SINK — definition (reason from capability)
Any operation that interprets, executes, transmits, or renders a value such
that an attacker-controlled value would violate confidentiality, integrity, or
availability. Ask: "If this value were fully attacker-controlled, what
concretely could go wrong?" If there is a concrete impact, it is a sink —
**even with an unfamiliar API**. Classify by capability/impact, not by a list.
Illustrative (NON-exhaustive): query/command interpreters (SQL, OS, LDAP,
XPath, NoSQL); code/expression evaluation & reflection; deserialization of
untrusted data; unsafe XML parsing; filesystem path construction; outbound
request / redirect / URL targets; unencoded response/header/cookie rendering
and reflected error messages; any other trust-boundary crossing.

NOT a sink:
- Pure reads; conditional/null-check usage
- Passing data to a view layer known to auto-escape it
- Logging — unless rendered back to users
- Internal builders/setters that only store data on framework state objects, framework object constructors, and event/audit logging calls
- Speculative downstream risk based only on a method/variable name. Report the
  concrete operation shown in this snippet, not what another unknown method
  might eventually do.

## IMPORTANT
- Extract sources and sinks independently. Do not omit a source merely because
  its sink is in another method/file, and do not omit a sink merely because its
  source is outside this snippet.
- Scan every shown method and enumerate every distinct concrete source and sink;
  do not stop after finding the first vulnerability.
- If your sink reasoning says a parameter, field, session value, configuration
  value, archive entry, uploaded file, or other value is attacker/user
  controlled, emit that value in top-level `sources` and repeat its exact
  identifier and line in that sink's `taint_sources`. The JSON must agree with
  your reasoning.
- Public/framework callback parameters and container-populated bean/tag
  setters can be external boundaries even without request annotations. Infer
  this from class/import/method context rather than requiring a known annotation.
- Track cross-method flows through fields when a class-level snippet is shown
  (for example `setValue(x) -> this.value -> render(this.value)`).
- Report the earliest boundary variable, not only its propagated field. For
  `setValue(String value) {{ this.field = value; }}`, emit source `value` at
  the setter. For `dangerous(String input)`, emit formal parameter `input` in
  that method when it is externally influenced, even if a same-named field or
  constructor parameter appears elsewhere. Prefer the occurrence in the
  sink-bearing flow over an unrelated same-name declaration.
- For rendering/output calls, emit every untrusted value consumed by the call
  as a separate sink. For example, report each tainted argument passed to a
  raw response writer rather than an unrelated builder created earlier.
- The source variable HOLDS the untrusted data; never report the API object
  (`request`, `runtime`, `serializer`, `writer`) as the source or sink
- For consumer calls such as `exec(command)` or `executeQuery(statement)`,
  report the dangerous argument as the sink.
- For value-producing security operations such as
  `File f = new File(dir, name)`, `Object x = deserialize(data)`, or a redirect
  builder, report the assignment/return-flow target (`f`, `x`, builder value)
  as the sink. This keeps the endpoint distinct from its source and aligned
  with the data-flow graph
- For dynamic class loading, emit the assigned class variable in
  `Class<?> clazz = classForName(untrustedName)` as a code-injection sink. For
  deserialization, emit the assigned result variable and the untrusted data as
  a source, even when both operations occur in the same method.
- A URL taken from external/session/client state and used to initialize a
  redirect builder is a source-to-sink flow: emit the input value as source and
  the builder/result consumed by `build()` or response rendering as sink.
- A setter that only stores state is not itself a redirect/output sink. Report
  a redirect only where the destination is sent to a client, unless the shown
  code proves that the setter performs that operation.
- If an identifier is declared in multiple methods, emit each relevant
  occurrence separately at its exact line. Never substitute an unrelated
  same-named parameter or field from another method.
- Report a sanitizer only when the shown operation actually prevents a named
  vulnerability on that value. File existence/readability/type checks such as
  `exists()`, `canRead()`, and `isFile()` do not prevent path traversal.
- For each sanitizer, list the vulnerability classes it prevents and estimate
  effectiveness. Mere observation, normalization without an allowed-root
  boundary check, and validation whose rejecting branch is not shown must have
  effectiveness below 0.9.
- Only report findings you are confident about (>= 0.7)
- Keep each `reasoning` value to one short sentence (at most 20 words), and do
  not describe non-findings. Concise output prevents otherwise valid JSON from
  being truncated on large files.
- Use your own concise snake_case `vulnerability_type` (a well-known name when
  one fits; a precise novel one otherwise — do NOT force-fit into an unrelated
  category) plus the best-fitting `cwe_id`
- If no sources or sinks found, return empty arrays

## Required Output Format
Return ONLY valid JSON with NO additional text:
```json
{{
    "sources": [
        {{
            "line": <line_number>,
            "variable": "<variable_name>",
            "type": "<source_type>",
            "pattern": "<method_or_operation>",
            "confidence": <0.0_to_1.0>,
            "reasoning": "<explanation>"
        }}
    ],
    "sinks": [
        {{
            "line": <line_number>,
            "variable": "<variable_name>",
            "type": "<sink_type>",
            "vulnerability_type": "<your_snake_case_class>",
            "cwe_id": "<CWE-NNN or CWE-UNKNOWN>",
            "taint_sources": [
                {{
                    "line": <line_number>,
                    "variable": "<exact_source_identifier>",
                    "type": "<source_type>",
                    "confidence": <0.0_to_1.0>
                }}
            ],
            "pattern": "<method_or_operation>",
            "confidence": <0.0_to_1.0>,
            "reasoning": "<why attacker-controlled data here is dangerous>"
        }}
    ],
    "sanitizers": [
        {{
            "line": <line_number>,
            "variable": "<sanitized_or_validated_variable>",
            "type": "<sanitizer_type>",
            "vulnerability_types": ["<snake_case_vulnerability>"],
            "confidence": <0.0_to_1.0>,
            "effectiveness": <0.0_to_1.0>,
            "reasoning": "<why this operation prevents the vulnerability>"
        }}
    ]
}}
```

If no findings: `{{"sources": [], "sinks": [], "sanitizers": []}}`"""


# ============================================================================
# ENHANCED SANITIZER DETECTION PROMPT
# ============================================================================
ENHANCED_SANITIZER_PROMPT = """# Security Analysis: Sanitization/Validation Detection

You are a security expert identifying security controls that protect against vulnerabilities.

## Context Information
{context}

## Code to Analyze
```java
{code}
```

## Task
Identify sanitization and validation operations that protect against security vulnerabilities.

### What counts as a sanitizer:
- **Input Validation**: Pattern matching, whitelist checks, type validation
- **SQL Protection**: Parameterized queries, PreparedStatement, query builders
- **Command Safety**: Whitelisting allowed commands, avoiding shell interpretation
- **Path Safety**: Path canonicalization, directory validation, traversal prevention
- **Output Encoding**: HTML encoding, URL encoding, XML escaping, JSON escaping
- **Type Checking**: instanceof checks, type casting validation
- **Length Limits**: String length checks, input size limits
- **Format Validation**: Email regex, URL validation, date parsing

### Sanitizer Patterns:
- Method calls to validation libraries (Apache Commons, OWASP Validator, etc.)
- If/throw guards that validate input before use
- Prepared statements and parameterized queries
- Encoding/escaping functions
- Type conversion with validation
- Framework-provided security features

## Analysis Requirements
For each sanitizer, provide:
1. **Line number** where sanitization occurs
2. **Sanitizer type** (from list above)
3. **Target data** being protected (if identifiable)
4. **Effectiveness score** (0.0-1.0) - how well it prevents attacks
5. **Sanitizer pattern** (method name, check type, etc.)

## Important Notes
- Consider whether sanitizer actually prevents the vulnerability
- Account for sanitizers that only partially protect
- Identify incomplete or ineffective validation
- Consider if sanitizer applies to the vulnerable variable

## Required Output Format
Return ONLY valid JSON with NO additional text:
```json
{{
    "sanitizers": [
        {{
            "line": <line_number>,
            "type": "<sanitizer_type>",
            "target": "<protected_variable>",
            "pattern": "<method_or_operation>",
            "effectiveness": <0.0_to_1.0>,
            "reasoning": "<explanation>"
        }}
    ]
}}
```

If no sanitizers found: `{{"sanitizers": []}}`"""


# ============================================================================
# GRAPH ENRICHMENT PROMPT (for LLM-driven graph builder)
# ============================================================================
GRAPH_ENRICHMENT_PROMPT = """# Data Flow Graph Enrichment

You are analyzing Java code to identify data flows missed by static AST analysis.

## Code
```java
{code}
```

## Already Identified Flows
{explicit_flows}

## Task
Identify ADDITIONAL data flows not in the list above:
1. **Framework flows**: Spring @Autowired injection, @RequestMapping parameter binding, model->view data, @Transactional proxies
2. **Callback/listener flows**: Event handlers, async callbacks, CompletableFuture chains
3. **Reflection flows**: Class.forName(), Method.invoke(), dynamic proxies
4. **Implicit type flows**: Type casting, deserialization, toString() in string concatenation
5. **Inter-method flows**: Data passed through fields/properties between methods

Also classify each variable's security role:
- SOURCE: receives untrusted external data
- SINK: passed to dangerous operation
- SANITIZER: validates/encodes data
- NEUTRAL: no security significance

## Output (JSON only)
{{{{
  "additional_flows": [
    {{{{"from": "varName", "to": "varName", "flow_type": "framework|callback|reflection|implicit|inter_method", "confidence": 0.9}}}}
  ],
  "classifications": [
    {{{{"variable": "varName", "classification": "SOURCE|SINK|SANITIZER|NEUTRAL", "confidence": 0.9}}}}
  ]
}}}}

If no additional flows found: {{{{"additional_flows": [], "classifications": []}}}}"""


def build_graph_enrichment_prompt(code: str, explicit_flows: str) -> str:
    """Build graph enrichment prompt for LLM-driven graph builder.

    Args:
        code: Java source code to analyze.
        explicit_flows: String listing already-identified data flows.

    Returns:
        Formatted prompt string.

    Raises:
        ValueError: If code is empty.
    """
    if not code or not code.strip():
        raise ValueError("code cannot be empty")

    return GRAPH_ENRICHMENT_PROMPT.format(code=code, explicit_flows=explicit_flows)


# ============================================================================
# CONTEXT BUILDING FUNCTIONS
# ============================================================================

def _build_context_section(
    function_info: Optional[Dict[str, Any]] = None,
    class_info: Optional[Dict[str, Any]] = None,
    imports: Optional[List[str]] = None,
) -> str:
    """Build context information section for prompts.

    Args:
        function_info: Dictionary with function metadata (name, signature, params, etc.)
        class_info: Dictionary with class metadata (name, extends, implements, etc.)
        imports: List of import statements from the file

    Returns:
        Formatted context section for inclusion in prompts
    """
    context_lines = ["## Code Context"]

    # Class information
    if class_info:
        class_name = class_info.get("name", "Unknown")
        context_lines.append(f"**Class**: `{class_name}`")

        if class_info.get("extends"):
            context_lines.append(f"**Extends**: `{class_info['extends']}`")

        if class_info.get("implements"):
            implements = ", ".join(class_info["implements"])
            context_lines.append(f"**Implements**: `{implements}`")

    # Function/method information
    if function_info:
        func_name = function_info.get("name", "unknown")
        return_type = function_info.get("return_type", "void")
        params = function_info.get("parameters", [])

        signature = f"{return_type} {func_name}("

        if params:
            # Parse parameters if they're strings
            if isinstance(params, list) and isinstance(params[0], str):
                param_strs = []
                for param in params:
                    # Clean up parameter string
                    param_clean = param.strip()
                    if param_clean:
                        param_strs.append(param_clean)
                signature += ", ".join(param_strs)
        signature += ")"

        context_lines.append(f"**Method**: `{signature}`")

        # Parameter details
        if params:
            context_lines.append("**Parameters**:")
            for i, param in enumerate(params, 1):
                if isinstance(param, str):
                    context_lines.append(f"  - `{param}`")

    # Import statements
    if imports and len(imports) > 0:
        # Show most relevant imports
        relevant_imports = []
        for imp in imports[:10]:  # Limit to first 10 imports
            if imp.strip():
                relevant_imports.append(f"`{imp.strip()}`")

        if relevant_imports:
            context_lines.append("**Relevant Imports**:")
            for imp in relevant_imports:
                context_lines.append(f"  - {imp}")

        if len(imports) > 10:
            context_lines.append(f"  - ... and {len(imports) - 10} more imports")

    return "\n".join(context_lines)


# ============================================================================
# ENHANCED BUILDER FUNCTIONS
# ============================================================================

def build_source_prompt(
    code: str,
    function_info: Optional[Dict[str, Any]] = None,
    class_info: Optional[Dict[str, Any]] = None,
    imports: Optional[List[str]] = None,
) -> str:
    """Build enhanced source detection prompt with AST context.

    Args:
        code: Java code snippet to analyze for sources.
        function_info: Optional function metadata dictionary.
        class_info: Optional class metadata dictionary.
        imports: Optional list of import statements.

    Returns:
        Formatted prompt string with code and context.

    Raises:
        ValueError: If code is empty.
    """
    if not code or not code.strip():
        raise ValueError("code cannot be empty")

    context = _build_context_section(function_info, class_info, imports)
    return ENHANCED_SOURCE_PROMPT.format(context=context, code=code)


def build_sink_prompt(
    code: str,
    function_info: Optional[Dict[str, Any]] = None,
    class_info: Optional[Dict[str, Any]] = None,
    imports: Optional[List[str]] = None,
) -> str:
    """Build enhanced sink detection prompt with AST context.

    Args:
        code: Java code snippet to analyze for sinks.
        function_info: Optional function metadata dictionary.
        class_info: Optional class metadata dictionary.
        imports: Optional list of import statements.

    Returns:
        Formatted prompt string with code and context.

    Raises:
        ValueError: If code is empty.
    """
    if not code or not code.strip():
        raise ValueError("code cannot be empty")

    context = _build_context_section(function_info, class_info, imports)
    return ENHANCED_SINK_PROMPT.format(context=context, code=code)


def build_combined_prompt(
    code: str,
    function_info: Optional[Dict[str, Any]] = None,
    class_info: Optional[Dict[str, Any]] = None,
    imports: Optional[List[str]] = None,
) -> str:
    """Build enhanced combined analysis prompt with AST context.

    Args:
        code: Java code snippet to analyze for both sources and sinks.
        function_info: Optional function metadata dictionary.
        class_info: Optional class metadata dictionary.
        imports: Optional list of import statements.

    Returns:
        Formatted prompt string with code and context.

    Raises:
        ValueError: If code is empty.
    """
    if not code or not code.strip():
        raise ValueError("code cannot be empty")

    context = _build_context_section(function_info, class_info, imports)
    return ENHANCED_COMBINED_PROMPT.format(context=context, code=code)


def build_missing_source_repair_prompt(code: str, sinks: list[dict]) -> str:
    """Build a compact second-pass prompt for internally inconsistent output."""
    return f"""# Taint Source Consistency Repair

The first security-analysis pass found the sinks below but emitted no sources.
Re-read the Java code and identify every concrete attacker-influenced value that
feeds those sinks. A value obtained from uploaded/archive contents (including a
ZipEntry name), a request, network input, deserialization, or externally set
configuration is a source. Do not invent a source when none is shown.
For a redirect operation, report the value that controls its destination URI,
not an unrelated query parameter appended to that destination.

## Reported sinks
```json
{json.dumps(sinks, ensure_ascii=True)}
```

## Java code
```java
{code}
```

Return ONLY JSON:
{{"sources":[{{"line":1,"variable":"name","type":"source_type","confidence":0.9,"reasoning":"at most 20 words"}}]}}
If no source is present, return {{"sources":[]}}."""


def build_sanitizer_prompt(
    code: str,
    function_info: Optional[Dict[str, Any]] = None,
    class_info: Optional[Dict[str, Any]] = None,
    imports: Optional[List[str]] = None,
) -> str:
    """Build enhanced sanitizer detection prompt with AST context.

    Args:
        code: Java code snippet to analyze for sanitizers.
        function_info: Optional function metadata dictionary.
        class_info: Optional class metadata dictionary.
        imports: Optional list of import statements.

    Returns:
        Formatted prompt string with code and context.

    Raises:
        ValueError: If code is empty.
    """
    if not code or not code.strip():
        raise ValueError("code cannot be empty")

    context = _build_context_section(function_info, class_info, imports)
    return ENHANCED_SANITIZER_PROMPT.format(context=context, code=code)


# ============================================================================
# BACKWARDS COMPATIBILITY WRAPPERS
# ============================================================================

def build_source_prompt_simple(code: str) -> str:
    """Simple source prompt without context (backwards compatible).

    Args:
        code: Java code snippet to analyze.

    Returns:
        Formatted prompt string.
    """
    return build_source_prompt(code)


def build_sink_prompt_simple(code: str) -> str:
    """Simple sink prompt without context (backwards compatible).

    Args:
        code: Java code snippet to analyze.

    Returns:
        Formatted prompt string.
    """
    return build_sink_prompt(code)


def build_combined_prompt_simple(code: str) -> str:
    """Simple combined prompt without context (backwards compatible).

    Args:
        code: Java code snippet to analyze.

    Returns:
        Formatted prompt string.
    """
    return build_combined_prompt(code)


def build_sanitizer_prompt_simple(code: str) -> str:
    """Simple sanitizer prompt without context (backwards compatible).

    Args:
        code: Java code snippet to analyze.

    Returns:
        Formatted prompt string.
    """
    return build_sanitizer_prompt(code)


# ============================================================================
# BACKWARDS COMPATIBILITY ALIASES
# ============================================================================
# For tests and legacy code that expect SIMPLE_* names

SIMPLE_SOURCE_PROMPT = ENHANCED_SOURCE_PROMPT
SIMPLE_SINK_PROMPT = ENHANCED_SINK_PROMPT
COMBINED_ANALYSIS_PROMPT = ENHANCED_COMBINED_PROMPT
SANITIZER_DETECTION_PROMPT = ENHANCED_SANITIZER_PROMPT
