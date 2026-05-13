"""Enhanced prompt templates for LLM-based source and sink detection with AST context."""

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

### What counts as a source:
- **User Input**: `request.getParameter()`, `request.getHeader()`, `request.getInputStream()`, `request.getCookies()`
- **Request Attributes**: `request.getAttribute()` — when the attribute was set from user-controlled data (e.g., login interceptors storing user objects)
- **Method Parameters**: Parameters annotated with `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`
- **File Operations**: `FileReader`, `Files.readAllBytes()`, `Scanner` on files
- **Network**: Socket reads, HTTP client responses
- **System**: Environment variables, system properties, Runtime.exec() output
- **Other**: Deserialization, JNDI lookups, XML parsing
- **Object Properties**: Properties of user-controlled objects (e.g., `loginUser.getUsername()` where `loginUser` comes from request)

### IMPORTANT: What is NOT a source:
- `ResultSet` (`rs`), `Connection` (`conn`), `Statement` (`stmt`), `PreparedStatement` (`ps`) — these are internal Java objects, NOT user input
- `ArrayList`, `HashMap`, `StringBuilder` — internal data structures
- Variables assigned from constants or hardcoded values
- Return values of internal service calls that do NOT depend on user input
- The source variable is the one that RECEIVES untrusted data (e.g., `username` in `username = request.getParameter("user")`), NOT the API object itself

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
Identify ALL dangerous sinks where untrusted data could cause security vulnerabilities.

### What counts as a sink:
- **SQL**: `Statement.execute()`, `executeQuery()`, `prepareStatement()` with string concat, `createQuery()`, `createNativeQuery()` with string concat
- **Command Execution**: `Runtime.getRuntime().exec()`, `ProcessBuilder`, `Process` — variable PASSED as command argument
- **File Operations**: `FileOutputStream`, `FileWriter`, `Files.write()` with user-controlled paths
- **XML**: `DocumentBuilder.parse()`, `SAXParser.parse()`, `XMLReader` without XXE protection
- **HTTP Response**: `PrintWriter.println()`, `response.sendRedirect()`, response headers, `response.getWriter().write()`
- **XSS/Output**: Direct HTML/JavaScript output without encoding, string concatenation into error messages that are reflected to users (e.g., `throw new RuntimeException("error: " + userInput)`), `model.addAttribute()` with unsanitized data rendered in views, `setAttribute()` for data rendered in JSP/templates
- **Path Traversal**: File path construction without validation
- **LDAP/Database**: LDAP queries, NoSQL operations with user input
- **Reflection**: `Class.forName()`, `Method.invoke()` with user-controlled data
- **Serialization**: `ObjectInputStream.readObject()` from untrusted source
- **SSRF**: `new URL(userInput)`, `HttpURLConnection`, `HttpClient` with user-controlled URLs

### IMPORTANT: What is NOT a sink:
- `request.getAttribute()` — this READS data, it does NOT execute anything dangerous
- `model.addAttribute()` — this is a sink ONLY if the template renders it without escaping; otherwise it is just passing data to the view layer
- Variables used ONLY in null-checks or conditional logic (`if (loginUser == null)`)
- Logging statements (`logger.info()`, `log.debug()`) — unless logs are displayed to users
- The sink variable is the one that CARRIES untrusted data INTO the dangerous operation, NOT the operation object itself

## Analysis Requirements
For each sink, provide:
1. **Line number** where sink occurs
2. **Variable** being passed to sink (the untrusted data variable, NOT the API object)
3. **Sink type** (from list above)
4. **Vulnerability type** this sink could enable
5. **Sink pattern** (method name, class, operation)
6. **Confidence score** (0.0-1.0)

## Vulnerability Types
- sql_injection, command_injection, xxe, xss, path_traversal, ssrf
- ldap_injection, code_injection, expression_injection, deserialization

## Important Notes
- Consider the destination of the operation (where data goes)
- Check parameter types and method signatures
- Account for indirect sinks (helper methods that eventually reach dangerous operations)
- A sink is especially critical if parameters are user-controlled

## Required Output Format
Return ONLY valid JSON with NO additional text:
```json
{{
    "sinks": [
        {{
            "line": <line_number>,
            "variable": "<variable_name>",
            "type": "<sink_type>",
            "vulnerability_type": "<vulnerability_type>",
            "pattern": "<method_or_operation>",
            "confidence": <0.0_to_1.0>,
            "reasoning": "<brief_explanation>"
        }}
    ]
}}
```

If no sinks found: `{{"sinks": []}}`"""


# ============================================================================
# ENHANCED COMBINED ANALYSIS PROMPT
# ============================================================================
ENHANCED_COMBINED_PROMPT = """# Security Analysis: Source and Sink Detection

You are a security expert analyzing Java code for taint-analysis vulnerabilities.

## Context Information
{context}

## Code to Analyze
```java
{code}
```

## Task
Identify untrusted data SOURCES and dangerous SINKS in this code.
Only report findings where you are confident that untrusted user data can reach a dangerous operation.

### What counts as a SOURCE (untrusted data entry point):
- `request.getParameter()`, `request.getHeader()`, `request.getInputStream()`, `request.getCookies()`
- `request.getAttribute()` — when attribute was set from user-controlled data
- Method parameters annotated with `@RequestParam`, `@PathVariable`, `@RequestBody`
- Properties of user-controlled objects (e.g., `loginUser.getUsername()` where `loginUser` comes from request)
- File reads, network input, deserialization

### What is NOT a source:
- `ResultSet`, `Connection`, `Statement`, `PreparedStatement` — internal Java objects
- `ArrayList`, `HashMap`, `StringBuilder` — data structures
- Return values of internal service/DAO methods that don't depend on user input
- Constants, hardcoded values, configuration objects
- Session/authentication data retrieved from server-side storage: `session.getAttribute()`, `authSession.getAuthNote()`, `getAuthenticatedUser()`, `getPrincipal()`
- Return values from framework configuration methods: `getRealm()`, `getClient()`, `getConfig()`, `getProvider()`
- Variables that hold internal state objects: `AuthenticationFlow`, `ExecutionModel`, `SessionModel`

### What counts as a SINK (dangerous operation):
- **SQL**: `executeQuery()`, `executeUpdate()`, string concatenation into SQL queries
- **XSS**: `response.getWriter().write()`, `setAttribute()` for data rendered in templates, string concatenation into error/exception messages shown to users (e.g., `throw new RuntimeException("error: " + userInput)`)
- **Command**: `Runtime.exec()`, `ProcessBuilder` with user-controlled arguments
- **Path Traversal**: `new File(userInput)`, `Paths.get(userInput)` without validation
- **XXE**: `DocumentBuilder.parse()` without secure configuration
- **SSRF**: `new URL(userInput)`, `HttpURLConnection` with user-controlled URLs

### What is NOT a sink:
- `request.getAttribute()` — reads data, does not execute anything
- Null-checks: `if (var == null)` — conditional logic, not a dangerous operation
- Logging: `logger.info()`, `log.debug()` — unless logs are displayed to users
- Internal method calls that don't reach dangerous APIs
- `model.addAttribute()` — only a sink if rendered without escaping
- Framework object constructors: `new AuthenticationFlow(...)`, `new FormProvider(...)`, `new SessionContext(...)`
- Internal setter methods that store data in framework objects: `.setClient()`, `.setState()`, `.setAuthNote()`
- Event/audit logging: `event.detail()`, `event.error()`, `event.success()`
- Exception constructors: `new AuthenticationFlowException(...)`, `throw new ErrorPageException(...)`

## Vulnerability Types
sql_injection, xss, command_injection, path_traversal, xxe, ssrf

## IMPORTANT
- The source variable is the one that HOLDS untrusted data, not the API object
- The sink variable is the one that CARRIES untrusted data INTO the dangerous operation
- Only report HIGH CONFIDENCE findings (>= 0.7)
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
            "vulnerability_type": "<vulnerability_type>",
            "pattern": "<method_or_operation>",
            "confidence": <0.0_to_1.0>,
            "reasoning": "<explanation>"
        }}
    ]
}}
```

If no findings: `{{"sources": [], "sinks": []}}`"""


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
