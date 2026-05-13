# Vulnerable Example Files

This directory contains simple, intentionally vulnerable Java code examples for testing and demonstrating the Verified Taint Chains security analysis tool.

## Files

### VulnerableExample.java

A simple Java class demonstrating multiple vulnerability types:

1. **SQL Injection** (PRIMARY EXAMPLE)
   - **Location**: `processUserInput()` method
   - **Source**: `userId` parameter from HTTP request
   - **Data Flow**: `userId` → `query` string → SQL execution
   - **Sink**: `stmt.executeQuery(query)`
   - **Vulnerability**: Direct string concatenation in SQL query
   - **Attack**: `' OR '1'='1` injected in userId parameter
   - **Impact**: Authentication bypass, unauthorized data access

2. **Command Injection**
   - **Location**: `executeSystemCommand()` method
   - **Source**: `filename` parameter from HTTP request
   - **Sink**: `Runtime.getRuntime().exec(command)`
   - **Vulnerability**: User input in system command execution
   - **Attack**: `test.txt; rm -rf /` to execute additional commands
   - **Impact**: Arbitrary command execution, system compromise

3. **Cross-Site Scripting (XSS)**
   - **Location**: `displayUserComment()` method
   - **Source**: `userComment` parameter from HTTP request
   - **Sink**: HTML output without encoding
   - **Vulnerability**: User input rendered in HTML
   - **Attack**: `<script>alert('XSS')</script>` in comment
   - **Impact**: Session hijacking, credential theft, malware injection

4. **Path Traversal**
   - **Location**: `readFile()` method
   - **Source**: `filePath` parameter from HTTP request
   - **Sink**: File system access
   - **Vulnerability**: Insufficient path validation
   - **Attack**: `../../../../etc/passwd` to access sensitive files
   - **Impact**: Unauthorized file access, information disclosure

## Running Analysis

### Basic Analysis
```bash
# Analyze the vulnerable example
python -m src analyze --file examples/VulnerableExample.java

# Results saved to results.json
```

### Verbose Analysis
```bash
# Run with debug output
python -m src analyze --file examples/VulnerableExample.java --verbose
```

### Custom Output
```bash
# Save to specific output file
python -m src analyze --file examples/VulnerableExample.java --output reports/vulnerable_analysis.json
```

## Expected Output

The tool should identify:

### Stage 1: Specification Extraction
- **Sources Found**: 4
  - `userId` (SQL injection)
  - `filename` (Command injection)
  - `userComment` (XSS)
  - `filePath` (Path traversal)

- **Sinks Found**: 4
  - `query` execution (SQL injection)
  - `exec()` call (Command injection)
  - HTML output (XSS)
  - File read operation (Path traversal)

### Stage 2: Path Discovery
- **Chains Found**: 4 (one for each vulnerability type)

### Stage 3: Verification
- **Chains Verified**: 4 (all paths are reachable)

### Stage 4: Explanation
- **Explanations Generated**: 4
  - SQL Injection (CWE-89, CRITICAL)
  - Command Injection (CWE-78, CRITICAL)
  - XSS (CWE-79, MEDIUM)
  - Path Traversal (CWE-22, HIGH)

## Security Notes

⚠️ **WARNING**: This code is intentionally vulnerable and should ONLY be used for:
- Testing security analysis tools
- Security training and education
- Vulnerability research in controlled environments

**DO NOT** use this code in production or as a template for real applications.

## How to Fix the Vulnerabilities

### SQL Injection Fix
```java
// Use parameterized queries
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, userId);
ResultSet rs = pstmt.executeQuery();
```

### Command Injection Fix
```java
// Use allowlist and avoid shell interpretation
String[] allowedFiles = {"test.txt", "data.csv", "config.json"};
if (Arrays.asList(allowedFiles).contains(filename)) {
    String[] cmd = {"/bin/sh", "-c", "cat /tmp/" + filename};
    Process process = Runtime.getRuntime().exec(cmd);
}
```

### XSS Fix
```java
// HTML encode user input
String encodedComment = HtmlUtils.htmlEscape(userComment);
String html = "<div class='comment'>" + encodedComment + "</div>";
```

### Path Traversal Fix
```java
// Validate path and prevent directory traversal
Path path = Paths.get("/safe/directory").resolve(filePath).normalize();
if (!path.startsWith("/safe/directory")) {
    throw new IllegalArgumentException("Invalid file path");
}
String content = new String(Files.readAllBytes(path));
```

## Analysis Metrics

Expected metrics when analyzing this file:

```
Sources Found ...................... 4
Sinks Found ........................ 4
Chains Found ....................... 4
Chains Verified .................... 4
Verification Rate .................. 100%
Explanations Generated ............. 4
Graph Nodes ........................ 8
Graph Edges ........................ 4
```

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-78: Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
