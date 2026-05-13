/**
 * Simple vulnerable Java example for security analysis.
 *
 * This class demonstrates a classic SQL injection vulnerability where
 * user input flows directly into a SQL query without proper sanitization.
 */

import javax.servlet.http.HttpServletRequest;
import java.sql.*;

public class VulnerableExample {

    private Connection connection;

    /**
     * Vulnerable method: SQL Injection
     *
     * USER INPUT: userId parameter from HTTP request
     * DATA FLOW: userId -> query -> SQL execution
     * VULNERABILITY: Direct string concatenation in SQL query
     *
     * @param request HTTP request containing user input
     * @return ResultSet with query results
     * @throws SQLException if database operation fails
     */
    public ResultSet processUserInput(HttpServletRequest request) throws SQLException {
        // SOURCE: User input from request parameter (untrusted data entry point)
        String userId = request.getParameter("userId");

        // VULNERABLE DATA FLOW: userId flows through query construction
        // The userId parameter is concatenated directly into the SQL query string
        // An attacker can inject SQL code by providing: ' OR '1'='1
        // This would result in: SELECT * FROM users WHERE id = ' OR '1'='1'
        // Which bypasses authentication by making the WHERE clause always true

        // SINK: Direct SQL query execution with untrusted data
        // The query is constructed using string concatenation with user input
        String query = "SELECT * FROM users WHERE id = " + userId;

        // Create and execute the statement
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        return rs;
    }

    /**
     * Another vulnerable method: Command Injection
     *
     * @param request HTTP request containing user input
     * @return command execution result
     * @throws Exception if command execution fails
     */
    public String executeSystemCommand(HttpServletRequest request) throws Exception {
        // SOURCE: User input from request parameter
        String filename = request.getParameter("filename");

        // VULNERABLE: Command injection
        // If filename = "test.txt; rm -rf /", the command becomes dangerous
        String command = "cat /tmp/" + filename;

        // SINK: Direct command execution
        Process process = Runtime.getRuntime().exec(command);

        return command;
    }

    /**
     * Another vulnerable method: XSS (Cross-Site Scripting)
     *
     * @param request HTTP request containing user input
     * @return HTML response
     */
    public String displayUserComment(HttpServletRequest request) {
        // SOURCE: User input from request parameter
        String userComment = request.getParameter("comment");

        // VULNERABLE: XSS injection
        // If userComment = "<script>alert('XSS')</script>", malicious script executes

        // SINK: HTML output without encoding
        String html = "<div class='comment'>" + userComment + "</div>";

        return html;
    }

    /**
     * Another vulnerable method: Path Traversal
     *
     * @param request HTTP request containing user input
     * @return file content
     * @throws Exception if file operation fails
     */
    public String readFile(HttpServletRequest request) throws Exception {
        // SOURCE: User input from request parameter
        String filePath = request.getParameter("file");

        // VULNERABLE: Path traversal
        // If filePath = "../../../../etc/passwd", sensitive files can be accessed

        // SINK: File system access with untrusted path
        String fullPath = "/safe/directory/" + filePath;

        return new String(java.nio.file.Files.readAllBytes(
            java.nio.file.Paths.get(fullPath)
        ));
    }
}
