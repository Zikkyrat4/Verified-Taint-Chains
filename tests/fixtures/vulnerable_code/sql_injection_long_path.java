/**
 * SQL Injection - Long Path with Multiple Transformations
 *
 * Vulnerability: User input flows through multiple variables before reaching sink
 * Expected: Source at line 10, Sink at line 20 (long path)
 * CWE: CWE-89
 */
public class SQLInjectionLongPath {
    public void complexQuery(HttpServletRequest request) {
        // Source
        String userInput = request.getParameter("search");

        // Path node 1
        String trimmed = userInput.trim();

        // Path node 2
        String lowercase = trimmed.toLowerCase();

        // Path node 3
        String searchTerm = lowercase.replace(" ", "%");

        // Path node 4
        String queryPart = "%" + searchTerm + "%";

        // Sink
        String query = "SELECT * FROM products WHERE name LIKE '" + queryPart + "'";

        try {
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            // Process results...
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
