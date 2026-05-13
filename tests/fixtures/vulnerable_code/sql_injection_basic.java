/**
 * SQL Injection - Basic String Concatenation
 *
 * Vulnerability: User input concatenated directly into SQL query
 * Expected: Source at line 9, Sink at line 10
 * CWE: CWE-89
 */
public class SQLInjectionBasic {
    public void getUserData(HttpServletRequest request) {
        String userId = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        try {
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            // Process results...
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
