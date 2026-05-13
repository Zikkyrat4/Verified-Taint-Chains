/**
 * SQL Injection - Complex with Multiple Inputs
 *
 * Vulnerability: Multiple user inputs in SQL query with conditional logic
 * Expected: Multiple sources (line 9, 10), Sink at line 18
 * CWE: CWE-89
 */
public class SQLInjectionComplex {
    public List<User> searchUsers(HttpServletRequest request) {
        String username = request.getParameter("username");
        String email = request.getParameter("email");

        StringBuilder query = new StringBuilder("SELECT * FROM users WHERE 1=1");

        if (username != null && !username.isEmpty()) {
            query.append(" AND username LIKE '%" + username + "%'");
        }

        if (email != null && !email.isEmpty()) {
            query.append(" AND email = '" + email + "'");
        }

        try {
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query.toString());
            return processResults(rs);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
}
