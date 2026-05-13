/**
 * Safe Code - SQL with Prepared Statements
 *
 * No vulnerability: Uses parameterized queries
 * Expected: NO vulnerability detected
 */
public class SQLSafePreparedStatement {
    public void getUserData(HttpServletRequest request) {
        String userId = request.getParameter("id");

        // SAFE: Using PreparedStatement
        String query = "SELECT * FROM users WHERE id = ?";

        try {
            PreparedStatement pstmt = connection.prepareStatement(query);
            pstmt.setString(1, userId);  // Properly parameterized
            ResultSet rs = pstmt.executeQuery();
            // Process results...
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public List<User> searchUsers(HttpServletRequest request) {
        String username = request.getParameter("username");
        String email = request.getParameter("email");

        // SAFE: Using PreparedStatement with multiple parameters
        String query = "SELECT * FROM users WHERE username = ? AND email = ?";

        try {
            PreparedStatement pstmt = connection.prepareStatement(query);
            pstmt.setString(1, username);
            pstmt.setString(2, email);
            ResultSet rs = pstmt.executeQuery();
            return processResults(rs);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
}
