/**
 * Multiple Vulnerabilities in One File
 *
 * Contains: SQL Injection, XSS, Path Traversal
 * Expected: 3 separate chains detected
 */
public class MultipleVulnerabilities {
    // Vulnerability 1: SQL Injection
    public void login(HttpServletRequest request) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String query = "SELECT * FROM users WHERE username='" + username +
                       "' AND password='" + password + "'";

        try {
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            // Check login...
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Vulnerability 2: XSS
    public void displayProfile(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String bio = request.getParameter("bio");
        response.getWriter().write("<p>Bio: " + bio + "</p>");
    }

    // Vulnerability 3: Path Traversal
    public void getAvatar(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String avatarFile = request.getParameter("avatar");
        File file = new File("/var/www/avatars/" + avatarFile);
        FileInputStream fis = new FileInputStream(file);
        // Stream file...
    }
}
