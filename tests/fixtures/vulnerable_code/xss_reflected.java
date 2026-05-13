/**
 * XSS - Reflected Cross-Site Scripting
 *
 * Vulnerability: User input directly output to HTML without encoding
 * Expected: Source at line 9, Sink at line 10
 * CWE: CWE-79
 */
public class XSSReflected {
    public void displayWelcome(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        response.getWriter().write("<h1>Welcome, " + name + "</h1>");
    }

    public void showSearchResults(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String searchQuery = request.getParameter("q");
        PrintWriter out = response.getWriter();
        out.println("<p>You searched for: " + searchQuery + "</p>");
        // Display results...
    }
}
