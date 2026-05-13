/**
 * Safe Code - XSS with Proper Encoding
 *
 * No vulnerability: User input is properly encoded before output
 * Expected: NO vulnerability detected
 */
public class XSSSafeEncoding {
    public void displayWelcome(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");

        // SAFE: Using HtmlUtils to encode output
        String encoded = HtmlUtils.htmlEscape(name);
        response.getWriter().write("<h1>Welcome, " + encoded + "</h1>");
    }

    public void showSearchResults(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String searchQuery = request.getParameter("q");

        // SAFE: Encoding before output
        String safeQuery = StringEscapeUtils.escapeHtml4(searchQuery);
        PrintWriter out = response.getWriter();
        out.println("<p>You searched for: " + safeQuery + "</p>");
    }

    // Using JSTL (auto-escapes by default)
    // In JSP: <c:out value="${param.name}" />
}
