/**
 * XSS - Partial Sanitization (Still Vulnerable)
 *
 * Vulnerability: Incomplete sanitization that can be bypassed
 * Expected: Source at line 11, Sanitizer at line 14, Sink at line 17
 * CWE: CWE-79
 */
public class XSSPartialSanitization {
    public void displayMessage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String message = request.getParameter("msg");

        // Incomplete sanitization - only removes <script> tags
        String cleaned = message.replaceAll("<script>", "").replaceAll("</script>", "");

        // Still vulnerable to <img onerror=...>, <iframe>, etc.
        response.getWriter().write("<div>" + cleaned + "</div>");
    }
}
