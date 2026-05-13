/**
 * SSRF - Server-Side Request Forgery
 *
 * Vulnerability: User-controlled URL in server-side request
 * Expected: Source at line 10, Sink at line 11
 * CWE: CWE-918
 */
public class SSRFAttack {
    public String fetchContent(HttpServletRequest request) {
        try {
            String targetUrl = request.getParameter("url");
            URL url = new URL(targetUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream())
            );

            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }

            return content.toString();
        } catch (Exception e) {
            return "Error fetching content";
        }
    }

    public void proxyRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String imageUrl = request.getParameter("imageUrl");
        URL url = new URL(imageUrl);
        InputStream is = url.openStream();
        // Stream image to response...
    }
}
