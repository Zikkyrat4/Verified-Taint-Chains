/**
 * Path Traversal - Directory Traversal
 *
 * Vulnerability: User input used in file path without validation
 * Expected: Source at line 9, Sink at line 10
 * CWE: CWE-22
 */
public class PathTraversal {
    public void downloadFile(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("file");
        File file = new File("/var/www/uploads/" + filename);

        if (file.exists()) {
            FileInputStream fis = new FileInputStream(file);
            OutputStream os = response.getOutputStream();
            // Copy file to response...
        }
    }

    public String readUserFile(HttpServletRequest request) {
        String userFile = request.getParameter("filename");
        Path basePath = Paths.get("/app/data/");
        Path filePath = Paths.get(basePath + "/" + userFile);

        try {
            return Files.readString(filePath);
        } catch (IOException e) {
            return "Error reading file";
        }
    }
}
