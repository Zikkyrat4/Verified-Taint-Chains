/**
 * Safe Code - Path Traversal with Validation
 *
 * No vulnerability: Path is validated and canonicalized
 * Expected: NO vulnerability detected
 */
public class PathSafeValidation {
    private static final Path BASE_PATH = Paths.get("/var/www/uploads");

    public void downloadFile(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("file");

        // SAFE: Canonicalize and validate path
        Path basePath = BASE_PATH.toRealPath();
        Path filePath = basePath.resolve(filename).normalize();

        // Check if resolved path is still inside base directory
        if (!filePath.startsWith(basePath)) {
            throw new SecurityException("Path traversal attempt detected");
        }

        if (Files.exists(filePath)) {
            FileInputStream fis = new FileInputStream(filePath.toFile());
            OutputStream os = response.getOutputStream();
            // Copy file to response...
        }
    }

    public String readUserFile(HttpServletRequest request) {
        String userFile = request.getParameter("filename");

        // SAFE: Whitelist validation
        if (!userFile.matches("^[a-zA-Z0-9._-]+$")) {
            throw new IllegalArgumentException("Invalid filename");
        }

        // SAFE: Reject path traversal sequences
        if (userFile.contains("..") || userFile.contains("/") || userFile.contains("\\")) {
            throw new SecurityException("Path traversal detected");
        }

        Path filePath = Paths.get("/app/data/", userFile);

        try {
            return Files.readString(filePath);
        } catch (IOException e) {
            return "Error reading file";
        }
    }
}
