/**
 * Safe Code - Command Execution with Array
 *
 * No vulnerability: Uses command array (no shell interpretation)
 * Expected: NO vulnerability detected
 */
public class CommandSafeArray {
    public void pingHost(HttpServletRequest request) {
        String hostname = request.getParameter("host");

        // SAFE: Using array form (no shell)
        String[] command = {"ping", "-c", "4", hostname};

        try {
            Process process = Runtime.getRuntime().exec(command);
            // Read output...
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void listFiles(HttpServletRequest request) {
        String directory = request.getParameter("dir");

        // SAFE: Using ProcessBuilder with separate arguments
        ProcessBuilder pb = new ProcessBuilder("ls", "-la", directory);
        pb.redirectErrorStream(true);

        try {
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(p.getInputStream())
            );
            // Process output...
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Even better: Avoid system commands entirely
    public void listFilesJava(String directory) {
        File dir = new File(directory);
        File[] files = dir.listFiles();
        // Process files using Java APIs
    }
}
