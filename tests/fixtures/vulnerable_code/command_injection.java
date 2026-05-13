/**
 * Command Injection - OS Command Execution
 *
 * Vulnerability: User input passed to system command execution
 * Expected: Source at line 9, Sink at line 10
 * CWE: CWE-78
 */
public class CommandInjection {
    public void pingHost(HttpServletRequest request) {
        String hostname = request.getParameter("host");
        String command = "ping -c 4 " + hostname;
        try {
            Process process = Runtime.getRuntime().exec(command);
            // Read output...
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void listFiles(HttpServletRequest request) {
        String directory = request.getParameter("dir");
        try {
            Process p = Runtime.getRuntime().exec("ls -la " + directory);
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            // Process output...
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
