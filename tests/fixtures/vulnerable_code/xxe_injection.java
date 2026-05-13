/**
 * XXE - XML External Entity Injection
 *
 * Vulnerability: XML parser processes external entities from user input
 * Expected: Source at line 10, Sink at line 14
 * CWE: CWE-611
 */
public class XXEInjection {
    public void parseXMLData(HttpServletRequest request) {
        try {
            String xmlData = request.getParameter("xml");

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));

            // Process XML document...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
