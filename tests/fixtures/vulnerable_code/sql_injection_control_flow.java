/**
 * SQL Injection - Complex Control Flow
 *
 * Vulnerability: User input reaches SQL through if/else and loops
 * Expected: Source at line 11, Sink at line 29
 * CWE: CWE-89
 */
public class SQLInjectionControlFlow {
    public List<Product> searchProducts(HttpServletRequest request) {
        String category = request.getParameter("category");
        String priceRange = request.getParameter("price");

        StringBuilder query = new StringBuilder("SELECT * FROM products WHERE 1=1");

        // Control flow: if statement
        if (category != null && !category.isEmpty()) {
            query.append(" AND category = '").append(category).append("'");
        }

        // Control flow: loop
        String[] keywords = request.getParameterValues("keywords");
        if (keywords != null) {
            for (String keyword : keywords) {
                query.append(" AND description LIKE '%").append(keyword).append("%'");
            }
        }

        // Sink
        try {
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query.toString());
            return processResults(rs);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
}
