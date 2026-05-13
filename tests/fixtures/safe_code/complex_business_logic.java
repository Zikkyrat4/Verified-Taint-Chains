/**
 * Complex Business Logic - No Vulnerabilities
 *
 * Complex code with user input but no security issues
 * Expected: NO vulnerability detected
 */
public class ComplexBusinessLogic {
    public void processOrder(HttpServletRequest request) {
        // User input
        String quantity = request.getParameter("quantity");
        String productId = request.getParameter("productId");

        // Safe: Parsing and validation
        int qty = Integer.parseInt(quantity);
        if (qty <= 0 || qty > 100) {
            throw new IllegalArgumentException("Invalid quantity");
        }

        // Safe: Using safe API
        Product product = productRepository.findById(productId);

        // Safe: Business logic, no dangerous sinks
        Order order = new Order();
        order.setQuantity(qty);
        order.setProduct(product);
        order.setStatus("PENDING");

        orderRepository.save(order);
    }
}
