#!/usr/bin/env python3
"""Quick start guide for A* pathfinding with semantic heuristics."""

from src.stage2_path_discovery.graph_builder import EnhancedGraphBuilder
from src.stage2_path_discovery.astar_search import AStarPathFinder, SemanticHeuristic
from src.core.models import Source, Sink, CodeLocation, VulnerabilityType


def example_1_basic_astar():
    """Example 1: Basic A* pathfinding without semantic heuristic."""
    print("\n" + "=" * 80)
    print("EXAMPLE 1: Basic A* Pathfinding (No Semantic Heuristic)")
    print("=" * 80)

    # Create simple data flow graph
    import networkx as nx

    graph = nx.DiGraph()
    graph.add_nodes_from(["userInput", "sanitized", "query", "execute"])
    graph.add_edges_from([
        ("userInput", "sanitized"),
        ("sanitized", "query"),
        ("query", "execute"),
    ])

    # Create A* finder without semantic heuristic
    finder = AStarPathFinder(graph, use_semantic=False)

    # Find path
    path = finder.find_path("userInput", "execute")
    print(f"\nPath found: {' -> '.join(path)}")
    print(f"Path length: {len(path)}")


def example_2_with_semantic_heuristic():
    """Example 2: A* with semantic heuristic enabled."""
    print("\n" + "=" * 80)
    print("EXAMPLE 2: A* with Semantic Heuristic")
    print("=" * 80)

    import networkx as nx

    graph = nx.DiGraph()
    graph.add_nodes_from(
        ["userInput", "processed", "transformed", "output"],
        var_type="String"
    )
    graph.add_edges_from([
        ("userInput", "processed"),
        ("processed", "transformed"),
        ("transformed", "output"),
    ])

    # Create semantic heuristic
    print("\nInitializing semantic heuristic...")
    heuristic = SemanticHeuristic()

    # Create A* finder with semantic heuristic
    finder = AStarPathFinder(graph, semantic_heuristic=heuristic, use_semantic=True)

    # Find path
    path = finder.find_path("userInput", "output")
    print(f"\nPath found: {' -> '.join(path)}")
    print(f"Path length: {len(path)}")

    # Clear cache to free memory
    heuristic.clear_cache()
    print("\nEmbedding cache cleared")


def example_3_real_world_scenario():
    """Example 3: Real-world SQL injection vulnerability."""
    print("\n" + "=" * 80)
    print("EXAMPLE 3: Real-World SQL Injection Scenario")
    print("=" * 80)

    java_code = """
    public void searchUsers(HttpServletRequest request) {
        String searchTerm = request.getParameter("search");
        String sanitized = sanitize(searchTerm);
        String query = "SELECT * FROM users WHERE name='" + sanitized + "'";
        ResultSet rs = connection.executeQuery(query);
        return rs;
    }
    """

    print("Java Code:")
    print(java_code)

    # Build enhanced graph
    print("\nBuilding enhanced data flow graph...")
    builder = EnhancedGraphBuilder()

    # Define source and sink
    source = Source(
        location=CodeLocation(file_path="UserController.java", line_number=2),
        variable_name="searchTerm",
        type="HTTP Parameter",
        confidence=0.95,
    )

    sink = Sink(
        location=CodeLocation(file_path="UserController.java", line_number=4),
        variable_name="query",
        type="SQL Query",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        confidence=0.92,
    )

    graph = builder.build_graph(java_code, [source], [sink])

    print(f"Graph built: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")

    # Find path using A*
    print("\nFinding optimal path using A*...")
    heuristic = SemanticHeuristic()
    finder = AStarPathFinder(graph, semantic_heuristic=heuristic)

    path = finder.find_path("searchTerm", "query")
    if path:
        print(f"Vulnerability path found: {' -> '.join(path)}")
        print(f"Path length: {len(path)} nodes")
    else:
        print("No path found (data might be properly sanitized)")

    heuristic.clear_cache()


def example_4_multiple_chains():
    """Example 4: Finding all taint chains."""
    print("\n" + "=" * 80)
    print("EXAMPLE 4: Finding All Taint Chains")
    print("=" * 80)

    import networkx as nx

    # Create graph with multiple paths
    graph = nx.DiGraph()

    graph.add_nodes_from([
        "userInput",
        "var1", "var2", "var3",
        "sink1", "sink2",
    ], var_type="String")

    graph.add_edges_from([
        ("userInput", "var1"),
        ("userInput", "var2"),
        ("var1", "var3"),
        ("var2", "var3"),
        ("var3", "sink1"),
        ("var2", "sink2"),
    ])

    # Define sources and sinks
    source = Source(
        location=CodeLocation(file_path="test.java", line_number=1),
        variable_name="userInput",
        type="User Input",
        confidence=0.9,
    )

    sink1 = Sink(
        location=CodeLocation(file_path="test.java", line_number=5),
        variable_name="sink1",
        type="Sink 1",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        confidence=0.95,
    )

    sink2 = Sink(
        location=CodeLocation(file_path="test.java", line_number=6),
        variable_name="sink2",
        type="Sink 2",
        vulnerability_type=VulnerabilityType.XSS,
        confidence=0.88,
    )

    # Find all chains
    print("\nFinding all chains from source to sinks...")
    heuristic = SemanticHeuristic()
    finder = AStarPathFinder(graph, semantic_heuristic=heuristic)

    chains = finder.find_all_chains([source], [sink1, sink2])

    print(f"\nFound {len(chains)} taint chains:")
    for i, chain in enumerate(chains, 1):
        path_str = " -> ".join(node.variable_name for node in chain.path)
        print(f"  Chain {i}: {path_str}")
        print(f"    Type: {chain.vulnerability_type}")
        print(f"    Confidence: {chain.confidence:.2f}")

    heuristic.clear_cache()


def example_5_compare_algorithms():
    """Example 5: Compare A* vs BFS."""
    print("\n" + "=" * 80)
    print("EXAMPLE 5: A* vs BFS Comparison")
    print("=" * 80)

    import networkx as nx
    from src.stage2_path_discovery.simple_path_finder import SimpleBFSPathFinder

    # Create a larger graph where A* is more efficient
    graph = nx.DiGraph()

    # Chain: 0 -> 1 -> 2 -> 3 -> ... -> 10
    nodes = [str(i) for i in range(11)]
    edges = [(str(i), str(i + 1)) for i in range(10)]

    # Add some alternative paths (longer)
    edges.extend([
        ("0", "5"),  # Skip ahead
        ("5", "10"),
    ])

    graph.add_nodes_from(nodes, var_type="String")
    graph.add_edges_from(edges)

    print(f"Graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")

    # BFS approach
    print("\n--- BFS Approach ---")
    bfs_finder = SimpleBFSPathFinder(graph)
    bfs_path = bfs_finder.find_path("0", "10")
    print(f"BFS path: {' -> '.join(bfs_path)}")

    # A* approach
    print("\n--- A* Approach ---")
    heuristic = SemanticHeuristic()
    astar_finder = AStarPathFinder(graph, semantic_heuristic=heuristic)
    astar_path = astar_finder.find_path("0", "10")
    print(f"A* path: {' -> '.join(astar_path)}")

    # Both should find a path, A* with better heuristic guidance
    print(f"\nBFS path length: {len(bfs_path)}")
    print(f"A* path length: {len(astar_path)}")

    heuristic.clear_cache()


def example_6_no_path():
    """Example 6: Handling case when no path exists."""
    print("\n" + "=" * 80)
    print("EXAMPLE 6: No Path Scenario")
    print("=" * 80)

    import networkx as nx

    # Create disconnected graph
    graph = nx.DiGraph()
    graph.add_nodes_from(["a", "b", "c", "d"])
    graph.add_edges_from([
        ("a", "b"),  # Component 1
        ("c", "d"),  # Component 2
    ])

    finder = AStarPathFinder(graph)

    # Try to find path between disconnected components
    path = finder.find_path("a", "d")

    if path:
        print(f"Path found: {' -> '.join(path)}")
    else:
        print("No path found (nodes are disconnected)")


if __name__ == "__main__":
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "A* PATHFINDING USAGE EXAMPLES" + " " * 29 + "║")
    print("╚" + "=" * 78 + "╝")

    # Run examples
    example_1_basic_astar()
    example_2_with_semantic_heuristic()
    example_3_real_world_scenario()
    example_4_multiple_chains()
    example_5_compare_algorithms()
    example_6_no_path()

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print("""
Key takeaways:

1. **A* with Semantic Heuristic**: Finds optimal paths faster than BFS
2. **EnhancedGraphBuilder**: Extracts variable types and control flow
3. **SemanticHeuristic**: Uses CodeBERT for semantic distance estimation
4. **Integration**: Works seamlessly with Stage 1 (Sources/Sinks) and Stage 3

Next steps:
- Read: docs/ASTAR_AND_GRAPH_BUILDER.md
- Test: pytest tests/integration/test_astar_search.py
- Integrate: Update Stage 2 orchestrator to use AStarPathFinder
    """)
    print("=" * 80 + "\n")
