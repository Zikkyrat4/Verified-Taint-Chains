"""Example: Using symbolic execution for high-confidence verification.

This example demonstrates how to use the new symbolic execution feature
for comprehensive taint chain verification.
"""

import asyncio
from src.core.config import PipelineConfig
from src.pipeline.orchestrator import SimplePipeline
from src.stage3_verification.verification_engine import VerificationEngine
from src.core.models import (
    TaintChain,
    Source,
    Sink,
    CodeLocation,
    VulnerabilityType,
)


# ============================================================================
# Example 1: Complete Pipeline with Symbolic Execution
# ============================================================================

async def example_1_complete_pipeline():
    """Run complete pipeline with symbolic execution enabled."""
    print("=" * 70)
    print("Example 1: Complete Pipeline with Symbolic Execution")
    print("=" * 70)

    # Create configuration with symbolic execution
    config = PipelineConfig(
        llm_api_key="sk-test-key",  # Replace with real key
        pathfinding_algorithm="astar",
        use_semantic_heuristic=True,
        verification_enabled=True,
        symbolic_execution_enabled=True,  # Enable symbolic execution
    )

    print("\nConfiguration:")
    print(f"  Algorithm: {config.pathfinding_algorithm}")
    print(f"  Semantic heuristic: {config.use_semantic_heuristic}")
    print(f"  Verification: {config.verification_enabled}")
    print(f"  Symbolic execution: {config.symbolic_execution_enabled}")

    # Create vulnerable code example
    code = """
    public class VulnerableApp {
        public void handleRequest(HttpServletRequest request) {
            String id = request.getParameter("id");
            String query = "SELECT * FROM users WHERE id=" + id;
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
        }
    }
    """

    # Save to temporary file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
        f.write(code)
        temp_file = f.name

    try:
        # Create and run pipeline
        pipeline = SimplePipeline(config)
        print(f"\nAnalyzing: {temp_file}")

        # Note: This would require a real OpenAI API key
        # result = await pipeline.run(temp_file)

        print("\nPipeline would execute:")
        print("  1. Stage 1: Extract sources and sinks")
        print("  2. Stage 2: Build graph and find paths (A*)")
        print("  3. Stage 3: Verify with CFG + symbolic execution")
        print("  4. Stage 4: Generate explanations")

    finally:
        import os
        os.unlink(temp_file)

    print("\n✓ Example 1 complete\n")


# ============================================================================
# Example 2: Direct Verification Engine Usage
# ============================================================================

def example_2_verification_engine():
    """Use VerificationEngine directly for verification."""
    print("=" * 70)
    print("Example 2: Direct Verification Engine Usage")
    print("=" * 70)

    # Create config
    config = PipelineConfig(
        llm_api_key="test-key",
        symbolic_execution_enabled=True,
    )

    # Create verification engine
    engine = VerificationEngine(
        config,
        max_loop_iterations=10,
        symbolic_timeout=30,
    )

    print("\nVerification Engine initialized:")
    print(f"  CFG enabled: True")
    print(f"  Symbolic execution enabled: {config.symbolic_execution_enabled}")
    print(f"  Max loop iterations: 10")
    print(f"  Symbolic timeout: 30s")

    # Get backend info
    stats = engine.get_statistics()
    print(f"\nBackend information:")
    print(f"  Symbolic backend: {stats['symbolic'].get('backend', 'N/A')}")
    print(f"  Z3 available: {stats['symbolic'].get('z3_available', False)}")

    # Example vulnerable code
    code = """
    String input = request.getParameter("q");
    String query = "SELECT * FROM users WHERE name='" + input + "'";
    db.execute(query);
    """

    # Create taint chain
    chain = TaintChain(
        id="sqli-example",
        source=Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="input",
            type="User Input",
            confidence=0.95,
        ),
        sink=Sink(
            location=CodeLocation(file_path="test.java", line_number=3),
            variable_name="query",
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.95,
        ),
        path=["input", "query"],
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
    )

    print("\nVerifying taint chain:")
    print(f"  Source: {chain.source.variable_name}")
    print(f"  Sink: {chain.sink.variable_name}")
    print(f"  Type: {chain.vulnerability_type.value}")

    # Verify the chain
    result = engine.verify_chain(chain, code)

    print(f"\nVerification Result:")
    print(f"  Overall status: {result.status.value}")
    print(f"  CFG status: {result.cfg_status.value}")
    print(f"  Symbolic status: {result.symbolic_status.value if result.symbolic_status else 'N/A'}")
    print(f"  Confidence: {result.confidence:.2f}")
    print(f"  Method used: {result.method_used}")
    print(f"  Details: {result.details}")

    print("\n✓ Example 2 complete\n")


# ============================================================================
# Example 3: Comparing CFG-Only vs CFG + Symbolic
# ============================================================================

def example_3_comparison():
    """Compare CFG-only vs CFG + symbolic execution."""
    print("=" * 70)
    print("Example 3: CFG-Only vs CFG + Symbolic Execution")
    print("=" * 70)

    code = """
    String name = request.getParameter("name");
    String message = "Hello, " + name;
    response.getWriter().write(message);
    """

    chain = TaintChain(
        id="xss-example",
        source=Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="name",
            type="User Input",
            confidence=0.9,
        ),
        sink=Sink(
            location=CodeLocation(file_path="test.java", line_number=3),
            variable_name="message",
            type="HTML Output",
            vulnerability_type=VulnerabilityType.XSS,
            confidence=0.9,
        ),
        path=["name", "message"],
        vulnerability_type=VulnerabilityType.XSS,
    )

    # Test 1: CFG-only
    print("\n--- Test 1: CFG-Only Verification ---")
    config_cfg = PipelineConfig(
        llm_api_key="test-key",
        symbolic_execution_enabled=False,
    )
    engine_cfg = VerificationEngine(config_cfg)
    result_cfg = engine_cfg.verify_chain(chain, code)

    print(f"Status: {result_cfg.status.value}")
    print(f"Confidence: {result_cfg.confidence:.2f}")
    print(f"Method: {result_cfg.method_used}")

    # Test 2: CFG + Symbolic
    print("\n--- Test 2: CFG + Symbolic Execution ---")
    config_symbolic = PipelineConfig(
        llm_api_key="test-key",
        symbolic_execution_enabled=True,
    )
    engine_symbolic = VerificationEngine(config_symbolic)
    result_symbolic = engine_symbolic.verify_chain(chain, code)

    print(f"Status: {result_symbolic.status.value}")
    print(f"Confidence: {result_symbolic.confidence:.2f}")
    print(f"Method: {result_symbolic.method_used}")

    # Compare
    print("\n--- Comparison ---")
    print(f"CFG-only confidence: {result_cfg.confidence:.2f}")
    print(f"Symbolic confidence: {result_symbolic.confidence:.2f}")
    print(f"Confidence improvement: {result_symbolic.confidence - result_cfg.confidence:.2f}")

    print("\n✓ Example 3 complete\n")


# ============================================================================
# Example 4: Batch Verification
# ============================================================================

def example_4_batch_verification():
    """Verify multiple chains in batch."""
    print("=" * 70)
    print("Example 4: Batch Verification")
    print("=" * 70)

    code = """
    String input1 = request.getParameter("id");
    String input2 = request.getParameter("name");
    String query = "SELECT * FROM users WHERE id=" + input1;
    String message = "Hello, " + input2;
    db.execute(query);
    response.getWriter().write(message);
    """

    # Create multiple chains
    chains = [
        TaintChain(
            id="chain-1-sqli",
            source=Source(
                location=CodeLocation(file_path="test.java", line_number=1),
                variable_name="input1",
                type="User Input",
                confidence=0.95,
            ),
            sink=Sink(
                location=CodeLocation(file_path="test.java", line_number=5),
                variable_name="query",
                type="SQL",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                confidence=0.95,
            ),
            path=["input1", "query"],
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        ),
        TaintChain(
            id="chain-2-xss",
            source=Source(
                location=CodeLocation(file_path="test.java", line_number=2),
                variable_name="input2",
                type="User Input",
                confidence=0.9,
            ),
            sink=Sink(
                location=CodeLocation(file_path="test.java", line_number=6),
                variable_name="message",
                type="HTML Output",
                vulnerability_type=VulnerabilityType.XSS,
                confidence=0.9,
            ),
            path=["input2", "message"],
            vulnerability_type=VulnerabilityType.XSS,
        ),
    ]

    print(f"\nVerifying {len(chains)} chains...")

    # Create engine with symbolic execution
    config = PipelineConfig(
        llm_api_key="test-key",
        symbolic_execution_enabled=True,
    )
    engine = VerificationEngine(config)

    # Verify all chains
    results = engine.verify_all_chains(chains, code)

    print(f"\nResults:")
    print(f"  Total chains: {results['total']}")
    print(f"  Verified: {len(results['verified'])}")
    print(f"  False: {len(results['false'])}")
    print(f"  Unverifiable: {len(results['unverifiable'])}")
    print(f"  Verification rate: {results['verification_rate']:.1%}")
    print(f"  Average confidence: {results['avg_confidence']:.2f}")
    print(f"\nMethod counts:")
    for method, count in results['method_counts'].items():
        print(f"  {method}: {count}")

    print("\n✓ Example 4 complete\n")


# ============================================================================
# Example 5: Performance Comparison
# ============================================================================

def example_5_performance():
    """Compare performance of CFG vs symbolic execution."""
    print("=" * 70)
    print("Example 5: Performance Comparison")
    print("=" * 70)

    import time

    code = """
    String x = input;
    String y = x;
    String z = y;
    process(z);
    """

    chain = TaintChain(
        id="perf-test",
        source=Source(
            location=CodeLocation(file_path="test.java", line_number=1),
            variable_name="input",
            type="Input",
            confidence=0.9,
        ),
        sink=Sink(
            location=CodeLocation(file_path="test.java", line_number=4),
            variable_name="z",
            type="Output",
            vulnerability_type=VulnerabilityType.XSS,
            confidence=0.9,
        ),
        path=["input", "x", "y", "z"],
        vulnerability_type=VulnerabilityType.XSS,
    )

    # Test CFG-only performance
    print("\nTesting CFG-only performance...")
    config_cfg = PipelineConfig(
        llm_api_key="test-key",
        symbolic_execution_enabled=False,
    )
    engine_cfg = VerificationEngine(config_cfg)

    start = time.time()
    result_cfg = engine_cfg.verify_chain(chain, code)
    cfg_time = time.time() - start

    print(f"  Time: {cfg_time*1000:.2f}ms")
    print(f"  Status: {result_cfg.status.value}")
    print(f"  Confidence: {result_cfg.confidence:.2f}")

    # Test symbolic execution performance
    print("\nTesting symbolic execution performance...")
    config_symbolic = PipelineConfig(
        llm_api_key="test-key",
        symbolic_execution_enabled=True,
    )
    engine_symbolic = VerificationEngine(config_symbolic)

    start = time.time()
    result_symbolic = engine_symbolic.verify_chain(chain, code)
    symbolic_time = time.time() - start

    print(f"  Time: {symbolic_time*1000:.2f}ms")
    print(f"  Status: {result_symbolic.status.value}")
    print(f"  Confidence: {result_symbolic.confidence:.2f}")

    # Compare
    print("\n--- Performance Comparison ---")
    print(f"CFG-only: {cfg_time*1000:.2f}ms")
    print(f"Symbolic: {symbolic_time*1000:.2f}ms")
    print(f"Slowdown: {symbolic_time/cfg_time:.1f}x")
    print(f"Confidence gain: +{result_symbolic.confidence - result_cfg.confidence:.2f}")

    print("\n✓ Example 5 complete\n")


# ============================================================================
# Main
# ============================================================================

def main():
    """Run all examples."""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  Symbolic Execution Examples".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "=" * 68 + "╝")
    print("\n")

    # Run synchronous examples
    example_2_verification_engine()
    example_3_comparison()
    example_4_batch_verification()
    example_5_performance()

    # Run async example
    print("Running async example...")
    asyncio.run(example_1_complete_pipeline())

    print("\n" + "=" * 70)
    print("All examples completed successfully!")
    print("=" * 70)
    print("\nKey Takeaways:")
    print("  1. Symbolic execution provides higher confidence (0.95 vs 0.6)")
    print("  2. CFG provides fast reject for unreachable paths")
    print("  3. Two-level strategy optimizes speed and accuracy")
    print("  4. Batch verification supports multiple chains efficiently")
    print("  5. Z3 solver required for symbolic execution")
    print("\nTo enable in your code:")
    print("  config.symbolic_execution_enabled = True")
    print("")


if __name__ == "__main__":
    main()
