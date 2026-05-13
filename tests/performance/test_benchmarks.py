"""Performance benchmarks for the analysis pipeline.

This module tests performance characteristics including:
- Time per stage
- Memory usage
- Scalability with code size
- Verification overhead
"""

import asyncio
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, List
from unittest.mock import AsyncMock, Mock, patch

import psutil
import pytest

from src.core.config import PipelineConfig
from src.core.models import (
    CodeLocation,
    PathNode,
    Source,
    Sink,
    TaintChain,
    VulnerabilityType,
)
from src.pipeline.orchestrator import SimplePipeline
from src.core.models import Specification


# Performance limits (adjust based on requirements)
ACCEPTABLE_LIMITS = {
    "small_file_time": 5.0,  # seconds for small file (<100 lines)
    "medium_file_time": 15.0,  # seconds for medium file (<500 lines)
    "large_file_time": 60.0,  # seconds for large file (<2000 lines)
    "memory_increase": 500.0,  # MB max increase per analysis
    "stage1_time": 3.0,  # seconds for LLM inference
    "stage2_time": 2.0,  # seconds for path discovery
    "stage3_cfg_time": 1.0,  # seconds for CFG verification
    "stage3_symbolic_time": 30.0,  # seconds for symbolic execution
    "stage4_time": 3.0,  # seconds for explanation generation
}


def _make_mock_spec_result(sources=None, sinks=None):
    """Create a Specification object for mocking."""
    if sources is None:
        sources = []
    if sinks is None:
        sinks = []

    source_objs = [
        Source(
            location=CodeLocation(file_path="test.java", line_number=s.get("line_number", 1)),
            variable_name=s["variable_name"],
            type=s.get("type", "User Input"),
            confidence=s.get("confidence", 0.9),
            code_snippet="",
        )
        for s in sources
    ]
    sink_objs = [
        Sink(
            location=CodeLocation(file_path="test.java", line_number=s.get("line_number", 1)),
            variable_name=s["variable_name"],
            type=s.get("type", "SQL"),
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=s.get("confidence", 0.9),
            code_snippet="",
        )
        for s in sinks
    ]
    return Specification(
        sources=source_objs,
        sinks=sink_objs,
        llm_model="test-model",
    )


def _run_pipeline_on_code(code: str, config: PipelineConfig, mock_spec_result=None):
    """Write code to temp file and run pipeline with mocked spec extractor."""
    pipeline = SimplePipeline(config)

    if mock_spec_result is None:
        mock_spec_result = _make_mock_spec_result()

    pipeline.spec_extractor = Mock()
    pipeline.spec_extractor.extract = AsyncMock(return_value=mock_spec_result)
    pipeline.explainer.generate_explanation = AsyncMock(return_value={
        "summary": "Test vulnerability",
        "details": "Details here",
    })

    with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
        f.write(code)
        tmp_path = f.name

    try:
        result = asyncio.run(pipeline.run(tmp_path))
    finally:
        os.unlink(tmp_path)

    return result


class TestPipelinePerformance:
    """Test overall pipeline performance."""

    @pytest.mark.performance
    def test_small_file_performance(
        self,
        performance_tracker,
        load_fixture_file,
    ) -> None:
        """Test performance on small file (<100 lines)."""
        code = load_fixture_file("sql_injection_basic.java", "vulnerable")

        mock_spec = _make_mock_spec_result(
            sources=[{"variable_name": "userId", "line_number": 9, "confidence": 0.9}],
            sinks=[{"variable_name": "query", "line_number": 10, "confidence": 0.85}],
        )

        config = PipelineConfig(llm_api_key="test-key", use_llm_graph_builder=False)

        performance_tracker.start()
        result = _run_pipeline_on_code(code, config, mock_spec)
        performance_tracker.stop()

        duration = performance_tracker.duration
        memory_delta = performance_tracker.memory_delta

        print(f"\nSmall file performance:")
        print(f"  Time: {duration:.2f}s (limit: {ACCEPTABLE_LIMITS['small_file_time']}s)")
        print(f"  Memory: {memory_delta:+.2f}MB (limit: {ACCEPTABLE_LIMITS['memory_increase']}MB)")

        assert duration < ACCEPTABLE_LIMITS["small_file_time"], \
            f"Small file analysis took {duration:.2f}s, limit is {ACCEPTABLE_LIMITS['small_file_time']}s"

        assert abs(memory_delta) < ACCEPTABLE_LIMITS["memory_increase"], \
            f"Memory increase {memory_delta:.2f}MB exceeds limit {ACCEPTABLE_LIMITS['memory_increase']}MB"

    @pytest.mark.performance
    @pytest.mark.slow
    def test_medium_file_performance(
        self,
        performance_tracker,
        load_fixture_file,
    ) -> None:
        """Test performance on medium file (<500 lines)."""
        base_code = load_fixture_file("sql_injection_complex.java", "vulnerable")
        medium_code = base_code * 5

        mock_spec = _make_mock_spec_result(
            sources=[{"variable_name": "username", "line_number": 9, "confidence": 0.9}],
            sinks=[{"variable_name": "query", "line_number": 14, "confidence": 0.85}],
        )

        config = PipelineConfig(llm_api_key="test-key", use_llm_graph_builder=False)

        performance_tracker.start()
        result = _run_pipeline_on_code(medium_code, config, mock_spec)
        performance_tracker.stop()

        duration = performance_tracker.duration
        memory_delta = performance_tracker.memory_delta

        print(f"\nMedium file performance:")
        print(f"  Code size: {len(medium_code)} bytes")
        print(f"  Time: {duration:.2f}s (limit: {ACCEPTABLE_LIMITS['medium_file_time']}s)")
        print(f"  Memory: {memory_delta:+.2f}MB (limit: {ACCEPTABLE_LIMITS['memory_increase']}MB)")

        assert duration < ACCEPTABLE_LIMITS["medium_file_time"], \
            f"Medium file analysis took {duration:.2f}s, exceeds limit"

    @pytest.mark.performance
    def test_multiple_files_sequential(
        self,
        performance_tracker,
        vulnerable_files: List[Path],
    ) -> None:
        """Test performance of analyzing multiple files sequentially."""
        files_to_test = vulnerable_files[:3]

        mock_spec = _make_mock_spec_result()
        config = PipelineConfig(llm_api_key="test-key", use_llm_graph_builder=False)

        performance_tracker.start()

        results = []
        for file_path in files_to_test:
            start = time.time()
            pipeline = SimplePipeline(config)
            pipeline.spec_extractor = Mock()
            pipeline.spec_extractor.extract = AsyncMock(return_value=mock_spec)
            pipeline.explainer.generate_explanation = AsyncMock(return_value={
                "summary": "Test", "details": "Test",
            })

            result = asyncio.run(pipeline.run(str(file_path)))
            duration = time.time() - start

            results.append({
                "file": file_path.name,
                "time": duration,
            })

        performance_tracker.stop()

        total_time = performance_tracker.duration
        avg_time = total_time / len(files_to_test)

        print(f"\nMultiple files performance:")
        print(f"  Files analyzed: {len(files_to_test)}")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Average per file: {avg_time:.2f}s")

        for r in results:
            print(f"    {r['file']}: {r['time']:.2f}s")

        assert avg_time < ACCEPTABLE_LIMITS["medium_file_time"], \
            f"Average time per file {avg_time:.2f}s exceeds limit"


class TestStagePerformance:
    """Test performance of individual pipeline stages."""

    @pytest.mark.performance
    def test_stage1_llm_inference_time(self) -> None:
        """Test Stage 1 (LLM inference) performance."""
        from src.stage1_llm_inference.llm_client import SimpleLLMClient
        from src.stage1_llm_inference.prompt_templates import build_source_prompt

        mock_llm = Mock(spec=SimpleLLMClient)

        async def fast_mock(code: str, prompt: str) -> Dict:
            await asyncio.sleep(0.1)
            return {"sources": []}

        mock_llm.analyze_code = AsyncMock(side_effect=fast_mock)

        test_code = "public class Test { }"
        prompt = build_source_prompt(test_code)

        start = time.time()
        result = asyncio.run(mock_llm.analyze_code(test_code, prompt))
        duration = time.time() - start

        print(f"\nStage 1 (LLM Inference) performance:")
        print(f"  Time: {duration:.2f}s (limit: {ACCEPTABLE_LIMITS['stage1_time']}s)")

        assert duration < 1.0, "Mock LLM should be very fast"

    @pytest.mark.performance
    def test_stage2_path_discovery_time(
        self,
        sample_source,
        sample_sink,
    ) -> None:
        """Test Stage 2 (Path discovery) performance."""
        from src.stage2_path_discovery.simple_path_finder import SimpleBFSPathFinder
        import networkx as nx

        # Create test graph with 50 nodes
        graph = nx.DiGraph()
        for i in range(50):
            graph.add_node(f"var_{i}")
            if i > 0:
                graph.add_edge(f"var_{i-1}", f"var_{i}")

        # Source and sink node names must exist in graph
        graph.add_node(sample_source.variable_name, type="source")
        graph.add_node(sample_sink.variable_name, type="sink")
        graph.add_edge("var_49", sample_sink.variable_name)
        graph.add_edge(sample_source.variable_name, "var_0")

        finder = SimpleBFSPathFinder(graph)

        start = time.time()
        chains = finder.find_all_chains([sample_source], [sample_sink], max_length=60)
        duration = time.time() - start

        print(f"\nStage 2 (Path Discovery) performance:")
        print(f"  Graph nodes: {len(graph.nodes)}")
        print(f"  Time: {duration:.2f}s (limit: {ACCEPTABLE_LIMITS['stage2_time']}s)")

        assert duration < ACCEPTABLE_LIMITS["stage2_time"], \
            f"Path discovery took {duration:.2f}s, exceeds limit"

    @pytest.mark.performance
    def test_stage3_cfg_verification_time(self) -> None:
        """Test Stage 3 (CFG verification) performance."""
        from src.stage3_verification.simple_verifier import SimpleCFGVerifier
        from src.stage2_path_discovery.simple_path_finder import SimpleGraphBuilder
        import networkx as nx

        test_code = """
        public class Test {
            void method() {
                String input = getInput();
                String var1 = input;
                String var2 = var1;
                if (condition) {
                    var2 = transform(var2);
                }
                for (int i = 0; i < 10; i++) {
                    var2 = process(var2);
                }
                sink(var2);
            }
        }
        """

        # Build a graph from the code
        builder = SimpleGraphBuilder()
        graph = builder.build_graph(test_code, [], [])

        verifier = SimpleCFGVerifier(graph)

        start = time.time()
        reachable = verifier.verify_reachability("input", "var2")
        duration = time.time() - start

        print(f"\nStage 3 (CFG Verification) performance:")
        print(f"  Time: {duration:.2f}s (limit: {ACCEPTABLE_LIMITS['stage3_cfg_time']}s)")

        assert duration < ACCEPTABLE_LIMITS["stage3_cfg_time"], \
            f"CFG verification took {duration:.2f}s, exceeds limit"

    @pytest.mark.performance
    @pytest.mark.slow
    def test_stage3_symbolic_execution_time(
        self,
        sample_taint_chain,
    ) -> None:
        """Test Stage 3 (Symbolic execution) performance."""
        from src.stage3_verification.symbolic_executor import (
            SymbolicExecutor,
            Z3_AVAILABLE,
        )

        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")

        test_code = """
        String input = getInput();
        String output = input;
        executeQuery(output);
        """

        executor = SymbolicExecutor(timeout=5)

        start = time.time()
        status = executor.execute_path(sample_taint_chain, test_code)
        duration = time.time() - start

        print(f"\nStage 3 (Symbolic Execution) performance:")
        print(f"  Time: {duration:.2f}s (limit: {ACCEPTABLE_LIMITS['stage3_symbolic_time']}s)")
        print(f"  Status: {status.value}")

        assert duration < ACCEPTABLE_LIMITS["stage3_symbolic_time"], \
            f"Symbolic execution took {duration:.2f}s, exceeds limit"

    @pytest.mark.performance
    def test_stage4_explanation_generation_time(
        self,
        sample_taint_chain,
    ) -> None:
        """Test Stage 4 (Explanation generation) performance."""
        from src.stage4_explanation.explanation_generator import ExplanationGenerator

        mock_llm = Mock()
        mock_llm.analyze_code = AsyncMock(return_value={
            "why_vulnerable": "User input is concatenated into SQL query",
            "how_to_fix": "Use parameterized queries",
            "example_fix": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id=?\");",
        })

        generator = ExplanationGenerator(mock_llm)

        start = time.time()
        explanation = asyncio.run(generator.generate_explanation(sample_taint_chain))
        duration = time.time() - start

        print(f"\nStage 4 (Explanation Generation) performance:")
        print(f"  Time: {duration:.2f}s (limit: {ACCEPTABLE_LIMITS['stage4_time']}s)")

        assert duration < ACCEPTABLE_LIMITS["stage4_time"], \
            f"Explanation generation took {duration:.2f}s, exceeds limit"


class TestMemoryUsage:
    """Test memory usage characteristics."""

    @pytest.mark.performance
    def test_memory_usage_per_analysis(
        self,
        load_fixture_file,
    ) -> None:
        """Test memory usage for single analysis."""
        process = psutil.Process(os.getpid())

        baseline_memory = process.memory_info().rss / 1024 / 1024  # MB

        code = load_fixture_file("multiple_vulnerabilities.java", "vulnerable")

        mock_spec = _make_mock_spec_result(
            sources=[{"variable_name": "username", "line_number": 10, "confidence": 0.9}],
            sinks=[{"variable_name": "query", "line_number": 12, "confidence": 0.85}],
        )

        config = PipelineConfig(llm_api_key="test-key", use_llm_graph_builder=False)
        result = _run_pipeline_on_code(code, config, mock_spec)

        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - baseline_memory

        print(f"\nMemory usage:")
        print(f"  Baseline: {baseline_memory:.2f}MB")
        print(f"  Final: {final_memory:.2f}MB")
        print(f"  Increase: {memory_increase:+.2f}MB (limit: {ACCEPTABLE_LIMITS['memory_increase']}MB)")

        assert abs(memory_increase) < ACCEPTABLE_LIMITS["memory_increase"], \
            f"Memory increase {memory_increase:.2f}MB exceeds limit"

    @pytest.mark.performance
    def test_memory_usage_multiple_analyses(
        self,
        vulnerable_files: List[Path],
    ) -> None:
        """Test memory usage for multiple sequential analyses."""
        process = psutil.Process(os.getpid())

        baseline_memory = process.memory_info().rss / 1024 / 1024  # MB

        mock_spec = _make_mock_spec_result()
        config = PipelineConfig(llm_api_key="test-key", use_llm_graph_builder=False)

        memory_readings = [baseline_memory]

        for file_path in vulnerable_files[:5]:
            pipeline = SimplePipeline(config)
            pipeline.spec_extractor = Mock()
            pipeline.spec_extractor.extract = AsyncMock(return_value=mock_spec)
            pipeline.explainer.generate_explanation = AsyncMock(return_value={
                "summary": "Test", "details": "Test",
            })

            result = asyncio.run(pipeline.run(str(file_path)))

            current_memory = process.memory_info().rss / 1024 / 1024
            memory_readings.append(current_memory)

        final_memory = memory_readings[-1]
        total_increase = final_memory - baseline_memory
        num_files = min(5, len(vulnerable_files))
        avg_increase_per_file = total_increase / max(num_files, 1)

        print(f"\nMemory usage (multiple analyses):")
        print(f"  Baseline: {baseline_memory:.2f}MB")
        print(f"  Final: {final_memory:.2f}MB")
        print(f"  Total increase: {total_increase:+.2f}MB")
        print(f"  Average per file: {avg_increase_per_file:+.2f}MB")

        assert total_increase < ACCEPTABLE_LIMITS["memory_increase"] * 2, \
            f"Total memory increase {total_increase:.2f}MB suggests memory leak"


class TestScalability:
    """Test scalability with different code sizes."""

    @pytest.mark.performance
    @pytest.mark.slow
    def test_scalability_with_code_size(self) -> None:
        """Test how performance scales with code size."""
        from src.stage2_path_discovery.simple_path_finder import SimpleBFSPathFinder
        import networkx as nx

        results = []

        for size in [10, 50, 100, 200]:
            graph = nx.DiGraph()
            for i in range(size):
                graph.add_node(f"var_{i}")
                if i > 0:
                    graph.add_edge(f"var_{i-1}", f"var_{i}")

            loc = CodeLocation(file_path="test.java", line_number=1)
            source = Source(
                location=loc,
                variable_name="var_0",
                type="User Input",
                confidence=0.9,
                code_snippet="",
            )
            sink = Sink(
                location=loc,
                variable_name=f"var_{size-1}",
                type="SQL",
                confidence=0.9,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            )

            finder = SimpleBFSPathFinder(graph)

            start = time.time()
            chains = finder.find_all_chains([source], [sink], max_length=size)
            duration = time.time() - start

            results.append({
                "size": size,
                "time": duration,
            })

        print(f"\nScalability test:")
        for r in results:
            print(f"  Size {r['size']:4d}: {r['time']:.3f}s")

        time_10 = results[0]["time"]
        time_200 = results[-1]["time"]

        if time_10 > 0:
            time_ratio = time_200 / time_10
            print(f"\n  Time ratio (200/10): {time_ratio:.1f}x")
            assert time_ratio < 100, "Performance degrades too quickly with scale"

    @pytest.mark.performance
    def test_scalability_with_vulnerability_count(
        self,
        load_fixture_file,
    ) -> None:
        """Test scalability with number of vulnerabilities."""
        code = load_fixture_file("multiple_vulnerabilities.java", "vulnerable")

        mock_spec = _make_mock_spec_result(
            sources=[
                {"variable_name": f"input{i}", "line_number": 10 + i, "confidence": 0.9}
                for i in range(3)
            ],
            sinks=[
                {"variable_name": f"sink{i}", "line_number": 20 + i, "confidence": 0.85}
                for i in range(3)
            ],
        )

        config = PipelineConfig(llm_api_key="test-key", use_llm_graph_builder=False)

        start = time.time()
        result = _run_pipeline_on_code(code, config, mock_spec)
        duration = time.time() - start

        print(f"\nMultiple vulnerabilities performance:")
        print(f"  Time: {duration:.2f}s")
        print(f"  Should scale reasonably with vulnerability count")

        assert duration < ACCEPTABLE_LIMITS["medium_file_time"], \
            f"Multiple vulnerabilities took {duration:.2f}s, too slow"


class TestVerificationOverhead:
    """Test overhead of different verification levels."""

    @pytest.mark.performance
    def test_no_verification_baseline(
        self,
        load_fixture_file,
    ) -> None:
        """Test performance without verification (baseline)."""
        code = load_fixture_file("sql_injection_basic.java", "vulnerable")

        mock_spec = _make_mock_spec_result(
            sources=[{"variable_name": "userId", "line_number": 9, "confidence": 0.9}],
            sinks=[{"variable_name": "query", "line_number": 10, "confidence": 0.85}],
        )

        config = PipelineConfig(
            llm_api_key="test-key",
            verification_enabled=False,
            use_llm_graph_builder=False,
        )

        start = time.time()
        result = _run_pipeline_on_code(code, config, mock_spec)
        baseline_time = time.time() - start

        print(f"\nNo verification (baseline): {baseline_time:.2f}s")

    @pytest.mark.performance
    def test_cfg_verification_overhead(
        self,
        load_fixture_file,
    ) -> None:
        """Test overhead of CFG verification."""
        code = load_fixture_file("sql_injection_basic.java", "vulnerable")

        mock_spec = _make_mock_spec_result(
            sources=[{"variable_name": "userId", "line_number": 9, "confidence": 0.9}],
            sinks=[{"variable_name": "query", "line_number": 10, "confidence": 0.85}],
        )

        config = PipelineConfig(
            llm_api_key="test-key",
            verification_enabled=True,
            verification_level="cfg",
            use_llm_graph_builder=False,
        )

        start = time.time()
        result = _run_pipeline_on_code(code, config, mock_spec)
        cfg_time = time.time() - start

        print(f"\nCFG verification: {cfg_time:.2f}s")
        print(f"  Overhead should be minimal")

        # Full pipeline includes model loading; use generous limit
        assert cfg_time < ACCEPTABLE_LIMITS["small_file_time"] * 2, \
            "CFG verification adds too much overhead"
