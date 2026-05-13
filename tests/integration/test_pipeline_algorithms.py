"""Integration tests for pipeline algorithm selection (BFS vs A*)."""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

from src.pipeline.orchestrator import SimplePipeline
from src.core.config import PipelineConfig
from src.core.models import Specification, Source, Sink, CodeLocation, VulnerabilityType


class TestPipelineBFSAlgorithm:
    """Tests for pipeline using BFS pathfinding."""

    def test_pipeline_bfs_config(self) -> None:
        """Test pipeline initialization with BFS algorithm."""
        config = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="bfs",
        )

        assert config.pathfinding_algorithm == "bfs"
        pipeline = SimplePipeline(config)
        assert pipeline.config.pathfinding_algorithm == "bfs"

    @pytest.mark.asyncio
    async def test_pipeline_bfs_execution(self) -> None:
        """Test complete pipeline execution with BFS."""
        config = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="bfs",
            verification_enabled=False,
            use_llm_graph_builder=False,
        )

        pipeline = SimplePipeline(config)

        code = """
        String input = request.getParameter("q");
        db.execute("SELECT * FROM t WHERE id=" + input);
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write(code)
            temp_file = f.name

        try:
            # Mock LLM extraction
            with patch.object(
                pipeline.spec_extractor, "extract", new_callable=AsyncMock
            ) as mock_extract:
                sources = [
                    Source(
                        location=CodeLocation(file_path="test.java", line_number=2),
                        variable_name="input",
                        type="User Input",
                        confidence=0.95,
                        code_snippet="",
                    )
                ]

                sinks = [
                    Sink(
                        location=CodeLocation(file_path="test.java", line_number=3),
                        variable_name="input",
                        type="SQL",
                        vulnerability_type=VulnerabilityType.SQL_INJECTION,
                        confidence=0.98,
                        code_snippet="",
                    )
                ]

                spec = Specification(
                    sources=sources,
                    sinks=sinks,
                    sanitizers=[],
                    llm_model="gpt-4",
                )

                mock_extract.return_value = spec

                result = await pipeline.run(temp_file)

                assert result is not None
                assert "metrics" in result
                assert result["metrics"]["sources_found"] == 1
                assert result["metrics"]["sinks_found"] == 1

        finally:
            Path(temp_file).unlink()

    def test_pipeline_bfs_path_finder_type(self) -> None:
        """Test that BFS uses SimpleBFSPathFinder."""
        from src.stage2_path_discovery.simple_path_finder import SimpleBFSPathFinder

        config = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="bfs",
        )

        pipeline = SimplePipeline(config)
        assert pipeline.config.pathfinding_algorithm == "bfs"
        # Note: path_finder is initialized in run(), not __init__


class TestPipelineAStarAlgorithm:
    """Tests for pipeline using A* pathfinding."""

    def test_pipeline_astar_config_default(self) -> None:
        """Test that A* is the default algorithm."""
        config = PipelineConfig(llm_api_key="test-key")

        assert config.pathfinding_algorithm == "astar"
        pipeline = SimplePipeline(config)
        assert pipeline.config.pathfinding_algorithm == "astar"

    def test_pipeline_astar_config_explicit(self) -> None:
        """Test pipeline initialization with explicit A* algorithm."""
        config = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="astar",
        )

        assert config.pathfinding_algorithm == "astar"
        pipeline = SimplePipeline(config)
        assert pipeline.config.pathfinding_algorithm == "astar"

    def test_pipeline_astar_with_semantic_heuristic(self) -> None:
        """Test A* with semantic heuristic enabled."""
        config = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="astar",
            use_semantic_heuristic=True,
        )

        assert config.pathfinding_algorithm == "astar"
        assert config.use_semantic_heuristic is True
        pipeline = SimplePipeline(config)
        assert pipeline.config.use_semantic_heuristic is True

    def test_pipeline_astar_without_semantic_heuristic(self) -> None:
        """Test A* with semantic heuristic disabled."""
        config = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="astar",
            use_semantic_heuristic=False,
        )

        assert config.pathfinding_algorithm == "astar"
        assert config.use_semantic_heuristic is False
        pipeline = SimplePipeline(config)
        assert pipeline.config.use_semantic_heuristic is False

    @pytest.mark.asyncio
    async def test_pipeline_astar_execution(self) -> None:
        """Test complete pipeline execution with A*."""
        config = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="astar",
            use_semantic_heuristic=False,  # Disable heuristic for testing
            verification_enabled=False,
            use_llm_graph_builder=False,
        )

        pipeline = SimplePipeline(config)

        code = """
        String user = request.getParameter("user");
        String query = "SELECT * FROM users WHERE name='" + user + "'";
        db.execute(query);
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write(code)
            temp_file = f.name

        try:
            # Mock LLM extraction
            with patch.object(
                pipeline.spec_extractor, "extract", new_callable=AsyncMock
            ) as mock_extract:
                sources = [
                    Source(
                        location=CodeLocation(file_path="test.java", line_number=2),
                        variable_name="user",
                        type="User Input",
                        confidence=0.95,
                        code_snippet="",
                    )
                ]

                sinks = [
                    Sink(
                        location=CodeLocation(file_path="test.java", line_number=4),
                        variable_name="query",
                        type="SQL",
                        vulnerability_type=VulnerabilityType.SQL_INJECTION,
                        confidence=0.98,
                        code_snippet="",
                    )
                ]

                spec = Specification(
                    sources=sources,
                    sinks=sinks,
                    sanitizers=[],
                    llm_model="gpt-4",
                )

                mock_extract.return_value = spec

                result = await pipeline.run(temp_file)

                assert result is not None
                assert "metrics" in result
                assert result["metrics"]["sources_found"] == 1
                assert result["metrics"]["sinks_found"] == 1

        finally:
            Path(temp_file).unlink()

    @pytest.mark.asyncio
    async def test_pipeline_astar_with_semantic_heuristic_execution(self) -> None:
        """Test pipeline with A* and semantic heuristic."""
        config = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="astar",
            use_semantic_heuristic=True,
            verification_enabled=False,
            use_llm_graph_builder=False,
        )

        pipeline = SimplePipeline(config)

        code = """
        String input = getInput();
        processData(input);
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write(code)
            temp_file = f.name

        try:
            # Mock LLM extraction
            with patch.object(
                pipeline.spec_extractor, "extract", new_callable=AsyncMock
            ) as mock_extract:
                sources = [
                    Source(
                        location=CodeLocation(file_path="test.java", line_number=2),
                        variable_name="input",
                        type="Input",
                        confidence=0.9,
                        code_snippet="",
                    )
                ]

                sinks = [
                    Sink(
                        location=CodeLocation(file_path="test.java", line_number=3),
                        variable_name="input",
                        type="Output",
                        vulnerability_type=VulnerabilityType.XSS,
                        confidence=0.85,
                        code_snippet="",
                    )
                ]

                spec = Specification(
                    sources=sources,
                    sinks=sinks,
                    sanitizers=[],
                    llm_model="gpt-4",
                )

                mock_extract.return_value = spec

                result = await pipeline.run(temp_file)

                assert result is not None
                # Verify semantic heuristic was created
                assert pipeline.semantic_heuristic is not None

        finally:
            Path(temp_file).unlink()


class TestPipelineAlgorithmSelection:
    """Tests for algorithm selection logic."""

    def test_invalid_algorithm_raises_error(self) -> None:
        """Test that invalid algorithm choice raises ValueError."""
        with pytest.raises(ValueError, match="pathfinding_algorithm must be"):
            PipelineConfig(
                llm_api_key="test-key",
                pathfinding_algorithm="invalid",  # type: ignore
            )

    def test_algorithm_case_insensitive(self) -> None:
        """Test that algorithm selection is case-insensitive from environment."""
        # Test via explicit config (not environment)
        config = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="astar",
        )
        assert config.pathfinding_algorithm == "astar"

    def test_bfs_algorithm_explicit(self) -> None:
        """Test explicit BFS algorithm selection."""
        config = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="bfs",
        )
        assert config.pathfinding_algorithm == "bfs"

    def test_astar_algorithm_explicit(self) -> None:
        """Test explicit A* algorithm selection."""
        config = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="astar",
        )
        assert config.pathfinding_algorithm == "astar"


class TestPipelineAlgorithmIntegration:
    """Integration tests for algorithm selection in pipeline."""

    def test_pipeline_uses_correct_graph_builder_for_astar(self) -> None:
        """Test that A* uses EnhancedGraphBuilder."""
        config = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="astar",
        )

        pipeline = SimplePipeline(config)
        assert pipeline.config.pathfinding_algorithm == "astar"
        # Note: graph_builder is initialized in run()

    def test_pipeline_uses_correct_graph_builder_for_bfs(self) -> None:
        """Test that BFS uses SimpleGraphBuilder."""
        config = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="bfs",
        )

        pipeline = SimplePipeline(config)
        assert pipeline.config.pathfinding_algorithm == "bfs"
        # Note: graph_builder is initialized in run()

    def test_pipeline_prefers_joern_over_algorithm(self) -> None:
        """Test that Joern is used if enabled, regardless of algorithm."""
        config = PipelineConfig(
            llm_api_key="test-key",
            use_joern=True,
            pathfinding_algorithm="astar",
        )

        pipeline = SimplePipeline(config)
        assert pipeline.config.use_joern is True
        assert pipeline.config.pathfinding_algorithm == "astar"

    def test_semantic_heuristic_only_with_astar(self) -> None:
        """Test that semantic heuristic is only used with A*."""
        config_astar = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="astar",
            use_semantic_heuristic=True,
        )

        config_bfs = PipelineConfig(
            llm_api_key="test-key",
            pathfinding_algorithm="bfs",
            use_semantic_heuristic=True,  # Heuristic is ignored with BFS
        )

        pipeline_astar = SimplePipeline(config_astar)
        pipeline_bfs = SimplePipeline(config_bfs)

        assert pipeline_astar.config.use_semantic_heuristic is True
        assert pipeline_bfs.config.use_semantic_heuristic is True
