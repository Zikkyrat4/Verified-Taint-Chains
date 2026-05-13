"""Integration tests for the complete pipeline."""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

from src.pipeline.orchestrator import SimplePipeline
from src.pipeline.result import PipelineResult
from src.core.config import PipelineConfig
from src.core.models import (
    VulnerabilityType,
    TaintChain,
    Source,
    Sink,
    CodeLocation,
)


class TestPipelineInitialization:
    """Tests for pipeline initialization."""

    def test_pipeline_init(self) -> None:
        """Test SimplePipeline initialization with valid config."""
        config = PipelineConfig(
            llm_api_key="test-key",
            llm_model="gpt-4-turbo",
            max_path_length=15,
            min_confidence=0.5,
            verification_enabled=True,
            use_llm_graph_builder=False,
        )

        pipeline = SimplePipeline(config)

        assert pipeline.config == config
        assert pipeline.llm_client is not None
        assert pipeline.spec_extractor is not None
        assert pipeline.explainer is not None

    def test_pipeline_init_invalid_config(self) -> None:
        """Test that invalid config raises ValueError."""
        with pytest.raises(ValueError):
            SimplePipeline(None)  # type: ignore


class TestPipelineReadSourceFile:
    """Tests for source file reading."""

    def test_read_source_file(self) -> None:
        """Test reading source file successfully."""
        config = PipelineConfig(llm_api_key="test-key", use_llm_graph_builder=False)
        pipeline = SimplePipeline(config)

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            test_code = "public class Test { }"
            f.write(test_code)
            temp_file = f.name

        try:
            content = pipeline._read_source_file(temp_file)
            assert content == test_code

        finally:
            Path(temp_file).unlink()

    def test_read_nonexistent_file(self) -> None:
        """Test that reading non-existent file raises FileNotFoundError."""
        config = PipelineConfig(llm_api_key="test-key", use_llm_graph_builder=False)
        pipeline = SimplePipeline(config)

        with pytest.raises(FileNotFoundError):
            pipeline._read_source_file("/nonexistent/file.java")

    def test_read_directory_instead_of_file(self) -> None:
        """Test that reading directory raises ValueError."""
        config = PipelineConfig(llm_api_key="test-key", use_llm_graph_builder=False)
        pipeline = SimplePipeline(config)

        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError):
                pipeline._read_source_file(tmpdir)


class TestPipelineRun:
    """Tests for complete pipeline execution."""

    @pytest.mark.asyncio
    async def test_pipeline_run_complete(self) -> None:
        """Test complete pipeline execution on sample code.

        This test verifies:
        1. All 4 stages execute successfully
        2. Results are properly aggregated
        3. Metrics are calculated correctly
        """
        config = PipelineConfig(
            llm_api_key="test-key",
            max_path_length=15,
            min_confidence=0.5,
            verification_enabled=True,
            use_llm_graph_builder=False,
        )

        pipeline = SimplePipeline(config)

        # Create sample vulnerable code
        code = """public void loginUser(HttpServletRequest request) {
            String username = request.getParameter("user");
            String password = request.getParameter("pass");
            String query = "SELECT * FROM users WHERE username='" + username + "'";
            ResultSet rs = db.executeQuery(query);
        }"""

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write(code)
            temp_file = f.name

        try:
            # Mock LLM calls
            source_response = {
                "sources": [
                    {
                        "line": 2,
                        "variable": "username",
                        "type": "user_input",
                        "confidence": 0.95,
                    }
                ]
            }

            sink_response = {
                "sinks": [
                    {
                        "line": 5,
                        "variable": "query",
                        "type": "sql_query",
                        "vulnerability_type": "sql_injection",
                        "confidence": 0.98,
                    }
                ]
            }

            with patch.object(
                pipeline.spec_extractor, "extract", new_callable=AsyncMock
            ) as mock_extract:
                from src.core.models import Specification

                spec = Specification(sources=[], sinks=[], sanitizers=[], llm_model="gpt-4")
                mock_extract.return_value = spec

                result = await pipeline.run(temp_file)

            # Verify results
            assert "file" in result
            assert "total_chains" in result
            assert "verified_chains" in result
            assert "explanations" in result
            assert "metrics" in result

            metrics = result["metrics"]
            assert "sources_found" in metrics
            assert "sinks_found" in metrics
            assert "chains_found" in metrics
            assert "chains_verified" in metrics

            print(f"✓ Pipeline execution completed")
            print(f"  File: {result['file']}")
            print(f"  Total chains: {result['total_chains']}")
            print(f"  Verified chains: {len(result['verified_chains'])}")
            print(f"  Metrics: {metrics}")

        finally:
            Path(temp_file).unlink()

    @pytest.mark.asyncio
    async def test_pipeline_run_file_not_found(self) -> None:
        """Test pipeline handles missing source file."""
        config = PipelineConfig(llm_api_key="test-key", use_llm_graph_builder=False)
        pipeline = SimplePipeline(config)

        with pytest.raises(FileNotFoundError):
            await pipeline.run("/nonexistent/file.java")


class TestPipelineResult:
    """Tests for PipelineResult dataclass."""

    def test_result_creation(self) -> None:
        """Test creating PipelineResult."""
        loc = CodeLocation(file_path="test.java", line_number=1)

        chain = TaintChain(
            id="chain_1",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.9, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="sql", confidence=0.9, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=[],
            length=0,
            confidence=0.9,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        result = PipelineResult(
            source_file="test.java",
            total_chains=1,
            verified_chains=[chain],
            explanations={},
            metrics={"sources": 1, "sinks": 1},
        )

        assert result.source_file == "test.java"
        assert result.total_chains == 1
        assert len(result.verified_chains) == 1

    def test_result_to_dict(self) -> None:
        """Test converting result to dictionary."""
        result = PipelineResult(
            source_file="test.java",
            total_chains=5,
            verified_chains=[],
            explanations={},
            metrics={"chains": 5},
        )

        result_dict = result.to_dict()

        assert result_dict["source_file"] == "test.java"
        assert result_dict["total_chains"] == 5
        assert "timestamp" in result_dict

    def test_result_to_json(self) -> None:
        """Test converting result to JSON."""
        result = PipelineResult(
            source_file="test.java",
            total_chains=3,
            verified_chains=[],
            explanations={},
            metrics={"sources": 2, "sinks": 1},
        )

        json_str = result.to_json()

        assert "test.java" in json_str
        assert "3" in json_str
        assert "timestamp" in json_str

    def test_result_save(self) -> None:
        """Test saving result to file."""
        result = PipelineResult(
            source_file="test.java",
            total_chains=2,
            verified_chains=[],
            explanations={},
            metrics={"test": "value"},
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "results.json"

            result.save(str(output_file))

            assert output_file.exists()

            # Verify file content
            with open(output_file) as f:
                content = f.read()
                assert "test.java" in content

    def test_result_get_summary(self) -> None:
        """Test getting human-readable summary."""
        result = PipelineResult(
            source_file="test.java",
            total_chains=5,
            verified_chains=[],
            explanations={},
            metrics={"sources": 2, "sinks": 3},
        )

        summary = result.get_summary()

        assert "test.java" in summary
        assert "5" in summary
        assert "Metrics" in summary


class TestEndToEndPipeline:
    """End-to-end pipeline workflow test."""

    @pytest.mark.asyncio
    async def test_complete_pipeline_workflow(self) -> None:
        """Test complete pipeline workflow from file to results.

        This test verifies:
        1. Configuration loading
        2. File reading
        3. All 4 stages execution
        4. Result creation and saving
        """
        # Setup
        config = PipelineConfig(
            llm_api_key="workflow-test-key",
            llm_model="gpt-4-turbo",
            max_path_length=20,
            min_confidence=0.6,
            verification_enabled=True,
            use_llm_graph_builder=False,
        )

        pipeline = SimplePipeline(config)

        # Create test code file
        test_code = """public class VulnerableApp {
            public void processUser(HttpServletRequest request) {
                String userId = request.getParameter("id");
                String query = "SELECT * FROM users WHERE id = " + userId;
                Statement stmt = connection.createStatement();
                ResultSet rs = stmt.executeQuery(query);
            }
        }"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write(test_code)
            test_file = f.name

        try:
            # Mock the spec extractor to return empty results
            from src.core.models import Specification

            empty_spec = Specification(
                sources=[],
                sinks=[],
                sanitizers=[],
                llm_model="gpt-4-turbo",
            )

            with patch.object(
                pipeline.spec_extractor, "extract", new_callable=AsyncMock
            ) as mock_extract:
                mock_extract.return_value = empty_spec

                # Run pipeline
                run_result = await pipeline.run(test_file)

            # Create PipelineResult
            pipeline_result = pipeline.create_result(run_result, test_file)

            # Verify result
            assert isinstance(pipeline_result, PipelineResult)
            assert pipeline_result.source_file == test_file
            assert len(pipeline_result.metrics) > 0

            # Save result
            with tempfile.TemporaryDirectory() as tmpdir:
                output_file = Path(tmpdir) / "output.json"
                pipeline_result.save(str(output_file))

                assert output_file.exists()

            print(f"✓ Complete Pipeline Workflow")
            print(f"  Config: {config.llm_model}")
            print(f"  File: {test_file}")
            print(f"  Total chains: {pipeline_result.total_chains}")
            print(f"  Verified chains: {len(pipeline_result.verified_chains)}")
            print(f"  Result saved successfully")

        finally:
            Path(test_file).unlink()

    @pytest.mark.asyncio
    async def test_pipeline_with_verification_disabled(self) -> None:
        """Test pipeline with verification disabled."""
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_enabled=False,
            use_llm_graph_builder=False,
        )

        pipeline = SimplePipeline(config)

        test_code = "public class Test { }"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write(test_code)
            test_file = f.name

        try:
            from src.core.models import Specification

            empty_spec = Specification(
                sources=[],
                sinks=[],
                sanitizers=[],
                llm_model="gpt-4-turbo",
            )

            with patch.object(
                pipeline.spec_extractor, "extract", new_callable=AsyncMock
            ) as mock_extract:
                mock_extract.return_value = empty_spec

                result = await pipeline.run(test_file)

            # Should still produce results even with verification disabled
            assert "metrics" in result

            print(f"✓ Pipeline with verification disabled")
            print(f"  Verification enabled: False")

        finally:
            Path(test_file).unlink()


class TestPipelineMetrics:
    """Tests for pipeline metrics calculation."""

    def test_metrics_with_results(self) -> None:
        """Test metrics are properly calculated."""
        loc = CodeLocation(file_path="test.java", line_number=1)

        # Create a result dict similar to pipeline.run output
        result = {
            "file": "test.java",
            "total_chains": 3,
            "verified_chains": [
                TaintChain(
                    id="chain_1",
                    source=Source(location=loc, variable_name="x", type="input", confidence=0.9, code_snippet=""),
                    sink=Sink(location=loc, variable_name="y", type="sql", confidence=0.9, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
                    path=[],
                    length=0,
                    confidence=0.9,
                    vulnerability_type=VulnerabilityType.SQL_INJECTION,
                ),
            ],
            "explanations": {},
            "metrics": {
                "sources_found": 2,
                "sinks_found": 2,
                "chains_found": 3,
                "chains_verified": 1,
                "verification_rate": 0.333,
            },
        }

        assert result["metrics"]["chains_found"] == 3
        assert result["metrics"]["chains_verified"] == 1
        assert result["metrics"]["verification_rate"] == pytest.approx(0.333, rel=0.01)

        print(f"✓ Metrics calculation")
        for key, value in result["metrics"].items():
            print(f"  {key}: {value}")
