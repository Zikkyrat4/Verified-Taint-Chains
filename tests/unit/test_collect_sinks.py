"""Tests for SimplePipeline.collect_sinks — Stage-1-only sink inventory."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.core.config import PipelineConfig
from src.core.models import Sink, CodeLocation, VulnerabilityType, SinkCategory
from src.pipeline.orchestrator import SimplePipeline


@pytest.fixture
def test_config():
    return PipelineConfig(
        llm_api_key="test-key",
        llm_model="gpt-4-turbo",
        min_confidence=0.5,
        use_llm_graph_builder=False,
    )


def _make_sink(file_path: str, line: int = 1) -> Sink:
    return Sink(
        location=CodeLocation(file_path=file_path, line_number=line),
        variable_name="x",
        type="exec",
        confidence=0.9,
        code_snippet="Runtime.getRuntime().exec(x)",
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        sink_category=SinkCategory.DIRECT_EXECUTION,
    )


@pytest.mark.asyncio
async def test_collect_sinks_gathers_all_files(tmp_path, test_config):
    """collect_sinks runs Stage 1 per file and returns every sink with its path."""
    pipeline = SimplePipeline(test_config)

    fa = tmp_path / "A.java"
    fa.write_text("class A { void m(){ Runtime.getRuntime().exec(x); } }")
    fb = tmp_path / "B.java"
    fb.write_text("class B { void n(){ stmt.executeQuery(y); } }")

    def fake_extract(source_code="", file_path="", model=""):
        spec = MagicMock()
        spec.sinks = [_make_sink(file_path)]
        return spec

    pipeline.spec_extractor.extract = AsyncMock(side_effect=fake_extract)

    result = await pipeline.collect_sinks([str(fa), str(fb)])

    assert result["files_analyzed"] == 2
    assert len(result["sinks"]) == 2
    # File path comes from the extraction loop (authoritative), not sink.location.
    paths = {fp for fp, _ in result["sinks"]}
    assert paths == {str(fa), str(fb)}


@pytest.mark.asyncio
async def test_collect_sinks_no_chain_pipeline(tmp_path, test_config):
    """Only Stage 1 runs — no graph/verification components are touched."""
    pipeline = SimplePipeline(test_config)
    fa = tmp_path / "A.java"
    fa.write_text("class A {}")

    spec = MagicMock()
    spec.sinks = []
    pipeline.spec_extractor.extract = AsyncMock(return_value=spec)

    result = await pipeline.collect_sinks([str(fa)])

    assert result["files_analyzed"] == 1
    assert result["sinks"] == []
    # Stage 2-3 components remain uninitialized (never built for sink inventory).
    assert pipeline.graph_builder is None
    assert pipeline.path_finder is None


@pytest.mark.asyncio
async def test_collect_sinks_invokes_on_file_done_per_file(tmp_path, test_config):
    """Callback fires once per file with that file's sinks — enables incremental saves."""
    pipeline = SimplePipeline(test_config)

    fa = tmp_path / "A.java"
    fa.write_text("class A {}")
    fb = tmp_path / "B.java"
    fb.write_text("class B {}")

    def fake_extract(source_code="", file_path="", model=""):
        spec = MagicMock()
        spec.sinks = [_make_sink(file_path)]
        return spec

    pipeline.spec_extractor.extract = AsyncMock(side_effect=fake_extract)

    callbacks = []

    def _on_done(file_path, sinks):
        callbacks.append((file_path, len(sinks)))

    await pipeline.collect_sinks([str(fa), str(fb)], on_file_done=_on_done)

    assert len(callbacks) == 2
    assert {fp for fp, _ in callbacks} == {str(fa), str(fb)}
    assert all(n == 1 for _, n in callbacks)


@pytest.mark.asyncio
async def test_collect_sinks_callback_error_does_not_abort(tmp_path, test_config):
    """A throwing callback is logged and swallowed — extraction must still complete."""
    pipeline = SimplePipeline(test_config)

    fa = tmp_path / "A.java"
    fa.write_text("class A {}")

    spec = MagicMock()
    spec.sinks = [_make_sink(str(fa))]
    pipeline.spec_extractor.extract = AsyncMock(return_value=spec)

    def _on_done(file_path, sinks):
        raise RuntimeError("disk full")

    result = await pipeline.collect_sinks([str(fa)], on_file_done=_on_done)

    assert result["files_analyzed"] == 1
    assert len(result["sinks"]) == 1


@pytest.mark.asyncio
async def test_collect_sinks_respects_max_files(tmp_path, test_config):
    """--max-files caps the number of files handed to Stage 1."""
    test_config.max_files = 1
    pipeline = SimplePipeline(test_config)

    fa = tmp_path / "A.java"
    fa.write_text("class A {}")
    fb = tmp_path / "B.java"
    fb.write_text("class B {}")

    spec = MagicMock()
    spec.sinks = []
    extract_mock = AsyncMock(return_value=spec)
    pipeline.spec_extractor.extract = extract_mock

    result = await pipeline.collect_sinks([str(fa), str(fb)])

    assert result["files_analyzed"] == 1
    assert extract_mock.await_count == 1
