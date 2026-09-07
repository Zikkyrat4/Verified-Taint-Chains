"""Unit tests for confidence preservation after graph verification."""

import pytest

from src.core.models import (
    CodeLocation,
    Source,
    Sink,
    PathNode,
    TaintChain,
    SourceCategory,
    SinkCategory,
    VulnerabilityType,
)
from src.pipeline.orchestrator import SimplePipeline


def _make_chain(
    src_category: SourceCategory = SourceCategory.UNKNOWN,
    sink_category: SinkCategory = SinkCategory.UNKNOWN,
    confidence: float = 0.8,
    source_var: str = "userInput",
    sink_var: str = "query",
) -> TaintChain:
    """Helper to build a TaintChain with given categories and confidence."""
    loc = CodeLocation(file_path="Test.java", line_number=1)
    source = Source(
        location=loc,
        variable_name=source_var,
        type="user_input",
        confidence=confidence,
        code_snippet="",
        source_category=src_category,
    )
    sink = Sink(
        location=CodeLocation(file_path="Test.java", line_number=10),
        variable_name=sink_var,
        type="sql_query",
        confidence=confidence,
        code_snippet="",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        sink_category=sink_category,
    )
    path = [
        PathNode(
            location=loc,
            variable_name=source_var,
            node_type="source",
            code_snippet="",
        ),
        PathNode(
            location=CodeLocation(file_path="Test.java", line_number=10),
            variable_name=sink_var,
            node_type="sink",
            code_snippet="",
        ),
    ]
    return TaintChain(
        id="chain-1",
        source=source,
        sink=sink,
        path=path,
        length=2,
        confidence=confidence,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
    )


class TestAdjustChainConfidence:
    """Tests for SimplePipeline._adjust_chain_confidence()."""

    def test_user_input_to_direct_exec_no_penalty(self) -> None:
        """USER_INPUT -> DIRECT_EXECUTION should keep full confidence."""
        chain = _make_chain(SourceCategory.USER_INPUT, SinkCategory.DIRECT_EXECUTION, 0.8)
        result = SimplePipeline._adjust_chain_confidence([chain], 0.5)
        assert len(result) == 1
        assert result[0].confidence == pytest.approx(0.8)

    def test_user_input_to_output_rendering_no_penalty(self) -> None:
        """USER_INPUT -> OUTPUT_RENDERING should keep full confidence."""
        chain = _make_chain(SourceCategory.USER_INPUT, SinkCategory.OUTPUT_RENDERING, 0.9)
        result = SimplePipeline._adjust_chain_confidence([chain], 0.5)
        assert len(result) == 1
        assert result[0].confidence == pytest.approx(0.9)

    def test_session_data_to_framework_api_is_filtered(self) -> None:
        chain = _make_chain(SourceCategory.SESSION_DATA, SinkCategory.FRAMEWORK_API, 0.8)
        result = SimplePipeline._adjust_chain_confidence([chain], 0.5)
        assert result == []

    def test_internal_api_to_framework_api_is_filtered(self) -> None:
        chain = _make_chain(SourceCategory.INTERNAL_API, SinkCategory.FRAMEWORK_API, 0.8)
        result = SimplePipeline._adjust_chain_confidence([chain], 0.5)
        assert result == []

    def test_internal_api_to_data_storage_is_filtered(self) -> None:
        chain = _make_chain(SourceCategory.INTERNAL_API, SinkCategory.DATA_STORAGE, 0.8)
        result = SimplePipeline._adjust_chain_confidence([chain], 0.5)
        assert result == []

    def test_unknown_categories_keep_model_confidence(self) -> None:
        chain = _make_chain(SourceCategory.UNKNOWN, SinkCategory.UNKNOWN, 0.8)
        result = SimplePipeline._adjust_chain_confidence([chain], 0.5)
        assert len(result) == 1

    def test_unknown_source_keeps_model_selected_framework_api(self) -> None:
        chain = _make_chain(SourceCategory.UNKNOWN, SinkCategory.FRAMEWORK_API, 0.8)
        result = SimplePipeline._adjust_chain_confidence([chain], 0.5)
        assert len(result) == 1

    def test_user_input_to_framework_api_keeps_model_confidence(self) -> None:
        chain = _make_chain(SourceCategory.USER_INPUT, SinkCategory.FRAMEWORK_API, 0.9)
        result = SimplePipeline._adjust_chain_confidence([chain], 0.5)
        assert len(result) == 1

    def test_unknown_sink_keeps_model_confidence(self) -> None:
        chain = _make_chain(SourceCategory.INTERNAL_API, SinkCategory.UNKNOWN, 0.8)
        result = SimplePipeline._adjust_chain_confidence([chain], 0.5)
        assert len(result) == 1

    def test_none_categories_treated_as_unknown(self) -> None:
        chain = _make_chain(confidence=0.8)
        chain.source.source_category = None
        chain.sink.sink_category = None
        result = SimplePipeline._adjust_chain_confidence([chain], 0.5)
        assert len(result) == 1

    def test_external_data_to_direct_execution(self) -> None:
        """EXTERNAL_DATA -> DIRECT_EXECUTION keeps model confidence."""
        chain = _make_chain(SourceCategory.EXTERNAL_DATA, SinkCategory.DIRECT_EXECUTION, 0.8)
        result = SimplePipeline._adjust_chain_confidence([chain], 0.5)
        assert len(result) == 1
        assert result[0].confidence == pytest.approx(0.8)

    def test_database_to_output_rendering(self) -> None:
        """DATABASE -> OUTPUT_RENDERING keeps model confidence."""
        chain = _make_chain(SourceCategory.DATABASE, SinkCategory.OUTPUT_RENDERING, 0.8)
        result = SimplePipeline._adjust_chain_confidence([chain], 0.3)
        assert len(result) == 1
        assert result[0].confidence == pytest.approx(0.8)

    def test_multiple_chains_mixed_filtering(self) -> None:
        """Security-capable sinks survive regardless of source category."""
        chain_keep = _make_chain(
            SourceCategory.USER_INPUT, SinkCategory.DIRECT_EXECUTION, 0.8,
            source_var="param", sink_var="sqlQuery",
        )
        chain_filter = _make_chain(
            SourceCategory.INTERNAL_API, SinkCategory.FRAMEWORK_API, 0.8,
            source_var="realm", sink_var="setClient",
        )
        result = SimplePipeline._adjust_chain_confidence(
            [chain_keep, chain_filter], 0.5
        )
        assert len(result) == 1
        assert result[0].source.variable_name == "param"

    def test_event_logging_sink_is_filtered(self) -> None:
        chain = _make_chain(
            SourceCategory.USER_INPUT, SinkCategory.EVENT_LOGGING, 0.8
        )
        result = SimplePipeline._adjust_chain_confidence([chain], 0.5)
        assert result == []

    def test_empty_chains_list(self) -> None:
        """Empty input returns empty output."""
        result = SimplePipeline._adjust_chain_confidence([], 0.5)
        assert result == []
