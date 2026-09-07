"""Tests for pipeline orchestrator."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from pathlib import Path

from src.core.config import PipelineConfig
from src.core.exceptions import TaintAnalysisError
from src.core.models import (
    Source, Sink, TaintChain, PathNode, CodeLocation,
    VulnerabilityType, VerificationStatus,
)
from src.pipeline.orchestrator import SimplePipeline
from src.pipeline.result import PipelineResult


@pytest.fixture
def test_config():
    return PipelineConfig(
        llm_api_key="test-key",
        llm_model="gpt-4-turbo",
        max_path_length=15,
        min_confidence=0.5,
        verification_enabled=True,
        verification_level="cfg",
        symbolic_execution_enabled=False,
        use_llm_graph_builder=False,
    )


@pytest.fixture
def sample_java_file(tmp_path):
    code = """
public class Test {
    public void process(String userId) {
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = conn.createStatement();
        stmt.executeQuery(query);
    }
}
"""
    file_path = tmp_path / "Test.java"
    file_path.write_text(code)
    return str(file_path)


class TestSimplePipeline:
    """Tests for SimplePipeline."""

    def test_init(self, test_config):
        pipeline = SimplePipeline(test_config)
        assert pipeline.config == test_config
        assert pipeline.llm_client is not None
        assert pipeline.spec_extractor is not None
        assert pipeline.explainer is not None

    @patch("src.pipeline.orchestrator.create_llm_client")
    def test_static_backend_does_not_create_llm_client(self, mock_create_llm):
        config = PipelineConfig(
            llm_api_key=None,
            analysis_backend="static",
            use_llm_graph_builder=False,
        )

        pipeline = SimplePipeline(config)

        mock_create_llm.assert_not_called()
        assert pipeline.llm_client is None
        assert pipeline.spec_extractor.analysis_backend == "static"

    def test_init_no_config(self):
        with pytest.raises(ValueError, match="config is required"):
            SimplePipeline(None)

    def test_read_source_file(self, test_config, sample_java_file):
        pipeline = SimplePipeline(test_config)
        content = pipeline._read_source_file(sample_java_file)
        assert "public class Test" in content

    def test_read_source_file_not_found(self, test_config):
        pipeline = SimplePipeline(test_config)
        with pytest.raises(FileNotFoundError):
            pipeline._read_source_file("/nonexistent/file.java")

    def test_read_source_file_not_a_file(self, test_config, tmp_path):
        pipeline = SimplePipeline(test_config)
        with pytest.raises(ValueError, match="not a file"):
            pipeline._read_source_file(str(tmp_path))

    def test_create_result(self, test_config, sample_java_file):
        pipeline = SimplePipeline(test_config)
        run_output = {
            "file": sample_java_file,
            "total_chains": 2,
            "verified_chains": [],
            "explanations": {},
            "metrics": {
                "sources_found": 1,
                "sinks_found": 1,
                "chains_found": 2,
                "chains_verified": 0,
                "verification_rate": 0.0,
                "explanations_generated": 0,
                "graph_nodes": 5,
                "graph_edges": 4,
            },
        }
        result = pipeline.create_result(run_output, sample_java_file)
        assert isinstance(result, PipelineResult)
        assert result.total_chains == 2

    @pytest.mark.asyncio
    async def test_run_file_not_found(self, test_config):
        pipeline = SimplePipeline(test_config)
        with pytest.raises(FileNotFoundError):
            await pipeline.run("/nonexistent.java")

    @pytest.mark.asyncio
    @patch("src.pipeline.orchestrator.SimpleSpecificationExtractor")
    @patch("src.pipeline.orchestrator.create_llm_client")
    async def test_run_basic(self, mock_create_llm, mock_spec_cls, test_config, sample_java_file):
        # Setup mocks
        mock_llm = MagicMock()
        mock_create_llm.return_value = mock_llm

        source = Source(
            location=CodeLocation(file_path=sample_java_file, line_number=3),
            variable_name="userId",
            type="User Input",
            confidence=0.9,
            code_snippet='String userId = request.getParameter("id");',
        )
        sink = Sink(
            location=CodeLocation(file_path=sample_java_file, line_number=4),
            variable_name="query",
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.85,
            code_snippet='stmt.executeQuery(query);',
        )

        mock_spec = MagicMock()
        mock_spec.sources = [source]
        mock_spec.sinks = [sink]

        mock_extractor = MagicMock()
        mock_extractor.extract = AsyncMock(return_value=mock_spec)
        mock_spec_cls.return_value = mock_extractor

        pipeline = SimplePipeline(test_config)
        pipeline.spec_extractor = mock_extractor

        result = await pipeline.run(sample_java_file)

        assert "file" in result
        assert "metrics" in result
        assert "verified_chains" in result
        assert result["metrics"]["sources_found"] == 1
        assert result["metrics"]["sinks_found"] == 1


class TestIsSecurityRelevant:
    """Tests for _is_security_relevant static method."""

    def test_sql_pattern(self):
        code = 'stmt.executeQuery("SELECT * FROM users WHERE id=" + id);'
        assert SimplePipeline._is_security_relevant(code) is True

    def test_http_input_pattern(self):
        code = 'String name = request.getParameter("name");'
        assert SimplePipeline._is_security_relevant(code) is True

    def test_spring_annotation(self):
        code = 'public void handle(@RequestParam String id) {}'
        assert SimplePipeline._is_security_relevant(code) is True

    def test_command_injection_pattern(self):
        code = 'Runtime.getRuntime().exec(cmd);'
        assert SimplePipeline._is_security_relevant(code) is True

    def test_file_traversal_pattern(self):
        code = 'File f = new File(userInput);'
        assert SimplePipeline._is_security_relevant(code) is True

    def test_deserialization_pattern(self):
        code = 'ObjectInputStream ois = new ObjectInputStream(in); ois.readObject();'
        assert SimplePipeline._is_security_relevant(code) is True

    def test_xxe_pattern(self):
        code = 'DocumentBuilder db = dbf.newDocumentBuilder();'
        assert SimplePipeline._is_security_relevant(code) is True

    def test_ssrf_pattern(self):
        code = 'URL url = new URL(userUrl); url.openConnection();'
        assert SimplePipeline._is_security_relevant(code) is True

    def test_getters_setters_only(self):
        code = """
public class UserDTO {
    private String name;
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}
"""
        assert SimplePipeline._is_security_relevant(code) is False

    def test_empty_file(self):
        assert SimplePipeline._is_security_relevant("") is False

    def test_whitespace_only(self):
        assert SimplePipeline._is_security_relevant("   \n\t  ") is False

    def test_plain_model_class(self):
        code = """
public class Config {
    private int timeout = 30;
    private String host = "localhost";
    public int getTimeout() { return timeout; }
}
"""
        assert SimplePipeline._is_security_relevant(code) is False

    def test_ldap_pattern(self):
        code = 'DirContext ctx = new InitialDirContext(env);'
        assert SimplePipeline._is_security_relevant(code) is True


class TestPartitionFiles:
    """Tests for _partition_files."""

    def test_partitions_correctly(self, test_config, tmp_path):
        relevant_file = tmp_path / "Controller.java"
        relevant_file.write_text('String q = request.getParameter("q");')

        irrelevant_file = tmp_path / "Model.java"
        irrelevant_file.write_text("public class Model { private int id; }")

        pipeline = SimplePipeline(test_config)
        relevant, irrelevant = pipeline._partition_files(
            [str(relevant_file), str(irrelevant_file)]
        )

        assert len(relevant) == 1
        assert len(irrelevant) == 1
        assert relevant[0][0] == str(relevant_file)
        assert irrelevant[0][0] == str(irrelevant_file)

    def test_all_relevant(self, test_config, tmp_path):
        f1 = tmp_path / "A.java"
        f2 = tmp_path / "B.java"
        f1.write_text("stmt.executeQuery(q);")
        f2.write_text('request.getParameter("x");')

        pipeline = SimplePipeline(test_config)
        relevant, irrelevant = pipeline._partition_files([str(f1), str(f2)])

        assert len(relevant) == 2
        assert len(irrelevant) == 0

    def test_all_irrelevant(self, test_config, tmp_path):
        f1 = tmp_path / "A.java"
        f2 = tmp_path / "B.java"
        f1.write_text("class A { int x = 1; }")
        f2.write_text("class B { String name; }")

        pipeline = SimplePipeline(test_config)
        relevant, irrelevant = pipeline._partition_files([str(f1), str(f2)])

        assert len(relevant) == 0
        assert len(irrelevant) == 2


class TestRunProject:
    """Tests for run_project (unified cross-file analysis)."""

    @pytest.mark.asyncio
    async def test_run_project_analyzes_all_files_by_default(
        self, test_config, tmp_path, monkeypatch
    ):
        """Default: every file is analyzed (priority, NOT exclusion).

        Keyword-filtering files away blinds the detector to 0-day patterns
        that use unfamiliar APIs, so both the security-matching and the
        non-matching file must reach the extractor.
        """
        monkeypatch.delenv("VTC_FAST_PREFILTER", raising=False)
        relevant = tmp_path / "Controller.java"
        irrelevant = tmp_path / "Model.java"
        relevant.write_text('String q = request.getParameter("q"); stmt.executeQuery(q);')
        irrelevant.write_text("public class Model { private int id; }")

        mock_spec = MagicMock()
        mock_spec.sources = []
        mock_spec.sinks = []
        mock_spec.sanitizers = []

        mock_extractor = MagicMock()
        mock_extractor.extract = AsyncMock(return_value=mock_spec)

        pipeline = SimplePipeline(test_config)
        pipeline.spec_extractor = mock_extractor

        result = await pipeline.run_project([str(relevant), str(irrelevant)])

        assert mock_extractor.extract.call_count == 2
        assert result["files_llm_extracted"] == 2
        assert result["files_skipped"] == 0
        assert result["files_analyzed"] == 2

    @pytest.mark.asyncio
    async def test_run_project_fast_prefilter_excludes_irrelevant(
        self, test_config, tmp_path, monkeypatch
    ):
        """VTC_FAST_PREFILTER=true restores the old exclude-irrelevant path."""
        monkeypatch.setenv("VTC_FAST_PREFILTER", "true")
        relevant = tmp_path / "Controller.java"
        irrelevant = tmp_path / "Model.java"
        relevant.write_text('String q = request.getParameter("q"); stmt.executeQuery(q);')
        irrelevant.write_text("public class Model { private int id; }")

        mock_spec = MagicMock()
        mock_spec.sources = []
        mock_spec.sinks = []
        mock_spec.sanitizers = []

        mock_extractor = MagicMock()
        mock_extractor.extract = AsyncMock(return_value=mock_spec)

        pipeline = SimplePipeline(test_config)
        pipeline.spec_extractor = mock_extractor

        result = await pipeline.run_project([str(relevant), str(irrelevant)])

        assert mock_extractor.extract.call_count == 1
        assert result["files_llm_extracted"] == 1
        assert result["files_skipped"] == 1
        assert result["files_analyzed"] == 2

    @pytest.mark.asyncio
    async def test_run_project_calls_per_file_extraction(self, test_config, tmp_path):
        """Verify spec_extractor.extract is called once per relevant file."""
        file_a = tmp_path / "A.java"
        file_b = tmp_path / "B.java"
        file_a.write_text("class A { String x = request.getParameter('q'); }")
        file_b.write_text("class B { db.execute(x); }")

        mock_spec = MagicMock()
        mock_spec.sources = []
        mock_spec.sinks = []
        mock_spec.sanitizers = []

        mock_extractor = MagicMock()
        mock_extractor.extract = AsyncMock(return_value=mock_spec)

        pipeline = SimplePipeline(test_config)
        pipeline.spec_extractor = mock_extractor

        await pipeline.run_project([str(file_a), str(file_b)])

        # Both files contain security patterns
        assert mock_extractor.extract.call_count == 2

    @pytest.mark.asyncio
    async def test_run_project_returns_unified_result(self, test_config, tmp_path):
        """Verify result structure contains project-mode fields."""
        file_a = tmp_path / "A.java"
        file_b = tmp_path / "B.java"
        file_a.write_text("class A { String x = request.getParameter('q'); }")
        file_b.write_text("class B { db.execute(x); }")

        source = Source(
            location=CodeLocation(file_path=str(file_a), line_number=1),
            variable_name="userInput",
            type="User Input",
            confidence=0.9,
            code_snippet="",
        )
        sink = Sink(
            location=CodeLocation(file_path=str(file_b), line_number=1),
            variable_name="query",
            type="SQL",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence=0.85,
            code_snippet="",
        )

        mock_spec_a = MagicMock()
        mock_spec_a.sources = [source]
        mock_spec_a.sinks = []
        mock_spec_a.sanitizers = []

        mock_spec_b = MagicMock()
        mock_spec_b.sources = []
        mock_spec_b.sinks = [sink]
        mock_spec_b.sanitizers = []

        mock_extractor = MagicMock()
        mock_extractor.extract = AsyncMock(side_effect=[mock_spec_a, mock_spec_b])

        pipeline = SimplePipeline(test_config)
        pipeline.spec_extractor = mock_extractor

        result = await pipeline.run_project([str(file_a), str(file_b)])

        assert result["files_analyzed"] == 2
        assert result["file_list"] == [str(file_a), str(file_b)]
        assert "project" in result["file"]
        assert "metrics" in result
        assert result["metrics"]["sources_found"] == 1
        assert result["metrics"]["sinks_found"] == 1

    @pytest.mark.asyncio
    async def test_run_project_max_files_cap(self, test_config, tmp_path):
        """Verify --max-files caps the number of files processed."""
        files = []
        for i in range(10):
            f = tmp_path / f"File{i}.java"
            f.write_text(f'class File{i} {{ request.getParameter("x"); }}')
            files.append(str(f))

        mock_spec = MagicMock()
        mock_spec.sources = []
        mock_spec.sinks = []
        mock_spec.sanitizers = []

        mock_extractor = MagicMock()
        mock_extractor.extract = AsyncMock(return_value=mock_spec)

        test_config.max_files = 3
        pipeline = SimplePipeline(test_config)
        pipeline.spec_extractor = mock_extractor

        result = await pipeline.run_project(files)

        # Only 3 files should be analyzed
        assert result["files_analyzed"] == 3

    @pytest.mark.asyncio
    async def test_run_project_fires_stage1_callback_before_stage2(
        self, test_config, tmp_path
    ):
        """on_stage1_complete fires after Stage 1 extracts, before Stages 2-4.

        Critical for incremental save: if Stage 2-4 crashes, the snapshot has
        the full extracted inventory on disk.
        """
        file_a = tmp_path / "A.java"
        file_a.write_text('String x = request.getParameter("q"); stmt.execute(x);')

        mock_spec = MagicMock()
        mock_spec.sources = []
        mock_spec.sinks = []
        mock_spec.sanitizers = []

        mock_extractor = MagicMock()
        mock_extractor.extract = AsyncMock(return_value=mock_spec)

        pipeline = SimplePipeline(test_config)
        pipeline.spec_extractor = mock_extractor

        captured = []

        def _on_stage1(snap):
            captured.append(snap)

        await pipeline.run_project([str(file_a)], on_stage1_complete=_on_stage1)

        assert len(captured) == 1
        snap = captured[0]
        assert snap["files_analyzed"] == 1
        assert snap["file_list"] == [str(file_a)]
        assert "sources" in snap and "sinks" in snap and "sanitizers" in snap

    @pytest.mark.asyncio
    async def test_run_project_stage1_callback_error_does_not_abort(
        self, test_config, tmp_path
    ):
        """A throwing Stage 1 callback is swallowed — Stages 2-4 still run."""
        file_a = tmp_path / "A.java"
        file_a.write_text('String x = request.getParameter("q"); stmt.execute(x);')

        mock_spec = MagicMock()
        mock_spec.sources = []
        mock_spec.sinks = []
        mock_spec.sanitizers = []

        mock_extractor = MagicMock()
        mock_extractor.extract = AsyncMock(return_value=mock_spec)

        pipeline = SimplePipeline(test_config)
        pipeline.spec_extractor = mock_extractor

        def _boom(snap):
            raise RuntimeError("disk full")

        # Should NOT raise — error is logged and swallowed.
        result = await pipeline.run_project(
            [str(file_a)], on_stage1_complete=_boom
        )
        assert result["files_analyzed"] == 1


# ============================================================================
# Quality filter — generic LLM-hallucination guard
# ============================================================================


def _chain_with_snippets(
    src_var: str, src_snip: str, sink_var: str, sink_snip: str,
    src_line: int = 10, sink_line: int = 20,
    src_function: str | None = None, sink_function: str | None = None,
) -> TaintChain:
    """Helper: build a minimal TaintChain with explicit code_snippets."""
    src_loc = CodeLocation(
        file_path="X.java", line_number=src_line, function_name=src_function
    )
    sink_loc = CodeLocation(
        file_path="X.java", line_number=sink_line, function_name=sink_function
    )
    source = Source(
        location=src_loc, variable_name=src_var, type="user_input",
        confidence=0.8, code_snippet=src_snip,
    )
    sink = Sink(
        location=sink_loc, variable_name=sink_var, type="sql",
        confidence=0.8, code_snippet=sink_snip,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
    )
    return TaintChain(
        id=f"{src_var}_to_{sink_var}",
        source=source, sink=sink,
        path=[
            PathNode(location=src_loc, variable_name=src_var,
                     node_type="source", code_snippet=src_snip),
            PathNode(location=sink_loc, variable_name=sink_var,
                     node_type="sink", code_snippet=sink_snip),
        ],
        length=2, confidence=0.8,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
    )


class TestFilterLowQualityChains:
    """`_filter_low_quality_chains` is the generic LLM-hallucination guard.

    A chain is dropped only when **both** sides have non-empty snippets that
    fail to mention their own variable name — the strongest signal that the
    LLM reported wrong line numbers and the snapshots are unrelated to the
    reported flow.
    """

    def test_both_snippets_match_kept(self) -> None:
        chain = _chain_with_snippets(
            "userInput", "String userInput = req.getParameter(\"x\");",
            "query", "stmt.execute(query);",
        )
        assert SimplePipeline._filter_low_quality_chains([chain]) == [chain]

    def test_only_source_mismatch_kept(self) -> None:
        # Source snippet missing the var (e.g. function-signature line),
        # but sink snippet OK — keep, since this is the common "declared
        # in signature, used below" pattern.
        chain = _chain_with_snippets(
            "userInput", "public void handle(HttpServletRequest req) {",
            "query", "stmt.execute(query);",
        )
        assert SimplePipeline._filter_low_quality_chains([chain]) == [chain]

    def test_only_sink_mismatch_kept(self) -> None:
        chain = _chain_with_snippets(
            "userInput", "String userInput = req.getParameter(\"x\");",
            "query", "}",
        )
        assert SimplePipeline._filter_low_quality_chains([chain]) == [chain]

    def test_both_mismatch_dropped(self) -> None:
        # Hallucinated chain — both snippets unrelated to declared variables.
        chain = _chain_with_snippets(
            "samlRequest", "SAML2Object samlObject = holder.getSamlObject();",
            "issuerNameId", "event.detail(Details.REASON, ...);",
        )
        assert SimplePipeline._filter_low_quality_chains([chain]) == []

    def test_empty_snippets_kept(self) -> None:
        # No info → don't penalise; fallback layers (category/dedup) handle it.
        chain = _chain_with_snippets("a", "", "b", "")
        assert SimplePipeline._filter_low_quality_chains([chain]) == [chain]

    def test_short_variable_names_skipped(self) -> None:
        # 1-char names are too noisy to use as a substring check — keep.
        chain = _chain_with_snippets(
            "x", "doThing();",
            "y", "doOther();",
        )
        assert SimplePipeline._filter_low_quality_chains([chain]) == [chain]

    def test_mixed_batch(self) -> None:
        good = _chain_with_snippets(
            "userInput", "String userInput = req.getParameter(\"x\");",
            "query", "stmt.execute(query);",
        )
        hallucinated = _chain_with_snippets(
            "samlRequest", "// unrelated",
            "issuerNameId", "}",
        )
        result = SimplePipeline._filter_low_quality_chains([good, hallucinated])
        assert result == [good]

    def test_empty_input(self) -> None:
        assert SimplePipeline._filter_low_quality_chains([]) == []


class TestFilterCrossFunctionChains:
    def test_same_file_different_functions_is_dropped(self) -> None:
        chain = _chain_with_snippets(
            "username", "String username = request.getParameter(\"u\");",
            "path", "File path = new File(root, username);",
            src_function="unrelatedEndpoint", sink_function="readFile",
        )

        assert SimplePipeline._filter_cross_function_chains([chain]) == []

    def test_same_function_is_kept(self) -> None:
        chain = _chain_with_snippets(
            "input", "String input = request.getParameter(\"q\");",
            "query", "stmt.execute(query);",
            src_function="search", sink_function="search",
        )

        assert SimplePipeline._filter_cross_function_chains([chain]) == [chain]

    def test_class_field_bridge_is_kept(self) -> None:
        import networkx as nx

        chain = _chain_with_snippets(
            "title", "void setTitle(String title)",
            "m_title", "out.print(m_title);",
            src_function="setTitle", sink_function="render",
        )
        graph = nx.DiGraph()
        graph.add_node("title")
        graph.add_node("m_title", is_field=True)

        assert SimplePipeline._filter_cross_function_chains(
            [chain], graph
        ) == [chain]
