"""Unit tests for specification extractor."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.stage1_llm_inference.specification_extractor import SimpleSpecificationExtractor
from src.stage1_llm_inference.llm_client import SimpleLLMClient
from src.core.exceptions import ParsingError, LLMError
from src.core.models import CodeLocation, SinkCategory, Source, VulnerabilityType


class TestSimpleSpecificationExtractorInit:
    """Tests for SimpleSpecificationExtractor initialization."""

    def test_init_with_valid_client(self) -> None:
        """Test initialization with valid LLM client."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)
        assert extractor.llm_client == client
        assert extractor.confidence_threshold == 0.5

    def test_init_with_custom_threshold(self) -> None:
        """Test initialization with custom confidence threshold."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client, confidence_threshold=0.8)
        assert extractor.confidence_threshold == 0.8

    def test_init_with_invalid_threshold_too_high(self) -> None:
        """Test that threshold > 1.0 raises ValueError."""
        client = SimpleLLMClient(api_key="test-key")
        with pytest.raises(ValueError, match="confidence_threshold must be between"):
            SimpleSpecificationExtractor(client, confidence_threshold=1.5)

    def test_init_with_invalid_threshold_negative(self) -> None:
        """Test that negative threshold raises ValueError."""
        client = SimpleLLMClient(api_key="test-key")
        with pytest.raises(ValueError, match="confidence_threshold must be between"):
            SimpleSpecificationExtractor(client, confidence_threshold=-0.1)


class TestExtractMethod:
    """Tests for the extract method."""

    @pytest.mark.asyncio
    async def test_extract_empty_code(self) -> None:
        """Test that empty code raises ValueError."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        with pytest.raises(ValueError, match="source_code cannot be empty"):
            await extractor.extract("")

    @pytest.mark.asyncio
    async def test_extract_whitespace_only(self) -> None:
        """Test that whitespace-only code raises ValueError."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        with pytest.raises(ValueError, match="source_code cannot be empty"):
            await extractor.extract("   \n\t  ")

    @pytest.mark.asyncio
    async def test_extract_simple_code(self) -> None:
        """Test extraction from simple Java code."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """public void process(HttpServletRequest request) {
            String input = request.getParameter("q");
            db.execute(input);
        }"""

        # Mock LLM combined response (single call per function)
        combined_response = {
            "sources": [{"line": 2, "variable": "input", "type": "user_input", "confidence": 0.9}],
            "sinks": [{"line": 3, "variable": "input", "type": "sql_query", "vulnerability_type": "sql_injection", "confidence": 0.95}],
        }

        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = combined_response

            spec = await extractor.extract(code, "test.java")

        assert len(spec.sources) == 1
        assert len(spec.sinks) == 1
        assert spec.sources[0].variable_name == "input"
        assert spec.sinks[0].variable_name == "input"


class TestSplitIntoFunctions:
    """Tests for the _split_into_functions method."""

    def test_split_single_function(self) -> None:
        """Test splitting code with single function."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """public void test() {
            String x = "hello";
        }"""

        functions = extractor._split_into_functions(code)
        assert len(functions) > 0

    def test_split_multiple_functions(self) -> None:
        """Test splitting code with multiple functions."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """public void foo() {
            int x = 1;
        }

        private String bar() {
            return "test";
        }"""

        functions = extractor._split_into_functions(code)
        assert len(functions) >= 1

    def test_split_no_functions(self) -> None:
        """Test splitting code with no proper functions."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = "int x = 5;"

        functions = extractor._split_into_functions(code)
        # Should return entire code as single unit
        assert len(functions) >= 1

    def test_split_preserves_function_name(self) -> None:
        """Test that split preserves function names."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """public void myFunction() {
            int x = 1;
        }"""

        functions = extractor._split_into_functions(code)
        if functions:
            assert "myFunction" in functions[0][0]


class TestParseLLMSources:
    """Tests for _parse_llm_sources method."""

    def test_parse_sources_success(self) -> None:
        """Test parsing valid source response."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sources": [
                {
                    "line": 10,
                    "variable": "user_input",
                    "type": "user_input",
                    "confidence": 0.95,
                }
            ]
        }

        sources = extractor._parse_llm_sources(response, "test.java")

        assert len(sources) == 1
        assert sources[0].variable_name == "user_input"
        assert sources[0].location.line_number == 10

    def test_parse_sources_empty(self) -> None:
        """Test parsing response with no sources."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {"sources": []}

        sources = extractor._parse_llm_sources(response, "test.java")

        assert len(sources) == 0

    def test_parse_sources_filters_by_confidence(self) -> None:
        """Test that sources below threshold are filtered."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client, confidence_threshold=0.7)

        response = {
            "sources": [
                {
                    "line": 10,
                    "variable": "high_conf",
                    "type": "user_input",
                    "confidence": 0.9,
                },
                {
                    "line": 11,
                    "variable": "low_conf",
                    "type": "user_input",
                    "confidence": 0.5,
                },
            ]
        }

        sources = extractor._parse_llm_sources(response, "test.java")

        assert len(sources) == 1
        assert sources[0].variable_name == "high_conf"

    def test_parse_sources_invalid_response_not_dict(self) -> None:
        """Test that non-dict response raises ParsingError."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        with pytest.raises(ParsingError):
            extractor._parse_llm_sources("not a dict", "test.java")

    def test_parse_sources_missing_key(self) -> None:
        """Test that missing 'sources' key raises ParsingError."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        with pytest.raises(ParsingError):
            extractor._parse_llm_sources({}, "test.java")

    def test_parse_sources_with_line_offset(self) -> None:
        """Test that line offset is applied correctly."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sources": [{"line": 5, "variable": "x", "type": "user_input", "confidence": 0.9}]
        }

        sources = extractor._parse_llm_sources(response, "test.java", line_offset=10)

        assert sources[0].location.line_number == 15


class TestParseLLMSinks:
    """Tests for _parse_llm_sinks method."""

    def test_parse_sinks_success(self) -> None:
        """Test parsing valid sink response."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sinks": [
                {
                    "line": 20,
                    "variable": "query",
                    "type": "sql_query",
                    "vulnerability_type": "sql_injection",
                    "confidence": 0.98,
                }
            ]
        }

        sinks = extractor._parse_llm_sinks(response, "test.java")

        assert len(sinks) == 1
        assert sinks[0].variable_name == "query"
        assert sinks[0].vulnerability_type == VulnerabilityType.SQL_INJECTION

    def test_parse_sinks_empty(self) -> None:
        """Test parsing response with no sinks."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {"sinks": []}

        sinks = extractor._parse_llm_sinks(response, "test.java")

        assert len(sinks) == 0

    def test_parse_sinks_filters_by_confidence(self) -> None:
        """Test that sinks below threshold are filtered."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client, confidence_threshold=0.8)

        response = {
            "sinks": [
                {
                    "line": 20,
                    "variable": "high",
                    "type": "sql_query",
                    "vulnerability_type": "sql_injection",
                    "confidence": 0.9,
                },
                {
                    "line": 21,
                    "variable": "low",
                    "type": "sql_query",
                    "vulnerability_type": "sql_injection",
                    "confidence": 0.6,
                },
            ]
        }

        sinks = extractor._parse_llm_sinks(response, "test.java")

        assert len(sinks) == 1
        assert sinks[0].variable_name == "high"

    def test_parse_sinks_missing_vulnerability_type(self) -> None:
        """Test handling of missing vulnerability type."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sinks": [
                {
                    "line": 20,
                    "variable": "query",
                    "type": "sql_query",
                    "confidence": 0.9,
                }
            ]
        }

        sinks = extractor._parse_llm_sinks(response, "test.java")

        assert len(sinks) == 1
        # Should default to SQL_INJECTION
        assert sinks[0].vulnerability_type == VulnerabilityType.SQL_INJECTION

    def test_parse_sinks_invalid_response(self) -> None:
        """Test that invalid response raises ParsingError."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        with pytest.raises(ParsingError):
            extractor._parse_llm_sinks("not a dict", "test.java")

    def test_parse_sinks_with_line_offset(self) -> None:
        """Test that line offset is applied correctly."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sinks": [
                {
                    "line": 3,
                    "variable": "q",
                    "type": "sql",
                    "vulnerability_type": "sql_injection",
                    "confidence": 0.9,
                }
            ]
        }

        sinks = extractor._parse_llm_sinks(response, "test.java", line_offset=100)

        assert sinks[0].location.line_number == 103


class TestContextExtraction:
    """Tests for context extraction methods."""

    def test_extract_imports_single(self) -> None:
        """Test extracting single import statement."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """import java.io.IOException;
        public class Test {}"""

        imports = extractor._extract_imports(code)
        assert len(imports) >= 1
        assert "java.io.IOException" in imports

    def test_extract_imports_multiple(self) -> None:
        """Test extracting multiple import statements."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """import java.io.IOException;
        import java.util.List;
        import javax.servlet.http.HttpServletRequest;
        public class Test {}"""

        imports = extractor._extract_imports(code)
        assert len(imports) >= 3

    def test_extract_imports_static(self) -> None:
        """Test extracting static import statements."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """import static java.lang.Math.PI;
        public class Test {}"""

        imports = extractor._extract_imports(code)
        assert len(imports) >= 1

    def test_extract_classes_single(self) -> None:
        """Test extracting single class."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """public class MyClass {}"""

        classes = extractor._extract_classes(code)
        assert len(classes) >= 1
        assert classes[0].get("name") == "MyClass"

    def test_extract_classes_with_extends(self) -> None:
        """Test extracting class with extends clause."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """public class MyService extends BaseService {}"""

        classes = extractor._extract_classes(code)
        assert len(classes) >= 1
        assert classes[0].get("name") == "MyService"

    def test_extract_classes_with_implements(self) -> None:
        """Test extracting class with implements clause."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """public class MyHandler implements EventListener {}"""

        classes = extractor._extract_classes(code)
        assert len(classes) >= 1
        assert classes[0].get("name") == "MyHandler"


class TestLLMEndpointPreservation:
    """The parser must not reject model-selected endpoints by variable name."""

    def test_preserves_valid_identifiers(self) -> None:
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sources": [
                {"line": 10, "variable": "result", "type": "database", "confidence": 0.9},
                {"line": 11, "variable": "context", "type": "external_data", "confidence": 0.9},
            ]
        }

        sources = extractor._parse_llm_sources(response, "test.java")
        assert [source.variable_name for source in sources] == ["result", "context"]

    def test_stores_function_name_in_source(self) -> None:
        """Test that function_name is stored in Source CodeLocation."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sources": [
                {"line": 5, "variable": "input", "type": "user_input", "confidence": 0.9},
            ]
        }

        sources = extractor._parse_llm_sources(
            response, "test.java", function_name="processRequest"
        )

        assert len(sources) == 1
        assert sources[0].location.function_name == "processRequest"

    def test_stores_function_name_in_sink(self) -> None:
        """Test that function_name is stored in Sink CodeLocation."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sinks": [
                {
                    "line": 10,
                    "variable": "query",
                    "type": "sql_query",
                    "vulnerability_type": "sql_injection",
                    "confidence": 0.9,
                }
            ]
        }

        sinks = extractor._parse_llm_sinks(
            response, "test.java", function_name="findById"
        )

        assert len(sinks) == 1
        assert sinks[0].location.function_name == "findById"


class TestRealWorldScenarios:
    """Tests with realistic Java code."""

    @pytest.mark.asyncio
    async def test_extract_sql_injection_vulnerability(self) -> None:
        """Test extraction of SQL injection vulnerability."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client, confidence_threshold=0.6)

        code = """public void searchUsers(HttpServletRequest request) {
            String searchTerm = request.getParameter("search");
            String query = "SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'";
            ResultSet rs = db.executeQuery(query);
        }"""

        combined_response = {
            "sources": [
                {
                    "line": 2,
                    "variable": "searchTerm",
                    "type": "user_input",
                    "confidence": 0.95,
                }
            ],
            "sinks": [
                {
                    "line": 4,
                    "variable": "query",
                    "type": "sql_query",
                    "vulnerability_type": "sql_injection",
                    "confidence": 0.92,
                }
            ],
        }

        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = combined_response

            spec = await extractor.extract(code, "UserService.java")

        assert len(spec.sources) == 1
        assert len(spec.sinks) == 1


class TestLineResolution:
    """The extractor recovers the actual variable line when the LLM is off.

    LLMs frequently report a slightly-wrong line (function header instead of
    body, off-by-one, function-relative line never recombined with the
    function start). The extractor scans ±5 lines, then the whole file, to
    find the variable's first occurrence — keeps `code_snippet` aligned with
    the reported variable so downstream classifier/filter work correctly.
    """

    @pytest.mark.asyncio
    async def test_recovers_off_by_one_line(self) -> None:
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(llm_client=client)
        code = (
            "public class C {\n"
            "  public void handle(HttpServletRequest req) {\n"
            "    String userInput = req.getParameter(\"x\");\n"
            "    stmt.execute(userInput);\n"
            "  }\n"
            "}\n"
        )
        # LLM points at line 2 (signature), real declaration at line 3
        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as m:
            m.return_value = {
                "sources": [{"line": 2, "variable": "userInput",
                             "type": "user_input", "confidence": 0.9}],
                "sinks": [{"line": 4, "variable": "userInput",
                           "type": "sql", "vulnerability_type": "sql_injection",
                           "confidence": 0.9}],
            }
            spec = await extractor.extract(code, "C.java")

        assert spec.sources, "Source should be extracted"
        # Snippet must contain the variable so classifier sees the real call
        assert "userInput" in spec.sources[0].code_snippet
        assert "getParameter" in spec.sources[0].code_snippet

    @pytest.mark.asyncio
    async def test_full_file_fallback_when_far_off(self) -> None:
        """LLM line outside ±5 window — fallback finds the var anywhere."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(llm_client=client)
        code = "\n".join(["// line 1", "// line 2"] * 30 +
                         ["String farAway = req.getParameter(\"q\");"] +
                         ["// trailing"] * 5) + "\n"
        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as m:
            m.return_value = {
                "sources": [{"line": 1, "variable": "farAway",
                             "type": "user_input", "confidence": 0.9}],
                "sinks": [],
            }
            spec = await extractor.extract(code, "X.java")

        assert spec.sources
        assert "farAway" in spec.sources[0].code_snippet

    @pytest.mark.asyncio
    async def test_comment_mention_is_not_used_as_endpoint_line(self) -> None:
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(
            llm_client=client,
            batch_max_chars=10_000,
        )
        code = """public class LinkTag {
  /** title is rendered by this tag. */
  private String stored;
  public void setTitle(String title) {
    this.stored = title;
  }
  public void render() { out.print(stored); }
}
"""
        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as m:
            m.return_value = {
                "sources": [{"line": 2, "variable": "title",
                             "type": "tag_attribute", "confidence": 0.9}],
                "sinks": [],
            }
            spec = await extractor.extract(code, "LinkTag.java")

        assert spec.sources[0].location.line_number == 4
        assert "setTitle" in spec.sources[0].code_snippet

    @pytest.mark.asyncio
    async def test_resolved_snippet_classifies_correctly(self) -> None:
        """End-to-end: line-resolved snippet hits the USER_INPUT classifier."""
        from src.core.models import SourceCategory

        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(llm_client=client)
        code = (
            "public class C {\n"
            "  public void handle(HttpServletRequest req) {\n"
            "    String userInput = req.getParameter(\"x\");\n"
            "    use(userInput);\n"
            "  }\n"
            "}\n"
        )
        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as m:
            m.return_value = {
                "sources": [{"line": 1, "variable": "userInput",
                             "type": "user_input", "confidence": 0.9}],
                "sinks": [],
            }
            spec = await extractor.extract(code, "C.java")

        assert spec.sources
        # Critical: with the resolved snippet, the source classifier sees
        # `getParameter(` and assigns USER_INPUT — not the INTERNAL_API
        # fallback that would bypass the risk matrix.
        assert spec.sources[0].source_category == SourceCategory.USER_INPUT


class TestInferVulnerabilityType:
    """Tests for the _infer_vulnerability_type fallback classifier."""

    def test_infer_deserialization_from_readobject(self) -> None:
        result = SimpleSpecificationExtractor._infer_vulnerability_type(
            raw_type="unknown_type", sink_type="readObject call"
        )
        assert result == VulnerabilityType.UNSAFE_DESERIALIZATION

    def test_infer_deserialization_from_readvalue(self) -> None:
        result = SimpleSpecificationExtractor._infer_vulnerability_type(
            raw_type="json", sink_type="JsonSerialization.readValue"
        )
        assert result == VulnerabilityType.UNSAFE_DESERIALIZATION

    def test_infer_code_injection_from_classforname(self) -> None:
        result = SimpleSpecificationExtractor._infer_vulnerability_type(
            raw_type="reflection", sink_type="Reflections.classForName"
        )
        assert result == VulnerabilityType.CODE_INJECTION

    def test_infer_xss_unchanged(self) -> None:
        """Existing XSS inference still wins on output sinks."""
        result = SimpleSpecificationExtractor._infer_vulnerability_type(
            raw_type="reflected", sink_type="response.write output"
        )
        assert result == VulnerabilityType.XSS

    def test_deserialize_keyword_beats_output(self) -> None:
        """`deserialize` is checked before XSS keywords like `output`."""
        result = SimpleSpecificationExtractor._infer_vulnerability_type(
            raw_type="deserialize_output_sink", sink_type="x"
        )
        assert result == VulnerabilityType.UNSAFE_DESERIALIZATION


class TestHasPotentialSinks:
    """AST-based zero-sink prefilter.

    These tests assume tree-sitter Java is installed; if not, the prefilter
    falls back to True (conservative) and the False-cases will fail — that's
    intentional, because without AST the prefilter doesn't gain anything.
    """

    def _extractor(self):
        client = SimpleLLMClient(api_key="test-key")
        return SimpleSpecificationExtractor(client)

    def test_enum_without_methods_returns_false(self):
        ext = self._extractor()
        if ext.ast_parser.parser is None:
            pytest.skip("tree-sitter unavailable")
        code = "public enum Color { RED, GREEN, BLUE; }"
        assert ext._has_potential_sinks(code) is False

    def test_marker_interface_returns_false(self):
        ext = self._extractor()
        if ext.ast_parser.parser is None:
            pytest.skip("tree-sitter unavailable")
        code = "public interface Marker {}"
        assert ext._has_potential_sinks(code) is False

    def test_pure_dto_returns_false(self):
        ext = self._extractor()
        if ext.ast_parser.parser is None:
            pytest.skip("tree-sitter unavailable")
        # Fields only, no method bodies — cannot contain a sink.
        code = (
            "public class UserDto { "
            "  private String name; "
            "  private int age; "
            "}"
        )
        assert ext._has_potential_sinks(code) is False

    def test_package_info_returns_false(self):
        ext = self._extractor()
        if ext.ast_parser.parser is None:
            pytest.skip("tree-sitter unavailable")
        code = "@Deprecated\npackage com.example.api;"
        assert ext._has_potential_sinks(code) is False

    def test_empty_class_shell_returns_false(self):
        ext = self._extractor()
        if ext.ast_parser.parser is None:
            pytest.skip("tree-sitter unavailable")
        code = "public class Foo extends Bar {}"
        assert ext._has_potential_sinks(code) is False

    def test_single_method_call_returns_true(self):
        ext = self._extractor()
        if ext.ast_parser.parser is None:
            pytest.skip("tree-sitter unavailable")
        code = (
            "public class A { "
            "  public void m(String s) { "
            "    System.out.println(s); "
            "  } "
            "}"
        )
        assert ext._has_potential_sinks(code) is True

    def test_constructor_call_returns_true(self):
        ext = self._extractor()
        if ext.ast_parser.parser is None:
            pytest.skip("tree-sitter unavailable")
        code = (
            "public class A { "
            "  public Object m() { return new File(\"x\"); } "
            "}"
        )
        assert ext._has_potential_sinks(code) is True

    def test_falls_back_to_true_without_ast(self):
        """When tree-sitter is unavailable, prefilter must NOT skip files.

        We can't reliably detect sinks without AST, and false negatives are
        the worst possible outcome (silently missed vulnerabilities). So when
        parser=None, return True (analyze the file) regardless of content.
        """
        ext = self._extractor()
        ext.ast_parser.parser = None  # simulate missing tree-sitter
        assert ext._has_potential_sinks("public enum E {}") is True


class TestExtractCacheIntegration:
    """Cache and prefilter integration with extract()."""

    def _make_extractor(self, spec_cache=None):
        client = SimpleLLMClient(api_key="test-key")
        # Use a real LLM-shaped mock so we can assert it was (or wasn't) called.
        client.chat_with_json_prompt = AsyncMock(return_value={"sources": [], "sinks": []})
        return SimpleSpecificationExtractor(
            client,
            spec_cache=spec_cache,
            llm_provider="openai",
        )

    @pytest.mark.asyncio
    async def test_cache_hit_skips_llm_call(self, tmp_path):
        from src.stage1_llm_inference.spec_cache import SpecCache
        from src.core.models import Specification

        cache = SpecCache(cache_dir=tmp_path)
        # Pre-populate with a known spec for content "X".
        cached_spec = Specification(
            sources=[], sinks=[], sanitizers=[], llm_model="gpt-4-turbo",
        )
        cache.put(
            "public class X { void m() { System.out.println(\"hi\"); } }",
            cached_spec,
            llm_provider="openai",
            llm_model="gpt-4-turbo",
            min_confidence=0.5,
            extractor_options=(
                "analysis_backend=llm;analysis_mode=exhaustive;batch_max_chars=0"
            ),
        )

        ext = self._make_extractor(spec_cache=cache)
        spec = await ext.extract(
            "public class X { void m() { System.out.println(\"hi\"); } }",
            file_path="X.java",
            model="gpt-4-turbo",
        )

        assert spec is not None
        # LLM must NOT have been called — replay from cache.
        ext.llm_client.chat_with_json_prompt.assert_not_called()
        assert cache.stats.hits == 1

    @pytest.mark.asyncio
    async def test_prefilter_skips_llm_call_for_declarative_file(self, tmp_path):
        from src.stage1_llm_inference.spec_cache import SpecCache

        cache = SpecCache(cache_dir=tmp_path)
        ext = self._make_extractor(spec_cache=cache)
        if ext.ast_parser.parser is None:
            pytest.skip("tree-sitter unavailable")

        spec = await ext.extract(
            "public enum Color { RED, GREEN, BLUE; }",
            file_path="Color.java",
            model="gpt-4-turbo",
        )

        assert spec.sources == []
        assert spec.sinks == []
        ext.llm_client.chat_with_json_prompt.assert_not_called()
        # Result was cached for next time.
        assert cache.stats.writes == 1

    @pytest.mark.asyncio
    async def test_no_cache_no_provider_still_works(self):
        """Without a cache, extract proceeds normally."""
        ext = self._make_extractor(spec_cache=None)
        if ext.ast_parser.parser is None:
            pytest.skip("tree-sitter unavailable")

        # A declarative file still bypasses the LLM via the prefilter.
        spec = await ext.extract(
            "public enum E { A, B; }",
            file_path="E.java",
            model="gpt-4-turbo",
        )
        assert spec.sources == []
        ext.llm_client.chat_with_json_prompt.assert_not_called()

    @pytest.mark.asyncio
    async def test_incomplete_extraction_is_not_cached(self, tmp_path):
        from src.stage1_llm_inference.spec_cache import SpecCache

        cache = SpecCache(cache_dir=tmp_path)
        ext = self._make_extractor(spec_cache=cache)
        ext.llm_client.chat_with_json_prompt = AsyncMock(
            side_effect=LLMError("temporary provider failure")
        )
        code = """
public class Controller {
    void run(String input) { Runtime.getRuntime().exec(input); }
}
"""

        spec = await ext.extract(code, file_path="Controller.java")

        assert spec.extraction_complete is False
        assert spec.extraction_errors
        assert cache.stats.writes == 0


class TestLLMBatching:
    """File batching reduces request fan-out without losing AST scope."""

    @pytest.mark.asyncio
    async def test_batches_methods_and_restores_function_scope(self):
        client = SimpleLLMClient(api_key="test-key")
        client.chat_with_json_prompt = AsyncMock(return_value={
            "sources": [{
                "line": 3,
                "variable": "input",
                "type": "user_input",
                "confidence": 0.9,
            }],
            "sinks": [{
                "line": 7,
                "variable": "query",
                "type": "sql_execution",
                "vulnerability_type": "sql_injection",
                "confidence": 0.9,
            }],
            "sanitizers": [{
                "line": 3,
                "variable": "input",
                "type": "input_validation",
                "vulnerability_types": ["sql_injection"],
                "confidence": 0.8,
                "effectiveness": 0.5,
            }],
        })
        extractor = SimpleSpecificationExtractor(
            client,
            batch_max_chars=10_000,
        )
        code = """public class Batched {
    public void first() {
        String input = request.getParameter("q");
        audit(input);
    }
    public void second(String query) {
        db.execute(query);
    }
}
"""

        spec = await extractor.extract(code, "Batched.java")

        client.chat_with_json_prompt.assert_awaited_once()
        assert [source.variable_name for source in spec.sources].count("input") == 1
        assert next(
            source for source in spec.sources if source.variable_name == "input"
        ).location.function_name == "first"
        assert next(
            sink for sink in spec.sinks if sink.variable_name == "query"
        ).location.function_name == "second"
        sanitizer = spec.sanitizers[0]
        assert sanitizer.location.function_name == "first"
        assert "request.getParameter" in sanitizer.code_snippet

    def test_combined_prompt_formats_full_file_examples(self):
        from src.stage1_llm_inference.prompt_templates import build_combined_prompt

        prompt = build_combined_prompt(
            code="class T { void run(String input) {} }",
            function_info=None,
            class_info=None,
            imports=[],
        )

        assert "setValue(String value)" in prompt
        assert "this.field = value" in prompt

    @pytest.mark.asyncio
    async def test_failed_full_file_batch_retries_as_smaller_method_batches(self):
        client = SimpleLLMClient(api_key="test-key")
        client.chat_with_json_prompt = AsyncMock(side_effect=[
            ParsingError("truncated"),
            ParsingError("truncated"),
            {"sources": [], "sinks": []},
            {"sources": [], "sinks": []},
        ])
        extractor = SimpleSpecificationExtractor(client, batch_max_chars=400)
        code = """public class RetriedBatch {
    public void first(String input) {
        service.consumeFirst(input);
    }

    // Padding keeps the complete file above the retry batch limit while each
    // individual method remains below it.
    public void second(String value) {
        service.consumeSecond(value);
    }
}
"""

        spec = await extractor.extract(code, "RetriedBatch.java")

        assert spec.extraction_complete is True
        assert spec.extraction_errors == []
        assert client.chat_with_json_prompt.await_count == 4

    @pytest.mark.asyncio
    async def test_successful_large_batch_is_not_mistaken_for_failure(self):
        client = SimpleLLMClient(api_key="test-key")
        client.chat_with_json_prompt = AsyncMock(return_value={
            "sources": [], "sinks": [], "sanitizers": [],
        })
        extractor = SimpleSpecificationExtractor(client, batch_max_chars=400)
        code = """public class SuccessfulBatch {
    public void first(String input) {
        Runtime.getRuntime().exec(input);
    }

    // Padding makes a failed synthetic batch eligible for split retry.
    public void second(String value) {
        Runtime.getRuntime().exec(value);
    }
}
"""

        spec = await extractor.extract(code, "SuccessfulBatch.java")

        assert spec.extraction_complete is True
        # The empty batch is reviewed once per suspicious method, not treated
        # as a failed batch and recursively split/retried.
        assert client.chat_with_json_prompt.await_count == 3

    @pytest.mark.asyncio
    async def test_sink_without_sources_gets_one_llm_consistency_repair(self):
        client = SimpleLLMClient(api_key="test-key")
        client.chat_with_json_prompt = AsyncMock(side_effect=[
            {
                "sources": [],
                "sinks": [{
                    "line": 4,
                    "variable": "target",
                    "type": "file_write",
                    "vulnerability_type": "path_traversal",
                    "confidence": 0.95,
                }],
            },
            {
                "sources": [{
                    "line": 3,
                    "variable": "entry",
                    "type": "archive_entry",
                    "confidence": 0.95,
                }]
            },
        ])
        extractor = SimpleSpecificationExtractor(client, batch_max_chars=10_000)
        code = """class ZipReader {
    void unpack(ZipEntry entry) {
        File target = new File(root, entry.getName());
        Files.copy(input, target.toPath());
    }
}"""

        spec = await extractor.extract(code, "ZipReader.java")

        assert client.chat_with_json_prompt.await_count == 2
        assert [source.variable_name for source in spec.sources] == ["entry"]

    @pytest.mark.asyncio
    async def test_suspicious_empty_result_gets_one_llm_review(self):
        client = SimpleLLMClient(api_key="test-key")
        client.chat_with_json_prompt = AsyncMock(side_effect=[
            {"sources": [], "sinks": [], "sanitizers": []},
            {
                "sources": [{
                    "line": 2, "variable": "target", "type": "user_input",
                    "confidence": 0.9,
                }],
                "sinks": [{
                    "line": 3, "variable": "target", "type": "redirect",
                    "vulnerability_type": "open_redirect", "confidence": 0.9,
                }],
                "sanitizers": [],
            },
        ])
        extractor = SimpleSpecificationExtractor(client)
        code = """class Redirector {
    public void redirect(HttpServletRequest request, HttpServletResponse response) {
        String target = request.getParameter("next");
        response.sendRedirect(target);
    }
}"""

        spec = await extractor.extract(code, "Redirector.java")

        assert client.chat_with_json_prompt.await_count == 2
        assert [source.variable_name for source in spec.sources] == ["target"]
        assert [sink.variable_name for sink in spec.sinks] == ["target"]

    @pytest.mark.asyncio
    async def test_batch_repairs_sink_method_without_its_own_source(self):
        client = SimpleLLMClient(api_key="test-key")
        client.chat_with_json_prompt = AsyncMock(side_effect=[
            {
                "sources": [{
                    "line": 3, "variable": "target",
                    "type": "user_input", "confidence": 0.9,
                }],
                "sinks": [
                    {
                        "line": 4, "variable": "target", "type": "redirect",
                        "vulnerability_type": "open_redirect", "confidence": 0.9,
                    },
                    {
                        "line": 8, "variable": "target", "type": "redirect",
                        "vulnerability_type": "open_redirect", "confidence": 0.9,
                    },
                ],
                "sanitizers": [],
            },
            {
                "sources": [{
                    "line": 7, "variable": "target",
                    "type": "user_input", "confidence": 0.9,
                }]
            },
        ])
        extractor = SimpleSpecificationExtractor(client, batch_max_chars=10_000)
        code = """class Redirector {
    public void first(HttpServletRequest request, HttpServletResponse response) {
        String target = request.getParameter("first");
        response.sendRedirect(target);
    }
    public void second(HttpServletRequest request, HttpServletResponse response) {
        String target = request.getHeader("Location");
        response.sendRedirect(target);
    }
}"""

        spec = await extractor.extract(code, "Redirector.java")

        assert client.chat_with_json_prompt.await_count == 2
        assert any(
            source.variable_name == "target"
            and source.location.function_name == "second"
            and source.location.line_number == 7
            for source in spec.sources
        )


class TestLLMAnalysisModes:
    @pytest.mark.asyncio
    async def test_targeted_skips_unrelated_nontrivial_method(self):
        client = SimpleLLMClient(api_key="test-key")
        client.chat_with_json_prompt = AsyncMock(
            return_value={"sources": [], "sinks": []}
        )
        extractor = SimpleSpecificationExtractor(client, analysis_mode="targeted")

        await extractor.extract(
            "class T { void work(String value) { service.customConsume(value); } }",
            "T.java",
        )

        client.chat_with_json_prompt.assert_not_called()

    @pytest.mark.asyncio
    async def test_llm_backend_does_not_mix_in_deterministic_endpoints(self):
        client = SimpleLLMClient(api_key="test-key")
        client.chat_with_json_prompt = AsyncMock(
            return_value={"sources": [], "sinks": []}
        )
        extractor = SimpleSpecificationExtractor(client, analysis_backend="llm")

        spec = await extractor.extract(
            "class T { public static void run(String cmd) { "
            "Runtime.getRuntime().exec(cmd); } }",
            "T.java",
        )

        assert client.chat_with_json_prompt.await_count == 2
        assert spec.sources == []
        assert spec.sinks == []
        assert spec.extraction_backend == "llm"

    @pytest.mark.asyncio
    async def test_static_backend_keeps_deterministic_endpoints_without_llm(self):
        client = SimpleLLMClient(api_key="test-key")
        client.chat_with_json_prompt = AsyncMock(
            return_value={"sources": [], "sinks": []}
        )
        extractor = SimpleSpecificationExtractor(client, analysis_backend="static")

        spec = await extractor.extract(
            "class T { public static void run(String cmd) { "
            "Runtime.getRuntime().exec(cmd); } }",
            "T.java",
        )

        client.chat_with_json_prompt.assert_not_called()
        assert any(sink.variable_name == "cmd" for sink in spec.sinks)
        assert spec.extraction_backend == "static"
        assert spec.llm_model == ""


class TestParseLLMSanitizers:
    def test_parse_sanitizer_success(self) -> None:
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)
        response = {
            "sanitizers": [{
                "line": 7,
                "variable": "path",
                "type": "allowed_root_check",
                "vulnerability_types": ["path_traversal"],
                "confidence": 0.95,
                "effectiveness": 0.9,
            }]
        }

        sanitizers = extractor._parse_llm_sanitizers(
            response, "Test.java", line_offset=10, function_name="load"
        )

        assert len(sanitizers) == 1
        assert sanitizers[0].variable_name == "path"
        assert sanitizers[0].location.line_number == 17
        assert sanitizers[0].location.function_name == "load"
        assert sanitizers[0].vulnerability_types == ["path_traversal"]
        assert sanitizers[0].effectiveness == 0.9

    def test_missing_sanitizers_key_means_none(self) -> None:
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        assert extractor._parse_llm_sanitizers({}, "Test.java") == []


class TestSinkAttributedSources:
    def test_accepts_only_explicit_model_attribution(self) -> None:
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)
        response = {
            "sinks": [{
                "variable": "f",
                "taint_sources": [{
                    "line": 8,
                    "variable": "e",
                    "type": "archive_entry",
                    "confidence": 0.95,
                }],
            }]
        }

        sources = extractor._parse_llm_sink_attributed_sources(
            response, "Zip.java", function_name="unpack"
        )

        assert [source.variable_name for source in sources] == ["e"]
        assert sources[0].location.line_number == 8

    def test_does_not_infer_source_from_sink_reasoning(self) -> None:
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)
        response = {
            "sinks": [{
                "variable": "f",
                "reasoning": "Zip entry e controls this path",
            }]
        }

        assert extractor._parse_llm_sink_attributed_sources(
            response, "Zip.java"
        ) == []


class TestStructuralSinkFilter:
    def test_rejects_literal_field_declaration(self):
        from src.core.models import CodeLocation, Sink

        sink = Sink(
            location=CodeLocation(file_path="Test.java", line_number=1),
            variable_name="redirect",
            type="other",
            confidence=0.9,
            code_snippet='private String redirect = "";',
            vulnerability_type=VulnerabilityType.OTHER,
        )

        assert SimpleSpecificationExtractor._is_plausible_sink(sink) is False

    def test_keeps_model_selected_unfamiliar_call_result(self):
        from src.core.models import CodeLocation, Sink

        sink = Sink(
            location=CodeLocation(file_path="Test.java", line_number=1),
            variable_name="result",
            type="novel_security_boundary",
            confidence=0.9,
            code_snippet="Payload result = customEngine.consume(input);",
            vulnerability_type=VulnerabilityType.OTHER,
        )

        assert SimpleSpecificationExtractor._is_plausible_sink(sink) is True

    def test_keeps_security_operation_assignment(self):
        from src.core.models import CodeLocation, Sink

        sink = Sink(
            location=CodeLocation(file_path="Test.java", line_number=1),
            variable_name="clazz",
            type="deserialization",
            confidence=0.9,
            code_snippet="Class<?> clazz = Reflections.classForName(value);",
            vulnerability_type=VulnerabilityType.UNSAFE_DESERIALIZATION,
        )
        assert SimpleSpecificationExtractor._is_plausible_sink(sink) is True

    def test_rejects_sink_whose_snippet_does_not_use_reported_variable(self):
        from src.core.models import CodeLocation, Sink

        sink = Sink(
            location=CodeLocation(file_path="Test.java", line_number=1),
            variable_name="catPicture",
            type="file_path",
            confidence=0.9,
            code_snippet="var uploadedFile = new File(root, fullName);",
            vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
        )

        assert SimpleSpecificationExtractor._is_plausible_sink(sink) is False

    def test_keeps_model_selected_call_assignment(self):
        from src.core.models import CodeLocation, Sink

        sink = Sink(
            location=CodeLocation(file_path="Test.java", line_number=1),
            variable_name="url",
            type="html_output",
            confidence=0.9,
            code_snippet="url = wikiContext.getURL(pageName);",
            vulnerability_type=VulnerabilityType.XSS,
        )

        assert SimpleSpecificationExtractor._is_plausible_sink(sink) is True

    @pytest.mark.parametrize(
        ("snippet", "variable", "vuln_type", "sink_category"),
        [
            (
                "byte[] listBytes = JsonSerialization.writeValueAsBytes(value);",
                "listBytes",
                VulnerabilityType.OTHER,
                None,
            ),
            (
                "url = wikiContext.getURL(VIEW, pageName);",
                "url",
                VulnerabilityType.SSRF,
                None,
            ),
            (
                "relayState = client.getAttribute(RELAY_STATE);",
                "relayState",
                VulnerabilityType.OTHER,
                None,
            ),
            (
                "relayState = client.getAttribute(RELAY_STATE);",
                "relayState",
                VulnerabilityType.OPEN_REDIRECT,
                None,
            ),
            (
                "code = OAuth2CodeParser.persistCode(session, codeData);",
                "code",
                VulnerabilityType.OPEN_REDIRECT,
                None,
            ),
            (
                "Worker worker = new Worker(doc, clientArtifactBindingURI);",
                "clientArtifactBindingURI",
                VulnerabilityType.SSRF,
                SinkCategory.FRAMEWORK_API,
            ),
            (
                "this.credentialId = credentialId;",
                "credentialId",
                VulnerabilityType.OTHER,
                None,
            ),
            (
                "code = OAuth2CodeParser.persistCode(session, codeData);",
                "code",
                VulnerabilityType.SSRF,
                None,
            ),
            (
                "ArtifactResolutionRunnable task = new ArtifactResolutionRunnable(uri);",
                "task",
                VulnerabilityType.SSRF,
                SinkCategory.FRAMEWORK_API,
            ),
            (
                "cache.put(NAME_ID, nameIdFormat);",
                "nameIdFormat",
                VulnerabilityType.OTHER,
                SinkCategory.DATA_STORAGE,
            ),
        ],
    )
    def test_rejects_non_terminal_model_sinks(
        self, snippet, variable, vuln_type, sink_category
    ):
        from src.core.models import CodeLocation, Sink

        sink = Sink(
            location=CodeLocation(file_path="Test.java", line_number=1),
            variable_name=variable,
            type="model_selected",
            confidence=0.9,
            code_snippet=snippet,
            vulnerability_type=vuln_type,
            sink_category=sink_category,
        )

        assert SimpleSpecificationExtractor._is_plausible_sink(sink) is False

    def test_keeps_concrete_outbound_ssrf_operation(self):
        from src.core.models import CodeLocation, Sink

        sink = Sink(
            location=CodeLocation(file_path="Test.java", line_number=1),
            variable_name="target",
            type="outbound_request",
            confidence=0.9,
            code_snippet="client.postText(target.toString(), token);",
            vulnerability_type=VulnerabilityType.SSRF,
        )

        assert SimpleSpecificationExtractor._is_plausible_sink(sink) is True



class TestIdentifierMatching:
    def test_does_not_match_longer_identifier(self):
        assert not SimpleSpecificationExtractor._mentions_identifier(
            "protected boolean redirectToAuthentication;", "redirect"
        )
        assert not SimpleSpecificationExtractor._mentions_identifier(
            "File catPicturesDirectory;", "catPicture"
        )

    def test_matches_exact_java_identifier(self):
        assert SimpleSpecificationExtractor._mentions_identifier(
            "return render(redirect);", "redirect"
        )

    def test_endpoint_variable_must_be_java_identifier(self):
        assert SimpleSpecificationExtractor._is_java_identifier("payload")
        assert SimpleSpecificationExtractor._is_java_identifier("$value_2")
        assert not SimpleSpecificationExtractor._is_java_identifier("getPayload()")
        assert not SimpleSpecificationExtractor._is_java_identifier("obj.value")

    def test_model_source_accessor_normalizes_to_receiver(self):
        normalize = SimpleSpecificationExtractor._normalize_llm_source_identifier

        assert normalize("e.getName()") == "e"
        assert normalize("file.getOriginalFilename()") == "file"
        assert normalize("this.contextData") == "contextData"

    def test_unqualified_call_is_not_invented_as_identifier(self):
        normalize = SimpleSpecificationExtractor._normalize_llm_source_identifier

        assert normalize("getId()") is None
        assert normalize("left + right") is None
