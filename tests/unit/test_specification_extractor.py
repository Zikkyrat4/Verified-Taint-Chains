"""Unit tests for specification extractor."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.stage1_llm_inference.specification_extractor import SimpleSpecificationExtractor
from src.stage1_llm_inference.llm_client import SimpleLLMClient
from src.core.exceptions import ParsingError, LLMError
from src.core.models import VulnerabilityType


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


class TestFalsePositiveFiltering:
    """Tests for false-positive source variable filtering."""

    def test_filter_resultset_variable(self) -> None:
        """Test that ResultSet variable 'rs' is filtered out."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sources": [
                {"line": 10, "variable": "rs", "type": "database", "confidence": 0.9},
                {"line": 11, "variable": "username", "type": "user_input", "confidence": 0.9},
            ]
        }

        sources = extractor._parse_llm_sources(response, "test.java")
        assert len(sources) == 1
        assert sources[0].variable_name == "username"

    def test_filter_connection_variable(self) -> None:
        """Test that Connection variable 'conn' is filtered out."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sources": [
                {"line": 10, "variable": "conn", "type": "database", "confidence": 0.9},
            ]
        }

        sources = extractor._parse_llm_sources(response, "test.java")
        assert len(sources) == 0

    def test_filter_statement_variables(self) -> None:
        """Test that Statement-related variables are filtered out."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sources": [
                {"line": 10, "variable": "stmt", "type": "database", "confidence": 0.9},
                {"line": 11, "variable": "ps", "type": "database", "confidence": 0.9},
                {"line": 12, "variable": "pstmt", "type": "database", "confidence": 0.9},
            ]
        }

        sources = extractor._parse_llm_sources(response, "test.java")
        assert len(sources) == 0

    def test_filter_is_case_insensitive(self) -> None:
        """Test that filtering works case-insensitively."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        response = {
            "sources": [
                {"line": 10, "variable": "RS", "type": "database", "confidence": 0.9},
                {"line": 11, "variable": "Conn", "type": "database", "confidence": 0.9},
            ]
        }

        sources = extractor._parse_llm_sources(response, "test.java")
        assert len(sources) == 0

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


class TestJspTagSetterPrePass:
    """Tests for the JSP-tag setter source pre-pass."""

    def test_is_jsp_tag_class_via_class_suffix(self) -> None:
        """Class name ending in `Tag` activates the pre-pass."""
        assert SimpleSpecificationExtractor._is_jsp_tag_class(
            imports=[], classes=[{"name": "LinkToTag"}]
        )

    def test_is_jsp_tag_class_via_import(self) -> None:
        """`javax.servlet.jsp.tagext` import activates the pre-pass."""
        assert SimpleSpecificationExtractor._is_jsp_tag_class(
            imports=["javax.servlet.jsp.tagext.TagSupport"], classes=[]
        )

    def test_is_jsp_tag_class_negative(self) -> None:
        """Plain Spring/POJO classes are not in scope."""
        assert not SimpleSpecificationExtractor._is_jsp_tag_class(
            imports=["org.springframework.stereotype.Component"],
            classes=[{"name": "UserService"}],
        )

    def test_extract_setter_sources_emits_param(self) -> None:
        """JSP-tag setter parameter is emitted as USER_INPUT source."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = (
            "package org.apache.wiki.tags;\n"
            "public class LinkToTag {\n"
            "    public String m_title = \"\";\n"
            "    public void setTitle( String title )\n"
            "    {\n"
            "        m_title = title;\n"
            "    }\n"
            "}\n"
        )
        sources = extractor._extract_jsp_setter_sources(
            source_code=code,
            file_path="LinkToTag.java",
            imports=[],
            classes=[{"name": "LinkToTag"}],
        )
        assert len(sources) == 1
        assert sources[0].variable_name == "title"
        assert sources[0].location.line_number == 4
        assert sources[0].location.function_name == "setTitle"
        assert sources[0].type == "user_input"

    def test_extract_setter_sources_skipped_outside_jsp(self) -> None:
        """POJO setters do not produce sources (avoids FP-explosion)."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = (
            "public class UserDto {\n"
            "    public void setName(String name) { this.name = name; }\n"
            "}\n"
        )
        sources = extractor._extract_jsp_setter_sources(
            source_code=code,
            file_path="UserDto.java",
            imports=[],
            classes=[{"name": "UserDto"}],
        )
        assert sources == []


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


class TestCorrectVulnTypeFromSnippet:
    """Tests for snippet-based vuln_type post-correction."""

    def test_readvalue_snippet_corrects_to_deserialization(self) -> None:
        snippet = "SerializedBrokeredIdentityContext ctx = JsonSerialization.readValue(asString, X.class);"
        result = SimpleSpecificationExtractor._correct_vuln_type_from_snippet(snippet)
        assert result == VulnerabilityType.UNSAFE_DESERIALIZATION

    def test_readobject_snippet_corrects(self) -> None:
        snippet = "Object o = ois.readObject();"
        result = SimpleSpecificationExtractor._correct_vuln_type_from_snippet(snippet)
        assert result == VulnerabilityType.UNSAFE_DESERIALIZATION

    def test_classforname_corrects_to_code_injection(self) -> None:
        snippet = "Class<?> clazz = Reflections.classForName(value.getClazz(), loader);"
        result = SimpleSpecificationExtractor._correct_vuln_type_from_snippet(snippet)
        assert result == VulnerabilityType.CODE_INJECTION

    def test_class_forname_corrects(self) -> None:
        snippet = "Class<?> c = Class.forName(name);"
        result = SimpleSpecificationExtractor._correct_vuln_type_from_snippet(snippet)
        assert result == VulnerabilityType.CODE_INJECTION

    def test_neutral_snippet_returns_none(self) -> None:
        """No override on snippets that don't match deserialization/code patterns."""
        snippet = "db.executeQuery(sql);"
        result = SimpleSpecificationExtractor._correct_vuln_type_from_snippet(snippet)
        assert result is None

    def test_empty_snippet_returns_none(self) -> None:
        assert SimpleSpecificationExtractor._correct_vuln_type_from_snippet("") is None

    def test_context_window_catches_neighboring_readvalue(self) -> None:
        """Snippet snaps to follow-on `return`, but window finds readValue."""
        snippet = "return serializedCtx;"
        context = (
            "try {\n"
            "    SerializedCtx serializedCtx = "
            "JsonSerialization.readValue(asString, SerializedCtx.class);\n"
            "    return serializedCtx;\n"
            "} catch (IOException e) {}\n"
        )
        result = SimpleSpecificationExtractor._correct_vuln_type_from_snippet(
            snippet, context
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
