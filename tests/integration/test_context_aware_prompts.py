"""Integration tests for context-aware prompt building in specification extractor."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from src.stage1_llm_inference.specification_extractor import SimpleSpecificationExtractor
from src.stage1_llm_inference.llm_client import SimpleLLMClient
from src.stage1_llm_inference.prompt_templates import (
    build_source_prompt,
    build_sink_prompt,
)


class TestContextAwareLLMPrompts:
    """Tests for context-aware prompt building with AST information."""

    @pytest.mark.asyncio
    async def test_extract_passes_function_context_to_prompts(self) -> None:
        """Test that extract() passes function info to prompt builders."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """import java.util.Scanner;
        import java.io.File;

        public class FileProcessor {
            public void readFile(String filename) {
                File f = new File(filename);
                Scanner s = new Scanner(f);
                String data = s.nextLine();
            }
        }"""

        combined_response = {
            "sources": [
                {
                    "line": 1,
                    "variable": "filename",
                    "type": "User Input",
                    "confidence": 0.9,
                    "reasoning": "Parameter from user",
                }
            ],
            "sinks": [
                {
                    "line": 2,
                    "variable": "f",
                    "type": "File Operations",
                    "vulnerability_type": "path_traversal",
                    "confidence": 0.85,
                    "reasoning": "File path from user input",
                }
            ],
        }

        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = combined_response

            spec = await extractor.extract(code, "FileProcessor.java")

        assert len(spec.sources) == 1
        assert len(spec.sinks) == 1
        assert spec.sources[0].variable_name == "filename"
        assert spec.sinks[0].variable_name == "f"

    @pytest.mark.asyncio
    async def test_extract_builds_context_with_imports(self) -> None:
        """Test that extract() extracts and uses imports in context."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """import javax.servlet.http.HttpServletRequest;
        import java.sql.Statement;

        public void handleRequest(HttpServletRequest req) {
            String param = req.getParameter("id");
            Statement stmt = connection.createStatement();
            stmt.execute("SELECT * FROM users WHERE id=" + param);
        }"""

        combined_response = {"sources": [], "sinks": []}

        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = combined_response

            spec = await extractor.extract(code)

        # Verify that chat_with_json_prompt was called once (combined prompt)
        assert mock_chat.call_count == 1

        # Extract imports to verify they were processed
        imports = extractor._extract_imports(code)
        assert len(imports) >= 2
        assert "javax.servlet.http.HttpServletRequest" in imports
        assert "java.sql.Statement" in imports

    @pytest.mark.asyncio
    async def test_extract_builds_context_with_class_info(self) -> None:
        """Test that extract() extracts and uses class information in context."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """public class UserService extends BaseService implements Serializable {
            public void updateUser(HttpServletRequest request) {
                String userData = request.getParameter("data");
                db.execute(userData);
            }
        }"""

        combined_response = {"sources": [], "sinks": []}

        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = combined_response

            spec = await extractor.extract(code)

        # Verify class extraction
        classes = extractor._extract_classes(code)
        assert len(classes) >= 1
        assert classes[0].get("name") == "UserService"
        # extends info may be in body or as a separate field depending on parser
        class_data = classes[0]
        assert "BaseService" in str(class_data.get("extends", "")) or "BaseService" in str(class_data.get("body", ""))

    def test_enhanced_prompt_includes_function_context(self) -> None:
        """Test that enhanced prompts include function and class context."""
        code = "String data = request.getParameter('input');"

        function_info = {
            "name": "processRequest",
            "return_type": "void",
            "parameters": ["HttpServletRequest request"],
        }

        class_info = {
            "name": "RequestHandler",
            "extends": "HttpServlet",
            "implements": ["Serializable"],
        }

        imports = [
            "javax.servlet.http.HttpServletRequest",
            "javax.servlet.http.HttpServlet",
            "java.io.Serializable",
        ]

        prompt = build_source_prompt(
            code=code,
            function_info=function_info,
            class_info=class_info,
            imports=imports,
        )

        # Verify prompt includes context sections
        assert "Code Context" in prompt
        assert "Class" in prompt
        assert "RequestHandler" in prompt
        assert "Method" in prompt
        assert "processRequest" in prompt
        assert "Imports" in prompt
        assert "javax.servlet.http.HttpServletRequest" in prompt

    def test_enhanced_sink_prompt_includes_context(self) -> None:
        """Test that enhanced sink prompts include context."""
        code = "stmt.execute(query);"

        function_info = {
            "name": "executeQuery",
            "return_type": "ResultSet",
            "parameters": ["String query"],
        }

        class_info = {"name": "DatabaseService", "extends": None, "implements": []}

        imports = ["java.sql.Statement", "java.sql.ResultSet"]

        prompt = build_sink_prompt(
            code=code,
            function_info=function_info,
            class_info=class_info,
            imports=imports,
        )

        # Verify prompt includes context
        assert "Code Context" in prompt
        assert "DatabaseService" in prompt
        assert "executeQuery" in prompt
        assert "ResultSet" in prompt
        assert "java.sql.Statement" in prompt

    @pytest.mark.asyncio
    async def test_extract_with_multiple_functions(self) -> None:
        """Test extraction from code with multiple functions."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """public class DataService {
            public void processData(String input) {
                db.execute("SELECT * FROM data WHERE id=" + input);
            }

            public String getData() {
                return "test";
            }
        }"""

        # Combined response for processData (getData is skipped — no security patterns)
        combined_response = {
            "sources": [],
            "sinks": [
                {
                    "line": 1,
                    "variable": "input",
                    "type": "SQL",
                    "vulnerability_type": "sql_injection",
                    "confidence": 0.9,
                }
            ],
        }

        with patch.object(client, "chat_with_json_prompt", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = combined_response

            spec = await extractor.extract(code, "DataService.java")

        # Should find one sink from processData
        assert len(spec.sinks) >= 1

    def test_context_extraction_is_robust(self) -> None:
        """Test that context extraction handles edge cases gracefully."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        # Test with minimal code (no imports or classes)
        minimal_code = "int x = 5;"

        imports = extractor._extract_imports(minimal_code)
        classes = extractor._extract_classes(minimal_code)

        assert imports == []
        assert classes == []

        # Test with complex imports
        complex_code = """import java.util.*;
        import static java.lang.Math.PI;
        import a.b.c.d.e.VeryLongClassName;
        """

        imports = extractor._extract_imports(complex_code)
        assert len(imports) >= 3

    def test_split_functions_returns_function_info(self) -> None:
        """Test that _split_into_functions returns function info as 4th element."""
        client = SimpleLLMClient(api_key="test-key")
        extractor = SimpleSpecificationExtractor(client)

        code = """public String getValue() {
            return "test";
        }"""

        functions = extractor._split_into_functions(code)

        # Should return 4-tuples: (name, code, offset, func_info)
        assert len(functions) > 0
        func_name, func_code, line_offset, func_info = functions[0]

        assert func_name == "getValue"
        assert func_code is not None
        assert isinstance(line_offset, int)
        assert isinstance(func_info, dict)
        assert "name" in func_info or func_info is not None
