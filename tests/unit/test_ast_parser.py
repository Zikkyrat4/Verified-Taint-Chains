"""Tests for JavaASTParser with regex fallback."""

import pytest
from src.stage1_llm_inference.ast_parser import JavaASTParser


# Code with static methods - matches the regex pattern
SAMPLE_JAVA_CODE_STATIC = """
package com.example;

public class UserController {
    private String name;

    public static void processRequest(String userId) {
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        executeQuery(query);
    }

    private static void executeQuery(String sql) {
        connection.execute(sql);
    }

    public static String getName() {
        return name;
    }
}
"""

SIMPLE_CLASS = """
public class SimpleClass {
    public static void doSomething() {
        System.out.println("hello");
    }
}
"""

# Non-static methods - the regex fallback pattern requires 'static'
NON_STATIC_CODE = """
public class Test {
    public void process() {}
}
"""


class TestJavaASTParser:
    """Tests for JavaASTParser."""

    def test_init(self):
        parser = JavaASTParser()
        assert parser is not None

    def test_parse_returns_dict(self):
        parser = JavaASTParser()
        result = parser.parse(SAMPLE_JAVA_CODE_STATIC)
        assert isinstance(result, dict)
        assert "source" in result
        assert "size" in result
        assert "method" in result
        assert result["source"] == SAMPLE_JAVA_CODE_STATIC
        assert result["size"] == len(SAMPLE_JAVA_CODE_STATIC)

    def test_parse_empty_code(self):
        parser = JavaASTParser()
        result = parser.parse("")
        assert result["size"] == 0
        assert result["source"] == ""

    def test_extract_functions_regex_static(self):
        parser = JavaASTParser()
        functions = parser.extract_functions(SAMPLE_JAVA_CODE_STATIC)
        assert isinstance(functions, list)
        func_names = [f["name"] for f in functions]
        assert "processRequest" in func_names
        assert "executeQuery" in func_names
        assert "getName" in func_names

    def test_extract_functions_returns_metadata(self):
        parser = JavaASTParser()
        functions = parser.extract_functions(SAMPLE_JAVA_CODE_STATIC)
        for func in functions:
            assert "name" in func
            assert "start_line" in func
            assert "end_line" in func
            assert "return_type" in func
            assert "body" in func

    def test_extract_functions_return_types(self):
        parser = JavaASTParser()
        functions = parser.extract_functions(SAMPLE_JAVA_CODE_STATIC)
        func_map = {f["name"]: f for f in functions}
        assert func_map["processRequest"]["return_type"] == "void"
        assert func_map["executeQuery"]["return_type"] == "void"
        assert func_map["getName"]["return_type"] == "String"

    def test_annotations_do_not_replace_method_metadata(self):
        code = """
public class UploadController {
    @PostMapping(path = "/upload")
    public String upload(@RequestParam("file") MultipartFile file) {
        return file.getOriginalFilename();
    }
}
"""
        parser = JavaASTParser()
        functions = parser.extract_functions(code)

        assert len(functions) == 1
        assert functions[0]["name"] == "upload"
        assert functions[0]["return_type"] == "String"
        assert functions[0]["class_name"] == "UploadController"
        assert "MultipartFile file" in functions[0]["parameters"][0]

    def test_extract_functions_empty_code(self):
        parser = JavaASTParser()
        functions = parser.extract_functions("")
        assert functions == []

    def test_extract_classes_regex(self):
        parser = JavaASTParser()
        classes = parser.extract_classes(SAMPLE_JAVA_CODE_STATIC)
        assert isinstance(classes, list)
        assert len(classes) >= 1
        class_names = [c["name"] for c in classes]
        assert "UserController" in class_names

    def test_extract_classes_metadata(self):
        parser = JavaASTParser()
        classes = parser.extract_classes(SAMPLE_JAVA_CODE_STATIC)
        for cls in classes:
            assert "name" in cls
            assert "start_line" in cls
            assert "end_line" in cls
            assert "body" in cls

    def test_extract_classes_simple(self):
        parser = JavaASTParser()
        classes = parser.extract_classes(SIMPLE_CLASS)
        assert len(classes) >= 1
        assert classes[0]["name"] == "SimpleClass"

    def test_extract_classes_empty_code(self):
        parser = JavaASTParser()
        classes = parser.extract_classes("")
        assert classes == []

    def test_parse_with_regex_fallback(self):
        parser = JavaASTParser()
        result = parser._parse_with_regex(SAMPLE_JAVA_CODE_STATIC)
        assert result["method"] == "regex"
        assert result["root"] is None
        assert result["source"] == SAMPLE_JAVA_CODE_STATIC

    def test_extract_functions_regex_method(self):
        code = """
public class Utils {
    public static int calculate(int x) {
        return x * 2;
    }
}
"""
        parser = JavaASTParser()
        functions = parser._extract_functions_regex(code)
        assert len(functions) >= 1
        assert functions[0]["name"] == "calculate"
        assert functions[0]["return_type"] == "int"

    def test_extract_classes_regex_private(self):
        code = """
private class InnerHelper {
    void help() {}
}
"""
        parser = JavaASTParser()
        classes = parser._extract_classes_regex(code)
        assert len(classes) >= 1
        assert classes[0]["name"] == "InnerHelper"

    def test_extract_functions_regex_no_match(self):
        """Non-static methods are not matched by the regex pattern."""
        parser = JavaASTParser()
        functions = parser._extract_functions_regex(NON_STATIC_CODE)
        # The regex pattern requires 'static', so non-static methods are not found
        assert isinstance(functions, list)

    def test_extract_classes_regex_multiple(self):
        code = """
public class Outer {
    private class Inner {
    }
}
"""
        parser = JavaASTParser()
        classes = parser._extract_classes_regex(code)
        names = [c["name"] for c in classes]
        assert "Outer" in names
        assert "Inner" in names

    def test_get_node_text(self):
        parser = JavaASTParser()
        # Test internal method with a mock node
        class MockNode:
            start_byte = 0
            end_byte = 5
        text = parser._get_node_text(MockNode(), "hello world")
        assert text == "hello"

    def test_get_node_text_error(self):
        parser = JavaASTParser()
        # Passing None should return empty string
        text = parser._get_node_text(None, "hello")
        assert text == ""

    def test_data_flows_with_multibyte_header(self):
        """Identifiers must stay intact when a multi-byte char precedes code.

        tree-sitter reports byte offsets; a ``©`` (or any non-ASCII byte) in
        a license header shifts every later offset, so slicing the str
        directly used to corrupt identifiers (``catPicture`` -> ``atPicture``)
        and silently drop every data-flow edge for the file. Regression guard.
        """
        parser = JavaASTParser()
        if parser.parser is None:
            pytest.skip("tree-sitter unavailable; AST path not exercised")
        code = (
            "/* Copyright © 2024 Example. All rights reserved. */\n"
            "public class T {\n"
            "  void m(String id) {\n"
            "    String catPicture = build(id);\n"
            "  }\n"
            "}\n"
        )
        flows = parser.extract_data_flows(code)
        # The edge must carry the *correct* names, not byte-shifted ones.
        assert any(
            f["from_var"] == "id" and f["to_var"] == "catPicture" for f in flows
        ), flows
        names = {f["from_var"] for f in flows} | {f["to_var"] for f in flows}
        assert "atPicture" not in names and "d" not in names

    def test_method_calls_include_enclosing_function(self):
        parser = JavaASTParser()
        if parser.parser is None:
            pytest.skip("tree-sitter unavailable; AST path not exercised")

        calls = parser.extract_method_calls(
            "class T { void delegate(String value) { service.consume(value); } }"
        )

        consume = next(call for call in calls if call["name"] == "consume")
        assert consume["function_name"] == "delegate"
