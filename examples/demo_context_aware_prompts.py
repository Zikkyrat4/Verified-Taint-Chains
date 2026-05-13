#!/usr/bin/env python3
"""
Demonstration of context-aware LLM prompts with AST information.

This script shows how the enhanced prompt templates incorporate:
1. Function signatures and parameters
2. Class information (extends, implements)
3. Import statements and relevant libraries
4. Context-aware vulnerability detection
"""

from src.stage1_llm_inference.prompt_templates import (
    build_source_prompt,
    build_sink_prompt,
)


def demo_basic_source_prompt():
    """Demonstrate source detection with context."""
    code = """String userInput = request.getParameter("username");
String query = "SELECT * FROM users WHERE name='" + userInput + "'";"""

    function_info = {
        "name": "searchUser",
        "return_type": "ResultSet",
        "parameters": ["HttpServletRequest request"],
    }

    class_info = {
        "name": "UserSearchService",
        "extends": "BaseService",
        "implements": ["Serializable"],
    }

    imports = [
        "javax.servlet.http.HttpServletRequest",
        "java.sql.ResultSet",
        "java.sql.Connection",
    ]

    prompt = build_source_prompt(
        code=code,
        function_info=function_info,
        class_info=class_info,
        imports=imports,
    )

    print("=" * 80)
    print("SOURCE DETECTION PROMPT WITH CONTEXT")
    print("=" * 80)
    print(prompt)
    print()


def demo_sink_prompt_with_context():
    """Demonstrate sink detection with context."""
    code = """Statement stmt = connection.createStatement();
String table = request.getParameter("table");
String where = request.getParameter("where");
stmt.execute("SELECT * FROM " + table + " WHERE " + where);"""

    function_info = {
        "name": "dynamicQuery",
        "return_type": "void",
        "parameters": ["HttpServletRequest request"],
    }

    class_info = {
        "name": "DatabaseAPI",
        "extends": None,
        "implements": [],
    }

    imports = [
        "java.sql.Statement",
        "java.sql.Connection",
        "javax.servlet.http.HttpServletRequest",
    ]

    prompt = build_sink_prompt(
        code=code,
        function_info=function_info,
        class_info=class_info,
        imports=imports,
    )

    print("=" * 80)
    print("SINK DETECTION PROMPT WITH CONTEXT")
    print("=" * 80)
    print(prompt)
    print()


def demo_minimal_context():
    """Demonstrate prompts with minimal context (fallback)."""
    code = """String data = getInput();
processData(data);"""

    prompt = build_source_prompt(code=code)

    print("=" * 80)
    print("SOURCE DETECTION WITH MINIMAL CONTEXT (BACKWARDS COMPATIBLE)")
    print("=" * 80)
    print(prompt)
    print()


def demo_context_without_class():
    """Demonstrate prompts with function context but no class."""
    code = """public String sanitizeInput(String input) {
    return input.replaceAll("[^a-zA-Z0-9]", "");
}"""

    function_info = {
        "name": "sanitizeInput",
        "return_type": "String",
        "parameters": ["String input"],
    }

    imports = ["java.util.regex.Pattern"]

    prompt = build_source_prompt(
        code=code,
        function_info=function_info,
        class_info=None,
        imports=imports,
    )

    print("=" * 80)
    print("SOURCE DETECTION WITH PARTIAL CONTEXT (FUNCTION ONLY)")
    print("=" * 80)
    print(prompt)
    print()


if __name__ == "__main__":
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 15 + "CONTEXT-AWARE LLM PROMPT DEMONSTRATION" + " " * 24 + "║")
    print("╚" + "=" * 78 + "╝")
    print()

    print("This demonstration shows how AST context improves LLM-based security analysis.")
    print()

    demo_basic_source_prompt()
    demo_sink_prompt_with_context()
    demo_context_without_class()
    demo_minimal_context()

    print("=" * 80)
    print("KEY IMPROVEMENTS WITH CONTEXT-AWARE PROMPTS:")
    print("=" * 80)
    print("""
1. CLASS CONTEXT:
   - LLM understands if class extends frameworks (Servlet, Spring, etc.)
   - Knows what interfaces are implemented
   - Can apply framework-specific security knowledge

2. FUNCTION SIGNATURE:
   - Parameter types inform about data sources
   - Return types clarify data flow
   - Method names suggest security-critical operations

3. IMPORT STATEMENTS:
   - LLM knows which security libraries are imported
   - Can recognize ORM frameworks, validation libraries
   - Understands security utility usage

4. PARAMETER TYPES:
   - HttpServletRequest parameters likely contain untrusted data
   - ResultSet, Stream parameters suggest data sources
   - Connection parameters indicate database operations

These enhancements significantly improve detection accuracy without requiring
the LLM to parse Java code directly. The pipeline handles parsing with tree-sitter,
and the LLM focuses on security analysis with better contextual information.
    """)
