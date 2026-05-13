"""Unit tests for prompt templates."""

import pytest
import json

from src.stage1_llm_inference.prompt_templates import (
    SIMPLE_SOURCE_PROMPT,
    SIMPLE_SINK_PROMPT,
    COMBINED_ANALYSIS_PROMPT,
    SANITIZER_DETECTION_PROMPT,
    build_source_prompt,
    build_sink_prompt,
    build_combined_prompt,
    build_sanitizer_prompt,
)


class TestPromptTemplateContent:
    """Tests for prompt template content."""

    def test_source_prompt_contains_json_format(self) -> None:
        """Test that source prompt contains expected JSON structure."""
        assert "sources" in SIMPLE_SOURCE_PROMPT
        assert "line" in SIMPLE_SOURCE_PROMPT
        assert "variable" in SIMPLE_SOURCE_PROMPT
        assert "type" in SIMPLE_SOURCE_PROMPT
        assert "confidence" in SIMPLE_SOURCE_PROMPT

    def test_sink_prompt_contains_json_format(self) -> None:
        """Test that sink prompt contains expected JSON structure."""
        assert "sinks" in SIMPLE_SINK_PROMPT
        assert "line" in SIMPLE_SINK_PROMPT
        assert "variable" in SIMPLE_SINK_PROMPT
        assert "type" in SIMPLE_SINK_PROMPT
        assert "vulnerability_type" in SIMPLE_SINK_PROMPT

    def test_combined_prompt_contains_both(self) -> None:
        """Test that combined prompt contains both sources and sinks."""
        assert "sources" in COMBINED_ANALYSIS_PROMPT
        assert "sinks" in COMBINED_ANALYSIS_PROMPT

    def test_sanitizer_prompt_contains_format(self) -> None:
        """Test that sanitizer prompt contains expected structure."""
        assert "sanitizers" in SANITIZER_DETECTION_PROMPT
        assert "type" in SANITIZER_DETECTION_PROMPT
        assert "effectiveness" in SANITIZER_DETECTION_PROMPT


class TestBuildSourcePrompt:
    """Tests for build_source_prompt function."""

    def test_build_source_prompt_success(self) -> None:
        """Test successful source prompt building."""
        code = "String user_input = request.getParameter('q');"
        prompt = build_source_prompt(code)

        assert code in prompt
        assert "sources" in prompt
        assert "{code}" not in prompt  # Ensure code was interpolated

    def test_build_source_prompt_with_multiline_code(self) -> None:
        """Test building prompt with multiline code."""
        code = """String user_input = request.getParameter('q');
        String processed = process(user_input);"""
        prompt = build_source_prompt(code)

        assert code in prompt
        assert "sources" in prompt

    def test_build_source_prompt_empty_code(self) -> None:
        """Test that empty code raises ValueError."""
        with pytest.raises(ValueError, match="code cannot be empty"):
            build_source_prompt("")

    def test_build_source_prompt_whitespace_only(self) -> None:
        """Test that whitespace-only code raises ValueError."""
        with pytest.raises(ValueError, match="code cannot be empty"):
            build_source_prompt("   \n\t  ")


class TestBuildSinkPrompt:
    """Tests for build_sink_prompt function."""

    def test_build_sink_prompt_success(self) -> None:
        """Test successful sink prompt building."""
        code = "stmt.executeQuery(query);"
        prompt = build_sink_prompt(code)

        assert code in prompt
        assert "sinks" in prompt
        assert "{code}" not in prompt

    def test_build_sink_prompt_with_multiline_code(self) -> None:
        """Test building prompt with multiline code."""
        code = """String query = "SELECT * FROM users WHERE id = " + user_id;
        ResultSet rs = stmt.executeQuery(query);"""
        prompt = build_sink_prompt(code)

        assert code in prompt
        assert "sinks" in prompt

    def test_build_sink_prompt_empty_code(self) -> None:
        """Test that empty code raises ValueError."""
        with pytest.raises(ValueError, match="code cannot be empty"):
            build_sink_prompt("")


class TestBuildCombinedPrompt:
    """Tests for build_combined_prompt function."""

    def test_build_combined_prompt_success(self) -> None:
        """Test successful combined prompt building."""
        code = """String user_input = request.getParameter('q');
        stmt.executeQuery(user_input);"""
        prompt = build_combined_prompt(code)

        assert code in prompt
        assert "sources" in prompt
        assert "sinks" in prompt
        assert "{code}" not in prompt

    def test_build_combined_prompt_empty_code(self) -> None:
        """Test that empty code raises ValueError."""
        with pytest.raises(ValueError, match="code cannot be empty"):
            build_combined_prompt("")


class TestBuildSanitizerPrompt:
    """Tests for build_sanitizer_prompt function."""

    def test_build_sanitizer_prompt_success(self) -> None:
        """Test successful sanitizer prompt building."""
        code = "if (validate(user_input)) { query = user_input; }"
        prompt = build_sanitizer_prompt(code)

        assert code in prompt
        assert "sanitizers" in prompt
        assert "{code}" not in prompt

    def test_build_sanitizer_prompt_empty_code(self) -> None:
        """Test that empty code raises ValueError."""
        with pytest.raises(ValueError, match="code cannot be empty"):
            build_sanitizer_prompt("")


class TestPromptConsistency:
    """Tests for consistency across prompts."""

    def test_all_prompts_request_json(self) -> None:
        """Test that all prompts explicitly request JSON output."""
        for prompt in [
            SIMPLE_SOURCE_PROMPT,
            SIMPLE_SINK_PROMPT,
            COMBINED_ANALYSIS_PROMPT,
            SANITIZER_DETECTION_PROMPT,
        ]:
            assert "JSON" in prompt or "json" in prompt

    def test_all_prompts_have_code_placeholder(self) -> None:
        """Test that all templates have {code} placeholder."""
        for prompt in [
            SIMPLE_SOURCE_PROMPT,
            SIMPLE_SINK_PROMPT,
            COMBINED_ANALYSIS_PROMPT,
            SANITIZER_DETECTION_PROMPT,
        ]:
            assert "{code}" in prompt

    def test_source_sink_prompts_mention_confidence(self) -> None:
        """Test that source and sink prompts mention confidence."""
        assert "confidence" in SIMPLE_SOURCE_PROMPT
        assert "confidence" in SIMPLE_SINK_PROMPT


class TestPromptQuality:
    """Tests for prompt quality and structure."""

    def test_source_prompt_mentions_untrusted_data(self) -> None:
        """Test that source prompt mentions untrusted data concept."""
        assert "untrusted" in SIMPLE_SOURCE_PROMPT.lower() or "user input" in SIMPLE_SOURCE_PROMPT.lower()

    def test_sink_prompt_mentions_harmful_operations(self) -> None:
        """Test that sink prompt mentions dangerous operations."""
        assert "SQL" in SIMPLE_SINK_PROMPT or "dangerous" in SIMPLE_SINK_PROMPT.lower()

    def test_prompts_specify_return_json_only(self) -> None:
        """Test that prompts specify to return ONLY JSON."""
        for prompt in [SIMPLE_SOURCE_PROMPT, SIMPLE_SINK_PROMPT]:
            assert "ONLY" in prompt and ("JSON" in prompt or "json" in prompt)


class TestRealWorldCodeExamples:
    """Tests with realistic Java code examples."""

    def test_source_prompt_with_servlet_code(self) -> None:
        """Test source prompt with servlet code example."""
        code = """
        HttpServletRequest request = getRequest();
        String userName = request.getParameter("username");
        String password = request.getParameter("password");
        """
        prompt = build_source_prompt(code)
        assert "username" in prompt
        assert "password" in prompt

    def test_sink_prompt_with_sql_code(self) -> None:
        """Test sink prompt with SQL code example."""
        code = """
        String userId = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = " + userId;
        ResultSet rs = statement.executeQuery(query);
        """
        prompt = build_sink_prompt(code)
        assert "executeQuery" in prompt

    def test_combined_prompt_with_injection_vulnerability(self) -> None:
        """Test combined prompt with SQL injection vulnerability."""
        code = """
        String userInput = request.getParameter("search");
        String query = "SELECT * FROM products WHERE name LIKE '%" + userInput + "%'";
        ResultSet results = db.executeQuery(query);
        """
        prompt = build_combined_prompt(code)
        assert "userInput" in prompt
        assert "executeQuery" in prompt
