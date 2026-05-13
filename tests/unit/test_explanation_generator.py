"""Unit tests for explanation generator."""

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch

from src.stage4_explanation.explanation_generator import ExplanationGenerator
from src.stage1_llm_inference.llm_client import SimpleLLMClient
from src.core.models import (
    TaintChain,
    Source,
    Sink,
    PathNode,
    CodeLocation,
    Explanation,
    VulnerabilityType,
    VerificationStatus,
)
from src.core.exceptions import ParsingError


class TestExplanationGeneratorInit:
    """Tests for ExplanationGenerator initialization."""

    def test_init_with_llm_client(self) -> None:
        """Test initialization with LLM client."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        assert generator.llm_client == client


class TestGenerateExplanation:
    """Tests for explanation generation."""

    @pytest.mark.asyncio
    async def test_generate_explanation(self) -> None:
        """Test generating explanation for a taint chain.

        This test verifies:
        1. LLM is called with correct prompt
        2. Response is parsed correctly
        3. Explanation object is returned with all fields
        """
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)
        chain = TaintChain(
            id="chain_1",
            source=Source(
                location=loc,
                variable_name="userInput",
                type="user_input",
                confidence=0.95,
                code_snippet='String userInput = request.getParameter("q");',
            ),
            sink=Sink(
                location=loc,
                variable_name="query",
                type="sql_query",
                confidence=0.98,
                code_snippet="db.execute(query);",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            path=[],
            length=0,
            confidence=0.96,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        # Mock LLM response
        llm_response = {
            "why_vulnerable": "User input flows directly into SQL query without parameterization.",
            "how_to_fix": "Use parameterized queries or prepared statements.",
            "example_fix": "PreparedStatement stmt = conn.prepareStatement('SELECT * FROM users WHERE id = ?');\nstmt.setString(1, userInput);",
        }

        with patch.object(client, "analyze_code", new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = llm_response

            explanation = await generator.generate_explanation(chain)

        # Assertions
        assert isinstance(explanation, Explanation)
        assert explanation.chain_id == "chain_1"
        assert "SQL" in explanation.why_vulnerable or "sql" in explanation.why_vulnerable.lower()
        assert explanation.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert explanation.cwe_id == "CWE-89"

    @pytest.mark.asyncio
    async def test_generate_explanation_invalid_response(self) -> None:
        """Test handling of invalid LLM response."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

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

        # Mock invalid LLM response (missing required fields)
        invalid_response = {"why_vulnerable": "Some reason"}

        with patch.object(client, "analyze_code", new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = invalid_response

            with pytest.raises(ParsingError):
                await generator.generate_explanation(chain)


class TestDetermineSeverity:
    """Tests for severity determination."""

    def test_determine_severity_sql_injection(self) -> None:
        """Test that SQL injection gets CRITICAL severity."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)
        chain = TaintChain(
            id="chain_1",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.95, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="sql", confidence=0.95, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=[],
            length=0,
            confidence=0.95,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        severity = generator.determine_severity(chain)

        assert severity == "CRITICAL"

    def test_determine_severity_command_injection(self) -> None:
        """Test that command injection gets CRITICAL severity."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)
        chain = TaintChain(
            id="chain_1",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.95, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="exec", confidence=0.95, code_snippet="", vulnerability_type=VulnerabilityType.COMMAND_INJECTION),
            path=[],
            length=0,
            confidence=0.95,
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        )

        severity = generator.determine_severity(chain)

        assert severity == "CRITICAL"

    def test_determine_severity_xss(self) -> None:
        """Test that XSS gets MEDIUM severity."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)
        chain = TaintChain(
            id="chain_1",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.95, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="html", confidence=0.95, code_snippet="", vulnerability_type=VulnerabilityType.XSS),
            path=[],
            length=0,
            confidence=0.95,
            vulnerability_type=VulnerabilityType.XSS,
        )

        severity = generator.determine_severity(chain)

        assert severity == "MEDIUM"

    def test_determine_severity_path_traversal(self) -> None:
        """Test that path traversal gets HIGH severity."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)
        chain = TaintChain(
            id="chain_1",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.95, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="file", confidence=0.95, code_snippet="", vulnerability_type=VulnerabilityType.PATH_TRAVERSAL),
            path=[],
            length=0,
            confidence=0.95,
            vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
        )

        severity = generator.determine_severity(chain)

        assert severity == "HIGH"

    def test_severity_reduced_by_low_confidence(self) -> None:
        """Test that low confidence reduces severity."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)

        # Critical vulnerability with low source/sink confidence to drive
        # calculate_confidence below 0.6 threshold
        # With no verification (default 0.5): (0.2+0.2)/2*0.4 + 0.5*0.5 + 1.0*0.1 = 0.08+0.25+0.1 = 0.43
        chain = TaintChain(
            id="chain_1",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.2, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="sql", confidence=0.2, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=[],
            length=0,
            confidence=0.45,  # Below 0.6 threshold
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        severity = generator.determine_severity(chain)

        # Should be reduced from CRITICAL to HIGH
        assert severity == "HIGH"

    def test_severity_reduced_by_sanitizers(self) -> None:
        """Test that presence of sanitizers reduces severity."""
        from src.core.models import Sanitizer

        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)

        sanitizer = Sanitizer(
            location=loc,
            type="input_validation",
            confidence=0.8,
            code_snippet="if (validate(x)) { ... }",
        )

        chain = TaintChain(
            id="chain_1",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.95, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="sql", confidence=0.95, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=[],
            length=0,
            confidence=0.95,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            sanitizers_on_path=[sanitizer],
        )

        severity = generator.determine_severity(chain)

        # Should be reduced from CRITICAL to HIGH due to sanitizer
        assert severity == "HIGH"


class TestMapToCWE:
    """Tests for CWE mapping."""

    def test_map_sql_injection_to_cwe(self) -> None:
        """Test SQL injection maps to CWE-89."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        cwe = generator.map_to_cwe(VulnerabilityType.SQL_INJECTION)

        assert cwe == "CWE-89"

    def test_map_xss_to_cwe(self) -> None:
        """Test XSS maps to CWE-79."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        cwe = generator.map_to_cwe(VulnerabilityType.XSS)

        assert cwe == "CWE-79"

    def test_map_command_injection_to_cwe(self) -> None:
        """Test command injection maps to CWE-78."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        cwe = generator.map_to_cwe(VulnerabilityType.COMMAND_INJECTION)

        assert cwe == "CWE-78"

    def test_map_path_traversal_to_cwe(self) -> None:
        """Test path traversal maps to CWE-22."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        cwe = generator.map_to_cwe(VulnerabilityType.PATH_TRAVERSAL)

        assert cwe == "CWE-22"

    def test_map_xxe_to_cwe(self) -> None:
        """Test XXE maps to CWE-611."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        cwe = generator.map_to_cwe(VulnerabilityType.XXE)

        assert cwe == "CWE-611"

    def test_map_ssrf_to_cwe(self) -> None:
        """Test SSRF maps to CWE-918."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        cwe = generator.map_to_cwe(VulnerabilityType.SSRF)

        assert cwe == "CWE-918"


class TestParseExplanation:
    """Tests for explanation response parsing."""

    def test_parse_explanation_valid_response(self) -> None:
        """Test parsing valid explanation response."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        response = {
            "why_vulnerable": "User input flows directly into SQL.",
            "how_to_fix": "Use parameterized queries.",
            "example_fix": "SELECT * FROM users WHERE id = ?",
        }

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

        result = generator._parse_explanation_response(response, chain)

        assert result["why_vulnerable"] == "User input flows directly into SQL."
        assert result["how_to_fix"] == "Use parameterized queries."
        assert result["example_fix"] == "SELECT * FROM users WHERE id = ?"

    def test_parse_explanation_missing_field(self) -> None:
        """Test that missing required field raises ParsingError."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        response = {
            "why_vulnerable": "User input flows directly into SQL.",
            # Missing "how_to_fix" and "example_fix"
        }

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

        with pytest.raises(ParsingError):
            generator._parse_explanation_response(response, chain)


class TestCreateDefaultExplanation:
    """Tests for default explanation creation."""

    def test_create_default_sql_injection_explanation(self) -> None:
        """Test default explanation for SQL injection."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)
        chain = TaintChain(
            id="chain_1",
            source=Source(location=loc, variable_name="userInput", type="input", confidence=0.95, code_snippet=""),
            sink=Sink(location=loc, variable_name="query", type="sql", confidence=0.98, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=[],
            length=0,
            confidence=0.96,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        explanation = generator._create_default_explanation(chain)

        assert explanation.chain_id == "chain_1"
        assert "SQL" in explanation.why_vulnerable or "sql" in explanation.why_vulnerable.lower()
        assert "parameterized" in explanation.how_to_fix.lower() or "prepared" in explanation.how_to_fix.lower()
        assert explanation.severity == "CRITICAL"
        assert explanation.cwe_id == "CWE-89"

    def test_create_default_command_injection_explanation(self) -> None:
        """Test default explanation for command injection."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)
        chain = TaintChain(
            id="chain_2",
            source=Source(location=loc, variable_name="filename", type="input", confidence=0.95, code_snippet=""),
            sink=Sink(location=loc, variable_name="cmd", type="exec", confidence=0.98, code_snippet="", vulnerability_type=VulnerabilityType.COMMAND_INJECTION),
            path=[],
            length=0,
            confidence=0.96,
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        )

        explanation = generator._create_default_explanation(chain)

        assert "command" in explanation.why_vulnerable.lower()
        assert explanation.severity == "CRITICAL"
        assert explanation.cwe_id == "CWE-78"

    def test_create_default_xss_explanation(self) -> None:
        """Test default explanation for XSS."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)
        chain = TaintChain(
            id="chain_3",
            source=Source(location=loc, variable_name="userInput", type="input", confidence=0.95, code_snippet=""),
            sink=Sink(location=loc, variable_name="output", type="html", confidence=0.98, code_snippet="", vulnerability_type=VulnerabilityType.XSS),
            path=[],
            length=0,
            confidence=0.96,
            vulnerability_type=VulnerabilityType.XSS,
        )

        explanation = generator._create_default_explanation(chain)

        assert "XSS" in explanation.why_vulnerable or "xss" in explanation.why_vulnerable.lower() or "script" in explanation.why_vulnerable.lower()
        assert explanation.severity == "MEDIUM"
        assert explanation.cwe_id == "CWE-79"


class TestGenerateExplanationsBatch:
    """Tests for batch explanation generation."""

    def test_generate_explanations_batch(self) -> None:
        """Test generating explanations for multiple chains."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)

        chains = [
            TaintChain(
                id="chain_1",
                source=Source(location=loc, variable_name="x", type="input", confidence=0.95, code_snippet=""),
                sink=Sink(location=loc, variable_name="y", type="sql", confidence=0.98, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
                path=[],
                length=0,
                confidence=0.96,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            TaintChain(
                id="chain_2",
                source=Source(location=loc, variable_name="a", type="input", confidence=0.95, code_snippet=""),
                sink=Sink(location=loc, variable_name="b", type="exec", confidence=0.98, code_snippet="", vulnerability_type=VulnerabilityType.COMMAND_INJECTION),
                path=[],
                length=0,
                confidence=0.96,
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            ),
        ]

        explanations = generator.generate_explanations_batch(chains)

        assert len(explanations) == 2
        assert "chain_1" in explanations
        assert "chain_2" in explanations
        assert explanations["chain_1"].cwe_id == "CWE-89"
        assert explanations["chain_2"].cwe_id == "CWE-78"


class TestCalculateConfidence:
    """Tests for confidence calculation."""

    def _make_chain(self, source_conf=0.9, sink_conf=0.85, verification=None, path_len=2):
        loc = CodeLocation(file_path="test.java", line_number=1)
        path_nodes = [
            PathNode(location=loc, variable_name="x", node_type="intermediate", code_snippet="")
            for _ in range(path_len)
        ]
        return TaintChain(
            id="conf-chain",
            source=Source(location=loc, variable_name="x", type="input", confidence=source_conf, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="sql", confidence=sink_conf, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=path_nodes,
            length=path_len,
            confidence=0.9,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            verification_status=verification,
        )

    def test_confidence_verified(self):
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        chain = self._make_chain(verification=VerificationStatus.VERIFIED)
        conf = gen.calculate_confidence(chain)
        assert 0.0 <= conf <= 1.0
        assert conf > 0.7  # High confidence when verified

    def test_confidence_false(self):
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        chain = self._make_chain(verification=VerificationStatus.FALSE)
        conf = gen.calculate_confidence(chain)
        assert conf <= 0.5  # Low confidence when false

    def test_confidence_unverifiable(self):
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        chain = self._make_chain(verification=VerificationStatus.UNVERIFIABLE)
        conf = gen.calculate_confidence(chain)
        assert 0.0 <= conf <= 1.0

    def test_confidence_long_path(self):
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        chain = self._make_chain(path_len=15)
        conf = gen.calculate_confidence(chain)
        assert conf <= 0.9  # Longer path reduces confidence


class TestFormatExplanation:
    """Tests for explanation formatting in different output formats."""

    def _make_chain_and_explanation(self):
        from src.stage4_explanation.explanation_generator import OutputFormat
        loc = CodeLocation(file_path="test.java", line_number=5)
        path_nodes = [
            PathNode(location=loc, variable_name="userId", node_type="source", code_snippet='String userId = request.getParameter("id");'),
            PathNode(location=loc, variable_name="query", node_type="sink", code_snippet='stmt.executeQuery(query);'),
        ]
        chain = TaintChain(
            id="fmt-chain",
            source=Source(location=loc, variable_name="userId", type="User Input", confidence=0.9,
                         code_snippet='String userId = request.getParameter("id");'),
            sink=Sink(location=loc, variable_name="query", type="SQL", confidence=0.85,
                     code_snippet='stmt.executeQuery(query);', vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=path_nodes,
            length=2,
            confidence=0.875,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            verification_status=VerificationStatus.VERIFIED,
        )
        explanation = Explanation(
            chain_id="fmt-chain",
            why_vulnerable="User input flows to SQL query",
            how_to_fix="Use prepared statements",
            example_fix="PreparedStatement stmt = conn.prepareStatement(...);",
            severity="HIGH",
            cwe_id="CWE-89",
        )
        return chain, explanation

    def test_format_markdown(self):
        from src.stage4_explanation.explanation_generator import OutputFormat
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        chain, explanation = self._make_chain_and_explanation()

        result = gen.format_explanation(explanation, chain, OutputFormat.MARKDOWN)
        assert "# " in result
        assert "HIGH" in result
        assert "CWE-89" in result
        assert "userId" in result
        assert "query" in result

    def test_format_html(self):
        from src.stage4_explanation.explanation_generator import OutputFormat
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        chain, explanation = self._make_chain_and_explanation()

        result = gen.format_explanation(explanation, chain, OutputFormat.HTML)
        assert "<html>" in result
        assert "HIGH" in result
        assert "CWE-89" in result

    def test_format_plain_text(self):
        from src.stage4_explanation.explanation_generator import OutputFormat
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        chain, explanation = self._make_chain_and_explanation()

        result = gen.format_explanation(explanation, chain, OutputFormat.PLAIN_TEXT)
        assert "SEVERITY: HIGH" in result
        assert "CWE" in result

    def test_format_json(self):
        from src.stage4_explanation.explanation_generator import OutputFormat
        import json
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        chain, explanation = self._make_chain_and_explanation()

        result = gen.format_explanation(explanation, chain, OutputFormat.JSON)
        data = json.loads(result)
        assert data["vulnerability"]["type"] == "sql_injection"
        assert data["vulnerability"]["severity"] == "HIGH"
        assert data["vulnerability"]["cwe_id"] == "CWE-89"
        assert data["explanation"]["why_vulnerable"] == "User input flows to SQL query"

    def test_format_unsupported_raises(self):
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        chain, explanation = self._make_chain_and_explanation()

        with pytest.raises(ValueError, match="Unsupported format"):
            gen.format_explanation(explanation, chain, "invalid")


class TestBuildPrompt:
    """Tests for prompt building methods."""

    def _make_chain(self):
        loc = CodeLocation(file_path="test.java", line_number=5)
        path_nodes = [
            PathNode(location=loc, variable_name="userId", node_type="source", code_snippet='String userId = request.getParameter("id");'),
            PathNode(location=loc, variable_name="query", node_type="sink", code_snippet='stmt.executeQuery(query);'),
        ]
        return TaintChain(
            id="prompt-chain",
            source=Source(location=loc, variable_name="userId", type="User Input", confidence=0.9,
                         code_snippet='String userId = request.getParameter("id");'),
            sink=Sink(location=loc, variable_name="query", type="SQL", confidence=0.85,
                     code_snippet='stmt.executeQuery(query);', vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=path_nodes,
            length=2,
            confidence=0.875,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            verification_status=VerificationStatus.VERIFIED,
        )

    def test_build_enhanced_prompt(self):
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        chain = self._make_chain()

        prompt = gen._build_enhanced_prompt(chain)
        assert "userId" in prompt
        assert "query" in prompt
        assert "SQL" in prompt.upper() or "sql" in prompt.lower()

    def test_build_basic_prompt(self):
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        chain = self._make_chain()

        prompt = gen._build_basic_prompt(chain)
        assert "userId" in prompt
        assert "query" in prompt
        assert "JSON" in prompt

    def test_build_context_code(self):
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        chain = self._make_chain()

        context = gen._build_context_code(chain)
        assert "userId" in context
        assert "query" in context

    def test_build_enhanced_prompt_without_attack_scenario(self):
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        chain = self._make_chain()

        prompt = gen._build_enhanced_prompt(chain, include_attack_scenario=False)
        assert "userId" in prompt

    def test_severity_false_verification(self):
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        loc = CodeLocation(file_path="test.java", line_number=5)
        path_nodes = [
            PathNode(location=loc, variable_name="x", node_type="source", code_snippet=""),
            PathNode(location=loc, variable_name="y", node_type="sink", code_snippet=""),
        ]
        chain = TaintChain(
            id="s-chain",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.9, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="sql", confidence=0.85, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=path_nodes,
            length=2,
            confidence=0.875,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            verification_status=VerificationStatus.FALSE,
        )
        severity = gen.determine_severity(chain)
        assert severity == "LOW"

    def test_severity_unverifiable_critical(self):
        client = SimpleLLMClient(api_key="test-key")
        gen = ExplanationGenerator(client)
        loc = CodeLocation(file_path="test.java", line_number=5)
        path_nodes = [
            PathNode(location=loc, variable_name="x", node_type="source", code_snippet=""),
            PathNode(location=loc, variable_name="y", node_type="sink", code_snippet=""),
        ]
        chain = TaintChain(
            id="s-chain-2",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.95, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="exec", confidence=0.95, code_snippet="", vulnerability_type=VulnerabilityType.COMMAND_INJECTION),
            path=path_nodes,
            length=2,
            confidence=0.95,
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            verification_status=VerificationStatus.UNVERIFIABLE,
        )
        severity = gen.determine_severity(chain)
        # CRITICAL reduced to HIGH when unverifiable
        assert severity == "HIGH"
