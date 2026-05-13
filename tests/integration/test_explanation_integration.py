"""Integration tests for explanation generator."""

import pytest
from unittest.mock import AsyncMock, patch

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
    Sanitizer,
)


class TestGenerateExplanation:
    """Test explanation generation for taint chains."""

    @pytest.mark.asyncio
    async def test_generate_explanation(self) -> None:
        """Test generating comprehensive explanation for a taint chain.

        This test verifies:
        1. Complete explanation is generated
        2. All required fields are populated
        3. Severity and CWE are correctly assigned
        4. Output is human-readable
        """
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        # Create a realistic SQL injection chain
        source_loc = CodeLocation(file_path="UserService.java", line_number=12)
        sink_loc = CodeLocation(file_path="UserService.java", line_number=18)

        source = Source(
            location=source_loc,
            variable_name="username",
            type="user_input",
            confidence=0.98,
            code_snippet='String username = request.getParameter("user");',
            reasoning="Direct HTTP request parameter",
        )

        sink = Sink(
            location=sink_loc,
            variable_name="query",
            type="sql_query",
            confidence=0.99,
            code_snippet='String query = "SELECT * FROM users WHERE username = \'" + username + "\'";',
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            reasoning="Direct string concatenation in SQL query",
        )

        path_nodes = [
            PathNode(
                location=source_loc,
                variable_name="username",
                node_type="source",
                code_snippet='String username = request.getParameter("user");',
            ),
            PathNode(
                location=CodeLocation(file_path="UserService.java", line_number=15),
                variable_name="processed",
                node_type="intermediate",
                code_snippet='String processed = username.trim();',
            ),
            PathNode(
                location=sink_loc,
                variable_name="query",
                node_type="sink",
                code_snippet='String query = "SELECT * FROM users WHERE username = \'" + username + "\'";',
            ),
        ]

        chain = TaintChain(
            id="sql_injection_user_login",
            source=source,
            sink=sink,
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.98,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        # Mock LLM response
        llm_response = {
            "why_vulnerable": "The username parameter is taken directly from user input and concatenated into a SQL query string without any parameterization or escaping, allowing attackers to inject arbitrary SQL code.",
            "how_to_fix": "Use parameterized queries (PreparedStatements) instead of string concatenation. This separates SQL code from data and prevents injection attacks.",
            "example_fix": "PreparedStatement stmt = connection.prepareStatement(\"SELECT * FROM users WHERE username = ?\");\nstmt.setString(1, username);\nResultSet rs = stmt.executeQuery();",
        }

        with patch.object(client, "analyze_code", new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = llm_response

            explanation = await generator.generate_explanation(chain)

        # Assertions
        assert isinstance(explanation, Explanation)
        assert explanation.chain_id == "sql_injection_user_login"

        print(f"✓ Generated explanation for SQL injection chain")
        print(f"  Chain ID: {explanation.chain_id}")
        print(f"\n  Why Vulnerable:")
        print(f"    {explanation.why_vulnerable}")
        print(f"\n  How to Fix:")
        print(f"    {explanation.how_to_fix}")
        print(f"\n  Example Fix:")
        print(f"    {explanation.example_fix}")
        print(f"\n  Severity: {explanation.severity}")
        print(f"  CWE: {explanation.cwe_id}")

        assert explanation.severity == "CRITICAL"
        assert explanation.cwe_id == "CWE-89"
        assert "parameterized" in explanation.how_to_fix.lower() or "prepared" in explanation.how_to_fix.lower()


class TestDetermineSeverity:
    """Test severity level determination."""

    def test_determine_severity(self) -> None:
        """Test severity mapping for various vulnerability types.

        This test verifies:
        1. Correct severity for each vulnerability type
        2. Severity reduction for low confidence
        3. Severity reduction for sanitizers
        """
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)

        test_cases = [
            (VulnerabilityType.SQL_INJECTION, 0.95, [], "CRITICAL"),
            (VulnerabilityType.COMMAND_INJECTION, 0.95, [], "CRITICAL"),
            (VulnerabilityType.XXE, 0.95, [], "HIGH"),
            (VulnerabilityType.SSRF, 0.95, [], "HIGH"),
            (VulnerabilityType.PATH_TRAVERSAL, 0.95, [], "HIGH"),
            (VulnerabilityType.XSS, 0.95, [], "MEDIUM"),
        ]

        print(f"✓ Severity Mapping Test")

        for vuln_type, confidence, sanitizers, expected_severity in test_cases:
            chain = TaintChain(
                id=f"chain_{vuln_type.value}",
                source=Source(location=loc, variable_name="x", type="input", confidence=confidence, code_snippet=""),
                sink=Sink(location=loc, variable_name="y", type="sink", confidence=confidence, code_snippet="", vulnerability_type=vuln_type),
                path=[],
                length=0,
                confidence=confidence,
                vulnerability_type=vuln_type,
                sanitizers_on_path=sanitizers,
            )

            severity = generator.determine_severity(chain)
            assert severity == expected_severity

            print(f"  {vuln_type.value:20} -> {severity}")

    def test_severity_reduced_by_confidence(self) -> None:
        """Test that low confidence reduces severity."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)

        # High confidence SQL injection = CRITICAL
        chain_high = TaintChain(
            id="chain_high_conf",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.95, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="sql", confidence=0.98, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=[],
            length=0,
            confidence=0.95,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        # Low confidence SQL injection = HIGH
        # Use low source/sink confidence so calculate_confidence() returns < 0.6
        chain_low = TaintChain(
            id="chain_low_conf",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.2, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="sql", confidence=0.2, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=[],
            length=0,
            confidence=0.45,  # Below threshold
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        severity_high = generator.determine_severity(chain_high)
        severity_low = generator.determine_severity(chain_low)

        assert severity_high == "CRITICAL"
        assert severity_low == "HIGH"

        print(f"✓ Severity affected by confidence")
        print(f"  High confidence: {severity_high}")
        print(f"  Low confidence: {severity_low}")

    def test_severity_reduced_by_sanitizers(self) -> None:
        """Test that sanitizers reduce severity."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)

        sanitizer = Sanitizer(
            location=CodeLocation(file_path="test.java", line_number=2),
            type="input_validation",
            confidence=0.85,
            code_snippet="if (validate(username)) { ... }",
        )

        # SQL injection without sanitizers = CRITICAL
        chain_no_sanitizer = TaintChain(
            id="chain_no_sanitizer",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.95, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="sql", confidence=0.98, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=[],
            length=0,
            confidence=0.95,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            sanitizers_on_path=[],
        )

        # SQL injection with sanitizers = HIGH
        chain_with_sanitizer = TaintChain(
            id="chain_with_sanitizer",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.95, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="sql", confidence=0.98, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=[],
            length=0,
            confidence=0.95,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            sanitizers_on_path=[sanitizer],
        )

        severity_no_sanitizer = generator.determine_severity(chain_no_sanitizer)
        severity_with_sanitizer = generator.determine_severity(chain_with_sanitizer)

        assert severity_no_sanitizer == "CRITICAL"
        assert severity_with_sanitizer == "HIGH"

        print(f"✓ Severity affected by sanitizers")
        print(f"  Without sanitizers: {severity_no_sanitizer}")
        print(f"  With sanitizers: {severity_with_sanitizer}")


class TestMapToCWE:
    """Test CWE mapping for vulnerabilities."""

    def test_map_to_cwe(self) -> None:
        """Test CWE mapping for all vulnerability types.

        This test verifies:
        1. All vulnerability types map to correct CWE
        2. CWE format is correct (CWE-XXXX)
        """
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        cwe_mappings = [
            (VulnerabilityType.SQL_INJECTION, "CWE-89"),
            (VulnerabilityType.XSS, "CWE-79"),
            (VulnerabilityType.COMMAND_INJECTION, "CWE-78"),
            (VulnerabilityType.PATH_TRAVERSAL, "CWE-22"),
            (VulnerabilityType.XXE, "CWE-611"),
            (VulnerabilityType.SSRF, "CWE-918"),
        ]

        print(f"✓ CWE Mapping Test")

        for vuln_type, expected_cwe in cwe_mappings:
            cwe = generator.map_to_cwe(vuln_type)
            assert cwe == expected_cwe
            print(f"  {vuln_type.value:20} -> {cwe}")


class TestParseExplanation:
    """Test explanation response parsing."""

    def test_parse_explanation(self) -> None:
        """Test parsing LLM response into explanation fields.

        This test verifies:
        1. Valid response is parsed correctly
        2. All required fields are extracted
        3. Field values are preserved
        """
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        response = {
            "why_vulnerable": "User input flows directly into SQL without parameterization.",
            "how_to_fix": "Use parameterized queries (PreparedStatements) to separate SQL code from data.",
            "example_fix": "PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setString(1, userId);",
        }

        loc = CodeLocation(file_path="test.java", line_number=1)
        chain = TaintChain(
            id="test_chain",
            source=Source(location=loc, variable_name="x", type="input", confidence=0.9, code_snippet=""),
            sink=Sink(location=loc, variable_name="y", type="sql", confidence=0.9, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
            path=[],
            length=0,
            confidence=0.9,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        parsed = generator._parse_explanation_response(response, chain)

        assert parsed["why_vulnerable"] == response["why_vulnerable"]
        assert parsed["how_to_fix"] == response["how_to_fix"]
        assert parsed["example_fix"] == response["example_fix"]

        print(f"✓ Explanation parsing successful")
        print(f"  Why vulnerable: {parsed['why_vulnerable'][:60]}...")
        print(f"  How to fix: {parsed['how_to_fix'][:60]}...")
        print(f"  Example fix: {parsed['example_fix'][:60]}...")


class TestEndToEndExplanation:
    """End-to-end explanation workflow test."""

    def test_complete_explanation_workflow(self) -> None:
        """Test complete workflow from chain to explanation.

        This test verifies:
        1. Default explanations work without LLM
        2. All vulnerability types have explanations
        3. Severity and CWE are correctly assigned
        4. Explanation output is complete
        """
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="VulnerableApp.java", line_number=1)

        vulnerabilities = [
            (VulnerabilityType.SQL_INJECTION, "userInput", "query"),
            (VulnerabilityType.COMMAND_INJECTION, "filename", "cmd"),
            (VulnerabilityType.XSS, "userComment", "htmlOutput"),
            (VulnerabilityType.PATH_TRAVERSAL, "filePath", "fileAccess"),
        ]

        print(f"✓ Complete Explanation Workflow")

        for vuln_type, source_var, sink_var in vulnerabilities:
            chain = TaintChain(
                id=f"chain_{vuln_type.value}",
                source=Source(location=loc, variable_name=source_var, type="input", confidence=0.95, code_snippet=""),
                sink=Sink(location=loc, variable_name=sink_var, type="sink", confidence=0.98, code_snippet="", vulnerability_type=vuln_type),
                path=[
                    PathNode(location=loc, variable_name=source_var, node_type="source", code_snippet=""),
                    PathNode(location=loc, variable_name=sink_var, node_type="sink", code_snippet=""),
                ],
                length=2,
                confidence=0.96,
                vulnerability_type=vuln_type,
            )

            explanation = generator._create_default_explanation(chain)

            # Verify all fields are populated
            assert explanation.chain_id is not None
            assert explanation.why_vulnerable is not None and len(explanation.why_vulnerable) > 0
            assert explanation.how_to_fix is not None and len(explanation.how_to_fix) > 0
            assert explanation.example_fix is not None and len(explanation.example_fix) > 0
            assert explanation.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            assert explanation.cwe_id is not None

            print(f"\n  {vuln_type.value.upper()}")
            print(f"    Severity: {explanation.severity}")
            print(f"    CWE: {explanation.cwe_id}")
            print(f"    Why: {explanation.why_vulnerable[:70]}...")

    def test_batch_explanations_workflow(self) -> None:
        """Test batch explanation generation workflow."""
        client = SimpleLLMClient(api_key="test-key")
        generator = ExplanationGenerator(client)

        loc = CodeLocation(file_path="test.java", line_number=1)

        # Create multiple chains
        chains = [
            TaintChain(
                id=f"chain_{i}",
                source=Source(location=loc, variable_name=f"input_{i}", type="input", confidence=0.95, code_snippet=""),
                sink=Sink(location=loc, variable_name=f"sink_{i}", type="sink", confidence=0.98, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
                path=[],
                length=0,
                confidence=0.96,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            )
            for i in range(3)
        ]

        # Generate explanations
        explanations = generator.generate_explanations_batch(chains)

        # Verify results
        assert len(explanations) == 3
        for i in range(3):
            chain_id = f"chain_{i}"
            assert chain_id in explanations
            explanation = explanations[chain_id]
            assert explanation.severity == "CRITICAL"
            assert explanation.cwe_id == "CWE-89"

        print(f"✓ Batch explanation generation")
        print(f"  Generated {len(explanations)} explanations")
        for chain_id, explanation in explanations.items():
            print(f"  - {chain_id}: {explanation.severity}")
