"""Unit tests for core models."""

import pytest
from pydantic import ValidationError

from src.core.models import (
    VulnerabilityType,
    VerificationStatus,
    CodeLocation,
    Source,
    Sink,
    Sanitizer,
    PathNode,
    TaintChain,
    Specification,
    Explanation,
)


class TestVulnerabilityTypeEnum:
    """Tests for VulnerabilityType enumeration."""

    def test_vulnerability_type_enum_values(self) -> None:
        """Check that all expected vulnerability types are present."""
        expected_types = {
            "sql_injection",
            "xss",
            "command_injection",
            "path_traversal",
            "xxe",
            "ssrf",
            "deserialization",
            "code_injection",
            "open_redirect",
            "other",
        }
        actual_types = {v.value for v in VulnerabilityType}
        assert actual_types == expected_types

    def test_vulnerability_type_enum_members(self) -> None:
        """Check that VulnerabilityType members are accessible."""
        assert VulnerabilityType.SQL_INJECTION.value == "sql_injection"
        assert VulnerabilityType.XSS.value == "xss"
        assert VulnerabilityType.COMMAND_INJECTION.value == "command_injection"


class TestVerificationStatusEnum:
    """Tests for VerificationStatus enumeration."""

    def test_verification_status_enum_values(self) -> None:
        """Check that all expected verification statuses are present."""
        expected_statuses = {"verified", "unverifiable", "false"}
        actual_statuses = {v.value for v in VerificationStatus}
        assert actual_statuses == expected_statuses


class TestCodeLocation:
    """Tests for CodeLocation model."""

    def test_code_location_creation(self) -> None:
        """Test creating a valid CodeLocation."""
        location = CodeLocation(
            file_path="src/app.py",
            line_number=42,
            column=10,
            function_name="process_user_input",
            class_name="UserHandler",
        )
        assert location.file_path == "src/app.py"
        assert location.line_number == 42
        assert location.column == 10
        assert location.function_name == "process_user_input"
        assert location.class_name == "UserHandler"

    def test_code_location_minimal(self) -> None:
        """Test CodeLocation with only required fields."""
        location = CodeLocation(file_path="src/app.py", line_number=1)
        assert location.file_path == "src/app.py"
        assert location.line_number == 1
        assert location.column is None
        assert location.function_name is None

    def test_code_location_line_number_validation_zero(self) -> None:
        """Test that line_number must be > 0."""
        with pytest.raises(ValidationError) as exc_info:
            CodeLocation(file_path="src/app.py", line_number=0)
        assert "line_number must be greater than 0" in str(exc_info.value)

    def test_code_location_line_number_validation_negative(self) -> None:
        """Test that line_number cannot be negative."""
        with pytest.raises(ValidationError) as exc_info:
            CodeLocation(file_path="src/app.py", line_number=-5)
        assert "line_number must be greater than 0" in str(exc_info.value)


class TestSource:
    """Tests for Source model."""

    def test_source_creation(self) -> None:
        """Test creating a valid Source."""
        location = CodeLocation(file_path="src/app.py", line_number=10)
        source = Source(
            location=location,
            variable_name="user_input",
            type="user_input",
            confidence=0.95,
            code_snippet="user_input = request.args.get('query')",
            reasoning="Direct access to request parameter",
        )
        assert source.variable_name == "user_input"
        assert source.type == "user_input"
        assert source.confidence == 0.95

    def test_source_confidence_validation_high(self) -> None:
        """Test that confidence can be 1.0."""
        location = CodeLocation(file_path="src/app.py", line_number=10)
        source = Source(
            location=location,
            variable_name="user_input",
            type="user_input",
            confidence=1.0,
            code_snippet="x = request.args.get('q')",
        )
        assert source.confidence == 1.0

    def test_source_confidence_validation_low(self) -> None:
        """Test that confidence can be 0.0."""
        location = CodeLocation(file_path="src/app.py", line_number=10)
        source = Source(
            location=location,
            variable_name="user_input",
            type="user_input",
            confidence=0.0,
            code_snippet="x = request.args.get('q')",
        )
        assert source.confidence == 0.0

    def test_source_confidence_validation_above_max(self) -> None:
        """Test that confidence > 1.0 is rejected."""
        location = CodeLocation(file_path="src/app.py", line_number=10)
        with pytest.raises(ValidationError) as exc_info:
            Source(
                location=location,
                variable_name="user_input",
                type="user_input",
                confidence=1.5,
                code_snippet="x = request.args.get('q')",
            )
        assert "confidence must be between 0.0 and 1.0" in str(exc_info.value)

    def test_source_confidence_validation_below_min(self) -> None:
        """Test that confidence < 0.0 is rejected."""
        location = CodeLocation(file_path="src/app.py", line_number=10)
        with pytest.raises(ValidationError) as exc_info:
            Source(
                location=location,
                variable_name="user_input",
                type="user_input",
                confidence=-0.1,
                code_snippet="x = request.args.get('q')",
            )
        assert "confidence must be between 0.0 and 1.0" in str(exc_info.value)


class TestSink:
    """Tests for Sink model."""

    def test_sink_creation(self) -> None:
        """Test creating a valid Sink."""
        location = CodeLocation(file_path="src/app.py", line_number=20)
        sink = Sink(
            location=location,
            variable_name="query",
            type="sql_query",
            confidence=0.98,
            code_snippet="db.execute(query)",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            reasoning="Direct execution of SQL with user-controlled input",
        )
        assert sink.variable_name == "query"
        assert sink.vulnerability_type == VulnerabilityType.SQL_INJECTION

    def test_sink_confidence_validation(self) -> None:
        """Test that Sink also validates confidence."""
        location = CodeLocation(file_path="src/app.py", line_number=20)
        with pytest.raises(ValidationError) as exc_info:
            Sink(
                location=location,
                variable_name="query",
                type="sql_query",
                confidence=2.0,
                code_snippet="db.execute(query)",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            )
        assert "confidence must be between 0.0 and 1.0" in str(exc_info.value)


class TestPathNode:
    """Tests for PathNode model."""

    def test_path_node_creation(self) -> None:
        """Test creating a valid PathNode."""
        location = CodeLocation(file_path="src/app.py", line_number=15)
        node = PathNode(
            location=location,
            variable_name="data",
            node_type="intermediate",
            code_snippet="data = process(user_input)",
        )
        assert node.node_type == "intermediate"

    def test_path_node_invalid_type(self) -> None:
        """Test that invalid node_type is rejected."""
        location = CodeLocation(file_path="src/app.py", line_number=15)
        with pytest.raises(ValidationError) as exc_info:
            PathNode(
                location=location,
                variable_name="data",
                node_type="invalid",
                code_snippet="data = process(user_input)",
            )
        assert "node_type must be one of" in str(exc_info.value)

    def test_path_node_valid_types(self) -> None:
        """Test all valid node types."""
        location = CodeLocation(file_path="src/app.py", line_number=15)
        for node_type in ["source", "intermediate", "sink"]:
            node = PathNode(
                location=location,
                variable_name="data",
                node_type=node_type,
                code_snippet="code",
            )
            assert node.node_type == node_type


class TestTaintChain:
    """Tests for TaintChain model."""

    def test_taint_chain_creation(self) -> None:
        """Test creating a valid TaintChain."""
        source_loc = CodeLocation(file_path="src/app.py", line_number=10)
        source = Source(
            location=source_loc,
            variable_name="user_input",
            type="user_input",
            confidence=0.95,
            code_snippet="user_input = request.args.get('q')",
        )

        sink_loc = CodeLocation(file_path="src/app.py", line_number=20)
        sink = Sink(
            location=sink_loc,
            variable_name="query",
            type="sql_query",
            confidence=0.98,
            code_snippet="db.execute(query)",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        node1_loc = CodeLocation(file_path="src/app.py", line_number=10)
        node1 = PathNode(
            location=node1_loc,
            variable_name="user_input",
            node_type="source",
            code_snippet="user_input = request.args.get('q')",
        )

        node2_loc = CodeLocation(file_path="src/app.py", line_number=20)
        node2 = PathNode(
            location=node2_loc,
            variable_name="query",
            node_type="sink",
            code_snippet="db.execute(query)",
        )

        chain = TaintChain(
            id="chain_1",
            source=source,
            sink=sink,
            path=[node1, node2],
            length=2,
            confidence=0.90,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        assert chain.id == "chain_1"
        assert len(chain.path) == 2
        assert chain.length == 2
        assert chain.confidence == 0.90

    def test_taint_chain_length_validation_mismatch(self) -> None:
        """Test that length must match path length."""
        source_loc = CodeLocation(file_path="src/app.py", line_number=10)
        source = Source(
            location=source_loc,
            variable_name="user_input",
            type="user_input",
            confidence=0.95,
            code_snippet="user_input = request.args.get('q')",
        )

        sink_loc = CodeLocation(file_path="src/app.py", line_number=20)
        sink = Sink(
            location=sink_loc,
            variable_name="query",
            type="sql_query",
            confidence=0.98,
            code_snippet="db.execute(query)",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        node1_loc = CodeLocation(file_path="src/app.py", line_number=10)
        node1 = PathNode(
            location=node1_loc,
            variable_name="user_input",
            node_type="source",
            code_snippet="user_input = request.args.get('q')",
        )

        with pytest.raises(ValidationError) as exc_info:
            TaintChain(
                id="chain_1",
                source=source,
                sink=sink,
                path=[node1],
                length=2,  # Mismatch: path has 1 node but length is 2
                confidence=0.90,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            )
        assert "length must equal the number of nodes in path" in str(exc_info.value)

    def test_taint_chain_with_sanitizers(self) -> None:
        """Test TaintChain with sanitizers on the path."""
        source_loc = CodeLocation(file_path="src/app.py", line_number=10)
        source = Source(
            location=source_loc,
            variable_name="user_input",
            type="user_input",
            confidence=0.95,
            code_snippet="user_input = request.args.get('q')",
        )

        sink_loc = CodeLocation(file_path="src/app.py", line_number=25)
        sink = Sink(
            location=sink_loc,
            variable_name="query",
            type="sql_query",
            confidence=0.98,
            code_snippet="db.execute(query)",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        node1 = PathNode(
            location=CodeLocation(file_path="src/app.py", line_number=10),
            variable_name="user_input",
            node_type="source",
            code_snippet="user_input = request.args.get('q')",
        )

        sanitizer = Sanitizer(
            location=CodeLocation(file_path="src/app.py", line_number=15),
            type="input_validation",
            confidence=0.85,
            code_snippet="if validate(user_input): query = user_input",
        )

        node2 = PathNode(
            location=CodeLocation(file_path="src/app.py", line_number=25),
            variable_name="query",
            node_type="sink",
            code_snippet="db.execute(query)",
        )

        chain = TaintChain(
            id="chain_with_sanitizer",
            source=source,
            sink=sink,
            path=[node1, node2],
            length=2,
            confidence=0.50,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            sanitizers_on_path=[sanitizer],
            verification_status=VerificationStatus.UNVERIFIABLE,
        )

        assert len(chain.sanitizers_on_path) == 1
        assert chain.verification_status == VerificationStatus.UNVERIFIABLE


class TestSpecification:
    """Tests for Specification model."""

    def test_specification_creation(self) -> None:
        """Test creating a valid Specification."""
        location = CodeLocation(file_path="src/app.py", line_number=10)
        source = Source(
            location=location,
            variable_name="user_input",
            type="user_input",
            confidence=0.95,
            code_snippet="user_input = request.args.get('q')",
        )

        spec = Specification(
            sources=[source],
            sinks=[],
            sanitizers=[],
            llm_model="gpt-4",
        )

        assert len(spec.sources) == 1
        assert spec.llm_model == "gpt-4"
        assert spec.timestamp is not None


class TestExplanation:
    """Tests for Explanation model."""

    def test_explanation_creation(self) -> None:
        """Test creating a valid Explanation."""
        explanation = Explanation(
            chain_id="chain_1",
            why_vulnerable="User input flows directly into SQL query",
            how_to_fix="Use parameterized queries",
            example_fix="db.execute('SELECT * FROM users WHERE id = ?', [user_id])",
            severity="HIGH",
            cwe_id="CWE-89",
        )

        assert explanation.chain_id == "chain_1"
        assert explanation.severity == "HIGH"

    def test_explanation_severity_validation_invalid(self) -> None:
        """Test that invalid severity is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            Explanation(
                chain_id="chain_1",
                why_vulnerable="Vulnerable",
                how_to_fix="Fix it",
                example_fix="fixed code",
                severity="INVALID",
            )
        assert "severity must be one of" in str(exc_info.value)

    def test_explanation_valid_severities(self) -> None:
        """Test all valid severity levels."""
        for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            explanation = Explanation(
                chain_id="chain_1",
                why_vulnerable="Vulnerable",
                how_to_fix="Fix it",
                example_fix="fixed code",
                severity=severity,
            )
            assert explanation.severity == severity
