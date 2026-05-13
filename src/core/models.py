"""Core data models for taint analysis system."""

from enum import Enum
from typing import List, Optional
from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class SourceCategory(str, Enum):
    """Category of a taint source based on its origin."""

    USER_INPUT = "user_input"
    EXTERNAL_DATA = "external_data"
    SESSION_DATA = "session_data"
    INTERNAL_API = "internal_api"
    DATABASE = "database"
    UNKNOWN = "unknown"


class SinkCategory(str, Enum):
    """Category of a taint sink based on its operation type."""

    DIRECT_EXECUTION = "direct_execution"
    OUTPUT_RENDERING = "output_rendering"
    RESOURCE_ACCESS = "resource_access"
    DATA_STORAGE = "data_storage"
    FRAMEWORK_API = "framework_api"
    EVENT_LOGGING = "event_logging"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class VulnerabilityType(str, Enum):
    """Enumeration of vulnerability types detected by taint analysis."""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"
    SSRF = "ssrf"
    UNSAFE_DESERIALIZATION = "deserialization"
    CODE_INJECTION = "code_injection"


class VerificationStatus(str, Enum):
    """Enumeration of taint chain verification statuses."""

    VERIFIED = "verified"
    UNVERIFIABLE = "unverifiable"
    FALSE = "false"


class CodeLocation(BaseModel):
    """Represents a specific location in source code.

    Attributes:
        file_path: Path to the source file.
        line_number: Line number in the file (1-indexed).
        column: Optional column number (0-indexed).
        function_name: Optional name of the containing function.
        class_name: Optional name of the containing class.
    """

    file_path: str
    line_number: int
    column: Optional[int] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None

    @field_validator("line_number")
    @classmethod
    def validate_line_number(cls, v: int) -> int:
        """Ensure line number is positive."""
        if v <= 0:
            raise ValueError("line_number must be greater than 0")
        return v


class Source(BaseModel):
    """Represents a taint source in the codebase.

    A source is an entry point where untrusted data enters the application.

    Attributes:
        location: Code location of the source.
        variable_name: Name of the variable holding the untrusted data.
        type: Type of source (e.g., "user_input", "file_read").
        confidence: Confidence score (0.0 to 1.0).
        code_snippet: The actual code snippet at this location.
        reasoning: Optional explanation for why this is a source.
    """

    location: CodeLocation
    variable_name: str
    type: str
    confidence: float
    code_snippet: str
    reasoning: Optional[str] = None
    source_category: Optional[SourceCategory] = None

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Ensure confidence is between 0.0 and 1.0."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        return v


class Sink(BaseModel):
    """Represents a taint sink in the codebase.

    A sink is a dangerous operation where untrusted data could cause harm.

    Attributes:
        location: Code location of the sink.
        variable_name: Name of the variable passed to the dangerous operation.
        type: Type of sink (e.g., "sql_query", "command_exec").
        confidence: Confidence score (0.0 to 1.0).
        code_snippet: The actual code snippet at this location.
        vulnerability_type: Type of vulnerability this sink represents.
        reasoning: Optional explanation for why this is a sink.
    """

    location: CodeLocation
    variable_name: str
    type: str
    confidence: float
    code_snippet: str
    vulnerability_type: VulnerabilityType
    reasoning: Optional[str] = None
    sink_category: Optional[SinkCategory] = None

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Ensure confidence is between 0.0 and 1.0."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        return v


class Sanitizer(BaseModel):
    """Represents a sanitization or validation operation.

    Sanitizers may break taint chains by filtering or validating untrusted data.

    Attributes:
        location: Code location of the sanitizer.
        type: Type of sanitization (e.g., "input_validation", "escape").
        confidence: Confidence that this sanitizer actually breaks the chain (0.0 to 1.0).
        code_snippet: The actual code snippet of the sanitization.
        variable_name: Optional variable name for path matching.
        vulnerability_types: Which vulnerability types this sanitizer prevents.
        effectiveness: How effective the sanitizer is (0.0 to 1.0).
    """

    location: CodeLocation
    type: str
    confidence: float
    code_snippet: str
    variable_name: Optional[str] = None
    vulnerability_types: List[str] = Field(default_factory=list)
    effectiveness: float = 0.5

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Ensure confidence is between 0.0 and 1.0."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        return v


class PathNode(BaseModel):
    """Represents a node in a taint propagation path.

    Attributes:
        location: Code location of this node.
        variable_name: Name of the variable at this point.
        node_type: Type of node ("source", "intermediate", or "sink").
        code_snippet: The actual code snippet at this location.
    """

    location: CodeLocation
    variable_name: str
    node_type: str
    code_snippet: str

    @field_validator("node_type")
    @classmethod
    def validate_node_type(cls, v: str) -> str:
        """Ensure node_type is one of the allowed values."""
        allowed = {"source", "intermediate", "sink"}
        if v not in allowed:
            raise ValueError(f"node_type must be one of {allowed}")
        return v


class TaintChain(BaseModel):
    """Represents a complete taint chain from source to sink.

    A taint chain describes a data flow path where untrusted data from a source
    reaches a dangerous sink operation.

    Attributes:
        id: Unique identifier for this chain.
        source: The source of the taint.
        sink: The sink where taint reaches.
        path: Full data flow path from source to sink.
        length: Number of nodes in the path (must equal len(path)).
        confidence: Overall confidence in this chain (0.0 to 1.0).
        vulnerability_type: Type of vulnerability represented.
        sanitizers_on_path: List of sanitizers found along the path.
        verification_status: Result of verification (if verified).
    """

    id: str
    source: Source
    sink: Sink
    path: List[PathNode]
    length: int
    confidence: float
    vulnerability_type: VulnerabilityType
    sanitizers_on_path: List[Sanitizer] = Field(default_factory=list)
    verification_status: Optional[VerificationStatus] = None

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Ensure confidence is between 0.0 and 1.0."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        return v

    @field_validator("length")
    @classmethod
    def validate_length(cls, v: int, info) -> int:
        """Ensure length matches path length."""
        # In Pydantic v2, use info.data to access other fields
        if hasattr(info, 'data') and "path" in info.data:
            if v != len(info.data["path"]):
                raise ValueError("length must equal the number of nodes in path")
        return v


class Specification(BaseModel):
    """Represents the analysis specification containing identified sources, sinks, and sanitizers.

    This is typically generated by Stage 1 (LLM Inference) and used by subsequent stages.

    Attributes:
        sources: List of identified taint sources.
        sinks: List of identified taint sinks.
        sanitizers: List of identified sanitizers.
        llm_model: Name of the LLM model used for inference.
        timestamp: ISO format timestamp when analysis was performed.
    """

    sources: List[Source]
    sinks: List[Sink]
    sanitizers: List[Sanitizer] = Field(default_factory=list)
    llm_model: str
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class Explanation(BaseModel):
    """Represents a human-readable explanation of a vulnerability.

    Generated by Stage 4 to help developers understand and fix vulnerabilities.

    Attributes:
        chain_id: ID of the taint chain being explained.
        why_vulnerable: Explanation of why the code is vulnerable.
        how_to_fix: Description of how to fix the vulnerability.
        example_fix: Example of corrected code.
        severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL).
        cwe_id: Optional CWE (Common Weakness Enumeration) identifier.
    """

    chain_id: str
    why_vulnerable: str
    how_to_fix: str
    example_fix: str
    severity: str
    cwe_id: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Ensure severity is one of the allowed values."""
        allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v
