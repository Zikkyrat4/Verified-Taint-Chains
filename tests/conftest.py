"""Pytest configuration and shared fixtures.

Provides common fixtures for all tests including:
- Test data loading
- Mock LLM clients
- Configuration instances
- Ground truth data
"""

import json
import pytest
from pathlib import Path
from typing import Dict, List
from unittest.mock import Mock, AsyncMock

from src.core.config import PipelineConfig
from src.core.models import (
    Source,
    Sink,
    TaintChain,
    PathNode,
    CodeLocation,
    VulnerabilityType,
    VerificationStatus,
)
from src.stage1_llm_inference.llm_client import SimpleLLMClient


# ============================================================================
# Path Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Get path to fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def vulnerable_code_dir(fixtures_dir: Path) -> Path:
    """Get path to vulnerable code directory."""
    return fixtures_dir / "vulnerable_code"


@pytest.fixture(scope="session")
def safe_code_dir(fixtures_dir: Path) -> Path:
    """Get path to safe code directory."""
    return fixtures_dir / "safe_code"


@pytest.fixture(scope="session")
def ground_truth_file(fixtures_dir: Path) -> Path:
    """Get path to ground truth JSON file."""
    return fixtures_dir / "ground_truth.json"


# ============================================================================
# Data Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def ground_truth(ground_truth_file: Path) -> Dict:
    """Load ground truth data."""
    with open(ground_truth_file) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def vulnerable_files(vulnerable_code_dir: Path) -> List[Path]:
    """List all vulnerable code files."""
    return sorted(vulnerable_code_dir.glob("*.java"))


@pytest.fixture(scope="session")
def safe_files(safe_code_dir: Path) -> List[Path]:
    """List all safe code files."""
    return sorted(safe_code_dir.glob("*.java"))


@pytest.fixture
def sample_vulnerable_code(vulnerable_code_dir: Path) -> str:
    """Load sample vulnerable code."""
    file_path = vulnerable_code_dir / "sql_injection_basic.java"
    with open(file_path) as f:
        return f.read()


@pytest.fixture
def sample_safe_code(safe_code_dir: Path) -> str:
    """Load sample safe code."""
    file_path = safe_code_dir / "sql_safe_prepared_statement.java"
    with open(file_path) as f:
        return f.read()


# ============================================================================
# Configuration Fixtures
# ============================================================================

@pytest.fixture
def test_config() -> PipelineConfig:
    """Create test pipeline configuration."""
    return PipelineConfig(
        llm_api_key="test-key",
        llm_model="gpt-4-turbo",
        max_path_length=15,
        min_confidence=0.5,
        verification_enabled=True,
        verification_level="cfg",
        symbolic_execution_enabled=False,
        use_llm_graph_builder=False,
    )


@pytest.fixture
def test_config_with_symbolic() -> PipelineConfig:
    """Create test config with symbolic execution."""
    return PipelineConfig(
        llm_api_key="test-key",
        llm_model="gpt-4-turbo",
        verification_enabled=True,
        verification_level="symbolic",
        symbolic_execution_enabled=True,
        symbolic_timeout=30,
    )


@pytest.fixture
def test_config_both_verification() -> PipelineConfig:
    """Create test config with both CFG and symbolic."""
    return PipelineConfig(
        llm_api_key="test-key",
        verification_enabled=True,
        verification_level="both",
        symbolic_timeout=60,
    )


# ============================================================================
# Mock LLM Fixtures
# ============================================================================

@pytest.fixture
def mock_llm_client() -> Mock:
    """Create mock LLM client."""
    client = Mock(spec=SimpleLLMClient)

    # Mock analyze_code to return empty response
    async def mock_analyze_code(code: str, prompt: str) -> Dict:
        return {
            "sources": [],
            "sinks": [],
            "sanitizers": []
        }

    client.analyze_code = AsyncMock(side_effect=mock_analyze_code)

    return client


@pytest.fixture
def mock_llm_client_with_results() -> Mock:
    """Create mock LLM client that returns SQL injection results."""
    client = Mock(spec=SimpleLLMClient)

    async def mock_analyze_code(code: str, prompt: str) -> Dict:
        # Detect what's being asked based on prompt
        if "source" in prompt.lower():
            return {
                "sources": [
                    {
                        "variable_name": "userId",
                        "type": "User Input",
                        "line_number": 9,
                        "code_snippet": 'String userId = request.getParameter("id");',
                        "confidence": 0.95
                    }
                ]
            }
        elif "sink" in prompt.lower():
            return {
                "sinks": [
                    {
                        "variable_name": "query",
                        "type": "SQL",
                        "vulnerability_type": "sql_injection",
                        "line_number": 10,
                        "code_snippet": 'String query = "SELECT * FROM users WHERE id = \'" + userId + "\'";',
                        "confidence": 0.90
                    }
                ]
            }
        else:
            return {}

    client.analyze_code = AsyncMock(side_effect=mock_analyze_code)

    return client


# ============================================================================
# Model Fixtures
# ============================================================================

@pytest.fixture
def sample_source() -> Source:
    """Create sample source for testing."""
    return Source(
        location=CodeLocation(
            file_path="test.java",
            line_number=10
        ),
        variable_name="userId",
        type="User Input",
        confidence=0.95,
        code_snippet='String userId = request.getParameter("id");'
    )


@pytest.fixture
def sample_sink() -> Sink:
    """Create sample sink for testing."""
    return Sink(
        location=CodeLocation(
            file_path="test.java",
            line_number=12
        ),
        variable_name="query",
        type="SQL",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        confidence=0.90,
        code_snippet='String query = "SELECT * FROM users WHERE id = \'" + userId + "\'";'
    )


@pytest.fixture
def sample_taint_chain(sample_source: Source, sample_sink: Sink) -> TaintChain:
    """Create sample taint chain for testing."""
    return TaintChain(
        id="test-chain-1",
        source=sample_source,
        sink=sample_sink,
        path=[
            PathNode(location=CodeLocation(file_path="test.java", line_number=10), variable_name="userId", node_type="source", code_snippet='String userId = request.getParameter("id");'),
            PathNode(location=CodeLocation(file_path="test.java", line_number=12), variable_name="query", node_type="sink", code_snippet='String query = "SELECT * FROM users WHERE id = \'" + userId + "\'";'),
        ],
        length=2,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        confidence=0.925,
        verification_status=VerificationStatus.VERIFIED
    )


@pytest.fixture
def sample_taint_chains(sample_source: Source, sample_sink: Sink) -> List[TaintChain]:
    """Create multiple sample taint chains."""
    chains = []

    # Chain 1: SQL Injection
    chains.append(TaintChain(
        id="chain-sqli-1",
        source=sample_source,
        sink=sample_sink,
        path=[
            PathNode(location=CodeLocation(file_path="test.java", line_number=10), variable_name="userId", node_type="source", code_snippet='String userId = request.getParameter("id");'),
            PathNode(location=CodeLocation(file_path="test.java", line_number=12), variable_name="query", node_type="sink", code_snippet='String query = "SELECT * FROM users WHERE id = \'" + userId + "\'";'),
        ],
        length=2,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        confidence=0.90,
        verification_status=VerificationStatus.VERIFIED
    ))

    # Chain 2: XSS
    xss_source = Source(
        location=CodeLocation(file_path="test.java", line_number=20),
        variable_name="name",
        type="User Input",
        confidence=0.85,
        code_snippet="",
    )
    xss_sink = Sink(
        location=CodeLocation(file_path="test.java", line_number=22),
        variable_name="output",
        type="HTML Output",
        vulnerability_type=VulnerabilityType.XSS,
        confidence=0.80,
        code_snippet="",
    )
    chains.append(TaintChain(
        id="chain-xss-1",
        source=xss_source,
        sink=xss_sink,
        path=[
            PathNode(location=CodeLocation(file_path="test.java", line_number=20), variable_name="name", node_type="source", code_snippet=""),
            PathNode(location=CodeLocation(file_path="test.java", line_number=22), variable_name="output", node_type="sink", code_snippet=""),
        ],
        length=2,
        vulnerability_type=VulnerabilityType.XSS,
        confidence=0.825,
        verification_status=VerificationStatus.UNVERIFIABLE
    ))

    # Chain 3: Command Injection
    cmd_source = Source(
        location=CodeLocation(file_path="test.java", line_number=30),
        variable_name="hostname",
        type="User Input",
        confidence=0.95,
        code_snippet="",
    )
    cmd_sink = Sink(
        location=CodeLocation(file_path="test.java", line_number=32),
        variable_name="command",
        type="Command Execution",
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        confidence=0.90,
        code_snippet="",
    )
    chains.append(TaintChain(
        id="chain-cmd-1",
        source=cmd_source,
        sink=cmd_sink,
        path=[
            PathNode(location=CodeLocation(file_path="test.java", line_number=30), variable_name="hostname", node_type="source", code_snippet=""),
            PathNode(location=CodeLocation(file_path="test.java", line_number=32), variable_name="command", node_type="sink", code_snippet=""),
        ],
        length=2,
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        confidence=0.925,
        verification_status=VerificationStatus.FALSE
    ))

    return chains


# ============================================================================
# Helper Fixtures
# ============================================================================

@pytest.fixture
def load_fixture_file():
    """Factory fixture to load any fixture file by name."""
    def _load_file(filename: str, file_type: str = "vulnerable") -> str:
        """Load fixture file contents.

        Args:
            filename: Name of the file.
            file_type: 'vulnerable' or 'safe'.

        Returns:
            File contents as string.
        """
        fixtures_dir = Path(__file__).parent / "fixtures"
        if file_type == "vulnerable":
            file_path = fixtures_dir / "vulnerable_code" / filename
        else:
            file_path = fixtures_dir / "safe_code" / filename

        with open(file_path) as f:
            return f.read()

    return _load_file


@pytest.fixture
def assert_vulnerability_detected():
    """Factory fixture to assert vulnerability detection."""
    def _assert(
        result: Dict,
        expected_type: str,
        expected_count: int = 1,
        min_confidence: float = 0.5
    ) -> None:
        """Assert that vulnerabilities were detected correctly.

        Args:
            result: Pipeline result dictionary.
            expected_type: Expected vulnerability type.
            expected_count: Expected number of vulnerabilities.
            min_confidence: Minimum confidence threshold.
        """
        assert "verified_chains" in result
        chains = result["verified_chains"]

        # Filter by type
        type_chains = [
            c for c in chains
            if c.vulnerability_type.value == expected_type
        ]

        assert len(type_chains) >= expected_count, (
            f"Expected at least {expected_count} {expected_type} vulnerabilities, "
            f"found {len(type_chains)}"
        )

        # Check confidence
        for chain in type_chains:
            assert chain.confidence >= min_confidence, (
                f"Chain {chain.id} confidence {chain.confidence} "
                f"below threshold {min_confidence}"
            )

    return _assert


# ============================================================================
# Performance Tracking Fixtures
# ============================================================================

@pytest.fixture
def performance_tracker():
    """Fixture to track performance metrics."""
    import time
    import psutil
    import os

    class PerformanceTracker:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            self.start_memory = None
            self.end_memory = None
            self.process = psutil.Process(os.getpid())

        def start(self):
            """Start tracking."""
            self.start_time = time.time()
            self.start_memory = self.process.memory_info().rss / 1024 / 1024  # MB

        def stop(self):
            """Stop tracking."""
            self.end_time = time.time()
            self.end_memory = self.process.memory_info().rss / 1024 / 1024  # MB

        @property
        def duration(self) -> float:
            """Get duration in seconds."""
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return 0.0

        @property
        def memory_delta(self) -> float:
            """Get memory delta in MB."""
            if self.start_memory is not None and self.end_memory is not None:
                return self.end_memory - self.start_memory
            return 0.0

        def __str__(self) -> str:
            return (
                f"Duration: {self.duration:.2f}s, "
                f"Memory: {self.memory_delta:+.2f}MB"
            )

    return PerformanceTracker()


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance tests"
    )
    config.addinivalue_line(
        "markers", "e2e: marks tests as end-to-end tests"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test items based on markers."""
    # Add slow marker to performance and e2e tests
    for item in items:
        if "performance" in item.nodeid or "test_benchmarks" in item.nodeid:
            item.add_marker(pytest.mark.slow)
            item.add_marker(pytest.mark.performance)

        if "e2e" in item.nodeid or "test_end_to_end" in item.nodeid:
            item.add_marker(pytest.mark.slow)
            item.add_marker(pytest.mark.e2e)
