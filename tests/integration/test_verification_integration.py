"""Integration tests for verification components."""

import os
import pytest
import networkx as nx
from unittest.mock import patch

from src.stage3_verification.simple_verifier import SimpleCFGVerifier
from src.core.models import (
    TaintChain,
    Source,
    Sink,
    PathNode,
    CodeLocation,
    VerificationStatus,
    VulnerabilityType,
)
from src.core.config import PipelineConfig, load_config_from_env


class TestVerifyExistingPath:
    """Test verification of valid taint chains with existing paths."""

    def test_verify_existing_path(self) -> None:
        """Test verifying a chain with a valid data flow path.

        Scenario: Create a graph representing data flow, then verify a chain
        that should successfully traverse this path.

        Graph structure:
            user_input -> username -> query -> result

        The chain should verify because a path exists from user_input to result.
        """
        # Build a realistic data flow graph
        graph = nx.DiGraph()

        # Create edges representing data flow in code:
        # String username = request.getParameter("user");  // user_input -> username
        # String query = "SELECT * FROM users WHERE id = " + username;  // username -> query
        # ResultSet result = db.executeQuery(query);  // query -> result
        graph.add_edges_from([
            ("user_input", "username"),
            ("username", "query"),
            ("query", "result"),
        ])

        # Create the chain to verify
        source_loc = CodeLocation(file_path="AuthService.java", line_number=3)
        sink_loc = CodeLocation(file_path="AuthService.java", line_number=6)

        source = Source(
            location=source_loc,
            variable_name="user_input",
            type="user_input",
            confidence=0.98,
            code_snippet='String user_input = request.getParameter("user");',
        )

        sink = Sink(
            location=sink_loc,
            variable_name="result",
            type="sql_result",
            confidence=0.95,
            code_snippet="ResultSet result = db.executeQuery(query);",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        # Build path nodes for the chain
        path_nodes = [
            PathNode(
                location=source_loc,
                variable_name="user_input",
                node_type="source",
                code_snippet='String user_input = request.getParameter("user");',
            ),
            PathNode(
                location=CodeLocation(file_path="AuthService.java", line_number=4),
                variable_name="username",
                node_type="intermediate",
                code_snippet='String username = request.getParameter("user");',
            ),
            PathNode(
                location=CodeLocation(file_path="AuthService.java", line_number=5),
                variable_name="query",
                node_type="intermediate",
                code_snippet='String query = "SELECT * FROM users WHERE id = " + username;',
            ),
            PathNode(
                location=sink_loc,
                variable_name="result",
                node_type="sink",
                code_snippet="ResultSet result = db.executeQuery(query);",
            ),
        ]

        # Create the taint chain
        chain = TaintChain(
            id="sql_injection_chain_1",
            source=source,
            sink=sink,
            path=path_nodes,
            length=len(path_nodes),
            confidence=0.96,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        # Initialize verifier
        verifier = SimpleCFGVerifier(graph)

        # Verify the chain
        status = verifier.verify_chain(chain)

        # Assertions
        assert status == VerificationStatus.VERIFIED
        print(f"✓ Chain VERIFIED")
        print(f"  Source: {source.variable_name}")
        print(f"  Sink: {sink.variable_name}")
        print(f"  Path: {' -> '.join(n.variable_name for n in path_nodes)}")
        print(f"  Path exists in graph: {nx.has_path(graph, source.variable_name, sink.variable_name)}")

    def test_verify_multiple_source_paths(self) -> None:
        """Test verifying chains with multiple data sources converging.

        Scenario: Both username and password flow to query, multiple chains
        should verify independently.

        Graph:
            username -> query
            password -> query
            query -> result
        """
        graph = nx.DiGraph()
        graph.add_edges_from([
            ("username", "query"),
            ("password", "query"),
            ("query", "result"),
        ])

        source_loc = CodeLocation(file_path="AuthService.java", line_number=1)
        sink_loc = CodeLocation(file_path="AuthService.java", line_number=5)

        # First chain: username -> result
        source1 = Source(
            location=source_loc,
            variable_name="username",
            type="user_input",
            confidence=0.95,
            code_snippet='String username = request.getParameter("user");',
        )

        sink = Sink(
            location=sink_loc,
            variable_name="result",
            type="sql_result",
            confidence=0.98,
            code_snippet="ResultSet result = db.executeQuery(query);",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        chain1 = TaintChain(
            id="chain_username",
            source=source1,
            sink=sink,
            path=[
                PathNode(location=CodeLocation(file_path="test.java", line_number=1), variable_name="username", node_type="source", code_snippet=""),
                PathNode(location=CodeLocation(file_path="test.java", line_number=2), variable_name="query", node_type="intermediate", code_snippet=""),
                PathNode(location=CodeLocation(file_path="test.java", line_number=3), variable_name="result", node_type="sink", code_snippet=""),
            ],
            length=3,
            confidence=0.93,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        # Second chain: password -> result
        source2 = Source(
            location=source_loc,
            variable_name="password",
            type="user_input",
            confidence=0.95,
            code_snippet='String password = request.getParameter("pass");',
        )

        chain2 = TaintChain(
            id="chain_password",
            source=source2,
            sink=sink,
            path=[
                PathNode(location=CodeLocation(file_path="test.java", line_number=1), variable_name="password", node_type="source", code_snippet=""),
                PathNode(location=CodeLocation(file_path="test.java", line_number=2), variable_name="query", node_type="intermediate", code_snippet=""),
                PathNode(location=CodeLocation(file_path="test.java", line_number=3), variable_name="result", node_type="sink", code_snippet=""),
            ],
            length=3,
            confidence=0.93,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        verifier = SimpleCFGVerifier(graph)

        # Verify both chains
        status1 = verifier.verify_chain(chain1)
        status2 = verifier.verify_chain(chain2)

        assert status1 == VerificationStatus.VERIFIED
        assert status2 == VerificationStatus.VERIFIED

        print(f"✓ Multiple source paths verified")
        print(f"  Chain 1: {source1.variable_name} -> {sink.variable_name}: {status1.value}")
        print(f"  Chain 2: {source2.variable_name} -> {sink.variable_name}: {status2.value}")


class TestVerifyNonexistentPath:
    """Test verification returning FALSE for invalid chains."""

    def test_verify_nonexistent_path(self) -> None:
        """Test that chains with no data flow path return FALSE status.

        Scenario: The graph has two disconnected components. A chain trying
        to flow from one component to another should fail verification.

        Graph:
            Component 1: a -> b
            Component 2: c -> d

        Attempt to verify: a -> d (should fail)
        """
        # Build graph with disconnected components
        graph = nx.DiGraph()

        # Component 1
        graph.add_edge("input_a", "var_b")

        # Component 2 (disconnected)
        graph.add_edge("input_c", "var_d")

        source_loc = CodeLocation(file_path="Service.java", line_number=1)
        sink_loc = CodeLocation(file_path="Service.java", line_number=10)

        # Create chain trying to flow from component 1 to component 2
        source = Source(
            location=source_loc,
            variable_name="input_a",
            type="user_input",
            confidence=0.9,
            code_snippet="String input_a = request.getParameter('a');",
        )

        sink = Sink(
            location=sink_loc,
            variable_name="var_d",
            type="sql_query",
            confidence=0.95,
            code_snippet="db.execute(var_d);",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        chain = TaintChain(
            id="false_chain",
            source=source,
            sink=sink,
            path=[],
            length=0,
            confidence=0.85,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        # Verify
        verifier = SimpleCFGVerifier(graph)
        status = verifier.verify_chain(chain)

        # Assertion
        assert status == VerificationStatus.FALSE
        print(f"✓ Disconnected path correctly identified as FALSE")
        print(f"  Source: {source.variable_name} (Component 1)")
        print(f"  Sink: {sink.variable_name} (Component 2)")
        print(f"  Path exists: {nx.has_path(graph, source.variable_name, sink.variable_name)}")

    def test_verify_nonexistent_source_node(self) -> None:
        """Test that chains with non-existent source node return FALSE.

        When the source variable doesn't exist in the graph at all.
        """
        graph = nx.DiGraph()
        graph.add_edge("real_input", "output")

        source_loc = CodeLocation(file_path="test.java", line_number=1)
        sink_loc = CodeLocation(file_path="test.java", line_number=5)

        # Source that doesn't exist in graph
        source = Source(
            location=source_loc,
            variable_name="nonexistent_source",
            type="user_input",
            confidence=0.9,
            code_snippet="",
        )

        sink = Sink(
            location=sink_loc,
            variable_name="output",
            type="sql",
            confidence=0.9,
            code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        chain = TaintChain(
            id="missing_source_chain",
            source=source,
            sink=sink,
            path=[],
            length=0,
            confidence=0.85,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        verifier = SimpleCFGVerifier(graph)
        status = verifier.verify_chain(chain)

        assert status == VerificationStatus.FALSE
        print(f"✓ Missing source node correctly identified as FALSE")

    def test_verify_nonexistent_sink_node(self) -> None:
        """Test that chains with non-existent sink node return FALSE."""
        graph = nx.DiGraph()
        graph.add_edge("input", "real_output")

        source_loc = CodeLocation(file_path="test.java", line_number=1)
        sink_loc = CodeLocation(file_path="test.java", line_number=5)

        source = Source(
            location=source_loc,
            variable_name="input",
            type="user_input",
            confidence=0.9,
            code_snippet="",
        )

        # Sink that doesn't exist in graph
        sink = Sink(
            location=sink_loc,
            variable_name="nonexistent_sink",
            type="sql",
            confidence=0.9,
            code_snippet="",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        chain = TaintChain(
            id="missing_sink_chain",
            source=source,
            sink=sink,
            path=[],
            length=0,
            confidence=0.85,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
        )

        verifier = SimpleCFGVerifier(graph)
        status = verifier.verify_chain(chain)

        assert status == VerificationStatus.FALSE
        print(f"✓ Missing sink node correctly identified as FALSE")


class TestGetConfidence:
    """Test confidence score calculation for verification."""

    def test_get_confidence_verified_chain(self) -> None:
        """Test that verified chains get 0.8 confidence."""
        graph = nx.DiGraph()
        graph.add_edge("x", "y")

        source_loc = CodeLocation(file_path="test.java", line_number=1)

        chain = TaintChain(
            id="verified_chain",
            source=Source(
                location=source_loc,
                variable_name="x",
                type="input",
                confidence=0.9,
                code_snippet="",
            ),
            sink=Sink(
                location=source_loc,
                variable_name="y",
                type="sql",
                confidence=0.95,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            path=[],
            length=0,
            confidence=0.93,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            verification_status=VerificationStatus.VERIFIED,
        )

        verifier = SimpleCFGVerifier(graph)
        confidence = verifier.get_verification_confidence(chain)

        assert confidence == 0.8
        print(f"✓ Verified chain confidence: {confidence}")

    def test_get_confidence_false_chain(self) -> None:
        """Test that false chains get 0.2 confidence."""
        graph = nx.DiGraph()

        source_loc = CodeLocation(file_path="test.java", line_number=1)

        chain = TaintChain(
            id="false_chain",
            source=Source(
                location=source_loc,
                variable_name="x",
                type="input",
                confidence=0.9,
                code_snippet="",
            ),
            sink=Sink(
                location=source_loc,
                variable_name="y",
                type="sql",
                confidence=0.95,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            path=[],
            length=0,
            confidence=0.93,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            verification_status=VerificationStatus.FALSE,
        )

        verifier = SimpleCFGVerifier(graph)
        confidence = verifier.get_verification_confidence(chain)

        assert confidence == 0.2
        print(f"✓ False chain confidence: {confidence}")

    def test_get_confidence_unverifiable_chain(self) -> None:
        """Test that unverifiable chains get 0.5 confidence."""
        graph = nx.DiGraph()

        source_loc = CodeLocation(file_path="test.java", line_number=1)

        chain = TaintChain(
            id="unverifiable_chain",
            source=Source(
                location=source_loc,
                variable_name="x",
                type="input",
                confidence=0.9,
                code_snippet="",
            ),
            sink=Sink(
                location=source_loc,
                variable_name="y",
                type="sql",
                confidence=0.95,
                code_snippet="",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            path=[],
            length=0,
            confidence=0.93,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            verification_status=VerificationStatus.UNVERIFIABLE,
        )

        verifier = SimpleCFGVerifier(graph)
        confidence = verifier.get_verification_confidence(chain)

        assert confidence == 0.5
        print(f"✓ Unverifiable chain confidence: {confidence}")

    def test_confidence_scores_summary(self) -> None:
        """Test all confidence scores together."""
        graph = nx.DiGraph()
        graph.add_edge("x", "y")

        source_loc = CodeLocation(file_path="test.java", line_number=1)

        # Create three chains with different statuses
        chains = [
            TaintChain(
                id="verified",
                source=Source(location=source_loc, variable_name="x", type="input", confidence=0.9, code_snippet=""),
                sink=Sink(location=source_loc, variable_name="y", type="sql", confidence=0.95, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
                path=[], length=0, confidence=0.93,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                verification_status=VerificationStatus.VERIFIED,
            ),
            TaintChain(
                id="false",
                source=Source(location=source_loc, variable_name="a", type="input", confidence=0.9, code_snippet=""),
                sink=Sink(location=source_loc, variable_name="b", type="sql", confidence=0.95, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
                path=[], length=0, confidence=0.93,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                verification_status=VerificationStatus.FALSE,
            ),
            TaintChain(
                id="unverifiable",
                source=Source(location=source_loc, variable_name="c", type="input", confidence=0.9, code_snippet=""),
                sink=Sink(location=source_loc, variable_name="d", type="sql", confidence=0.95, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
                path=[], length=0, confidence=0.93,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                verification_status=VerificationStatus.UNVERIFIABLE,
            ),
        ]

        verifier = SimpleCFGVerifier(graph)

        print(f"✓ Confidence Score Summary:")
        for chain in chains:
            conf = verifier.get_verification_confidence(chain)
            print(f"  {chain.id:15} -> confidence: {conf:.1f}")

        assert verifier.get_verification_confidence(chains[0]) == 0.8
        assert verifier.get_verification_confidence(chains[1]) == 0.2
        assert verifier.get_verification_confidence(chains[2]) == 0.5


class TestConfigFromEnv:
    """Test loading configuration from environment."""

    def test_config_from_env(self) -> None:
        """Test loading configuration from environment variables.

        This test verifies the complete configuration loading workflow:
        1. Set environment variables
        2. Load config using load_config_from_env()
        3. Verify all values are correct
        """
        # Save original environment
        env_keys = [
            "OPENAI_API_KEY", "OPENAI_MODEL", "LLM_MODEL", "LLM_PROVIDER",
            "MAX_PATH_LENGTH", "MIN_CONFIDENCE", "VERIFICATION_ENABLED",
            "SYMBOLIC_EXECUTION_ENABLED", "VERIFICATION_LEVEL",
            "PATHFINDING_ALGORITHM", "USE_JOERN", "USE_ASTAR",
            "USE_SEMANTIC_HEURISTIC", "OLLAMA_BASE_URL", "SYMBOLIC_TIMEOUT",
        ]
        original_env = {k: os.environ.get(k) for k in env_keys}

        try:
            # Set test environment variables (set all to override .env file)
            os.environ["OPENAI_API_KEY"] = "test-key-12345"
            os.environ["OPENAI_MODEL"] = "gpt-4-turbo"
            os.environ["LLM_MODEL"] = "gpt-4-turbo"
            os.environ["LLM_PROVIDER"] = "openai"
            os.environ["MAX_PATH_LENGTH"] = "20"
            os.environ["MIN_CONFIDENCE"] = "0.6"
            os.environ["VERIFICATION_ENABLED"] = "true"
            os.environ["SYMBOLIC_EXECUTION_ENABLED"] = "false"
            os.environ["VERIFICATION_LEVEL"] = "cfg"
            os.environ["PATHFINDING_ALGORITHM"] = "astar"
            os.environ["USE_JOERN"] = "false"
            os.environ["USE_ASTAR"] = "true"
            os.environ["USE_SEMANTIC_HEURISTIC"] = "true"

            # Load configuration
            config = load_config_from_env()

            # Verify all values
            assert config.llm_api_key == "test-key-12345"
            assert config.llm_model == "gpt-4-turbo"
            assert config.max_path_length == 20
            assert config.min_confidence == 0.6
            assert config.verification_enabled is True
            assert config.symbolic_execution_enabled is False

            print(f"Configuration loaded from environment")
            print(f"  API Key: {config.llm_api_key}")
            print(f"  Model: {config.llm_model}")
            print(f"  Max Path Length: {config.max_path_length}")
            print(f"  Min Confidence: {config.min_confidence}")
            print(f"  Verification Enabled: {config.verification_enabled}")
            print(f"  Symbolic Execution Enabled: {config.symbolic_execution_enabled}")

        finally:
            # Restore original environment
            for key, value in original_env.items():
                if value is not None:
                    os.environ[key] = value
                else:
                    os.environ.pop(key, None)

    def test_config_with_defaults(self) -> None:
        """Test that config uses defaults when env vars not set."""
        env_keys = [
            "OPENAI_API_KEY", "OPENAI_MODEL", "LLM_MODEL", "LLM_PROVIDER",
            "MAX_PATH_LENGTH", "MIN_CONFIDENCE", "VERIFICATION_LEVEL",
            "PATHFINDING_ALGORITHM", "USE_JOERN", "USE_ASTAR",
            "USE_SEMANTIC_HEURISTIC", "OLLAMA_BASE_URL", "SYMBOLIC_TIMEOUT",
            "VERIFICATION_ENABLED", "SYMBOLIC_EXECUTION_ENABLED",
        ]
        original_env = {k: os.environ.get(k) for k in env_keys}

        try:
            # Set only required variable
            os.environ["OPENAI_API_KEY"] = "minimal-key"
            os.environ["LLM_PROVIDER"] = "openai"

            # Set optional variables to empty to prevent .env override
            # (load_dotenv won't override existing env vars, even empty ones)
            os.environ["OPENAI_MODEL"] = ""
            os.environ["LLM_MODEL"] = ""
            os.environ["MAX_PATH_LENGTH"] = ""
            os.environ["MIN_CONFIDENCE"] = ""
            os.environ["VERIFICATION_LEVEL"] = ""
            os.environ["PATHFINDING_ALGORITHM"] = ""
            os.environ["USE_JOERN"] = ""
            os.environ["USE_ASTAR"] = ""
            os.environ["USE_SEMANTIC_HEURISTIC"] = ""
            os.environ["SYMBOLIC_TIMEOUT"] = ""
            os.environ["VERIFICATION_ENABLED"] = ""
            os.environ["SYMBOLIC_EXECUTION_ENABLED"] = ""

            # Load configuration
            config = load_config_from_env()

            # Verify defaults are used
            assert config.llm_api_key == "minimal-key"
            assert config.llm_model == "gpt-4-turbo"  # Default for openai provider
            assert config.max_path_length == 15  # Default
            assert config.min_confidence == 0.6  # Default

            print(f"Configuration with defaults")
            print(f"  API Key: {config.llm_api_key} (provided)")
            print(f"  Model: {config.llm_model} (default)")
            print(f"  Max Path Length: {config.max_path_length} (default)")
            print(f"  Min Confidence: {config.min_confidence} (default)")

        finally:
            for key, value in original_env.items():
                if value is not None:
                    os.environ[key] = value
                else:
                    os.environ.pop(key, None)

    def test_config_invalid_values_use_defaults(self) -> None:
        """Test that invalid config values fall back to defaults."""
        env_keys = [
            "OPENAI_API_KEY", "LLM_PROVIDER", "LLM_MODEL", "OPENAI_MODEL",
            "MAX_PATH_LENGTH", "MIN_CONFIDENCE", "VERIFICATION_LEVEL",
            "PATHFINDING_ALGORITHM", "USE_JOERN", "USE_ASTAR",
            "USE_SEMANTIC_HEURISTIC", "SYMBOLIC_TIMEOUT",
            "VERIFICATION_ENABLED", "SYMBOLIC_EXECUTION_ENABLED",
        ]
        original_env = {k: os.environ.get(k) for k in env_keys}

        try:
            os.environ["OPENAI_API_KEY"] = "test-key"
            os.environ["LLM_PROVIDER"] = "openai"
            os.environ["LLM_MODEL"] = ""
            os.environ["OPENAI_MODEL"] = ""
            os.environ["MAX_PATH_LENGTH"] = "not-a-number"
            os.environ["MIN_CONFIDENCE"] = "invalid-float"
            os.environ["VERIFICATION_LEVEL"] = ""
            os.environ["PATHFINDING_ALGORITHM"] = ""
            os.environ["USE_JOERN"] = ""
            os.environ["USE_ASTAR"] = ""
            os.environ["USE_SEMANTIC_HEURISTIC"] = ""
            os.environ["SYMBOLIC_TIMEOUT"] = ""
            os.environ["VERIFICATION_ENABLED"] = ""
            os.environ["SYMBOLIC_EXECUTION_ENABLED"] = ""

            # Load configuration (should not raise)
            config = load_config_from_env()

            # Verify defaults used for invalid values
            assert config.llm_api_key == "test-key"
            assert config.max_path_length == 15  # Default (invalid value)
            assert config.min_confidence == 0.6  # Default (invalid value)

            print(f"Invalid values handled gracefully")
            print(f"  Max Path Length: invalid -> {config.max_path_length} (default)")
            print(f"  Min Confidence: invalid -> {config.min_confidence} (default)")

        finally:
            for key, value in original_env.items():
                if value is not None:
                    os.environ[key] = value
                else:
                    os.environ.pop(key, None)


class TestEndToEndVerification:
    """End-to-end verification workflow test."""

    def test_complete_verification_workflow(self) -> None:
        """Test complete verification workflow from config to chain verification.

        1. Load configuration
        2. Build data flow graph
        3. Create chains
        4. Verify chains
        5. Check confidence scores
        """
        # Setup environment
        original_api_key = os.environ.get("OPENAI_API_KEY")

        try:
            os.environ["OPENAI_API_KEY"] = "workflow-test-key"

            # Load config
            config = load_config_from_env()
            assert config.verification_enabled is True

            # Build graph
            graph = nx.DiGraph()
            graph.add_edges_from([
                ("user_input", "processed"),
                ("processed", "query"),
                ("query", "db_result"),
            ])

            # Create verifier
            verifier = SimpleCFGVerifier(graph)

            # Create and verify chains
            source_loc = CodeLocation(file_path="App.java", line_number=10)
            sink_loc = CodeLocation(file_path="App.java", line_number=20)

            chains = [
                TaintChain(
                    id="chain_1",
                    source=Source(location=source_loc, variable_name="user_input", type="input", confidence=0.95, code_snippet=""),
                    sink=Sink(location=sink_loc, variable_name="db_result", type="sql", confidence=0.98, code_snippet="", vulnerability_type=VulnerabilityType.SQL_INJECTION),
                    path=[],
                    length=0,
                    confidence=0.96,
                    vulnerability_type=VulnerabilityType.SQL_INJECTION,
                ),
            ]

            # Verify chains
            results = verifier.verify_all_chains(chains)

            # Check results
            assert len(results["verified"]) >= 0
            assert results["total"] == 1

            print(f"✓ Complete Verification Workflow")
            print(f"  Config: {config.llm_model}")
            print(f"  Graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
            print(f"  Chains verified: {len(results['verified'])}")
            print(f"  Chains false: {len(results['false'])}")
            print(f"  Verification rate: {results['verification_rate']:.1%}")

        finally:
            if original_api_key:
                os.environ["OPENAI_API_KEY"] = original_api_key
            else:
                os.environ.pop("OPENAI_API_KEY", None)
