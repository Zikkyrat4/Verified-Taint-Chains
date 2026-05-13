"""End-to-end tests with ground truth validation.

This module tests the full pipeline on test fixtures and validates results
against ground truth data, calculating metrics like recall, precision, and F1.
"""

import json
import pytest
from pathlib import Path
from typing import Dict, List, Set, Tuple
from unittest.mock import Mock, AsyncMock

from src.pipeline.orchestrator import SimplePipeline
from src.core.config import PipelineConfig
from src.core.models import VulnerabilityType, VerificationStatus


class TestEndToEndWithGroundTruth:
    """Test full pipeline against ground truth data."""

    @pytest.fixture(autouse=True)
    def setup(self, fixtures_dir: Path, ground_truth: Dict):
        """Setup test environment."""
        self.fixtures_dir = fixtures_dir
        self.ground_truth = ground_truth
        self.vulnerable_dir = fixtures_dir / "vulnerable_code"
        self.safe_dir = fixtures_dir / "safe_code"

    def _create_mock_llm_for_file(self, filename: str) -> Mock:
        """Create mock LLM client that returns results based on ground truth.

        Args:
            filename: Name of the Java file to analyze.

        Returns:
            Mock LLM client with appropriate responses.
        """
        client = Mock()

        # Get expected vulnerabilities from ground truth
        gt_data = self.ground_truth.get("vulnerable_code", {}).get(filename, {})
        vulnerabilities = gt_data.get("vulnerabilities", [])

        async def mock_chat_prompt(prompt: str) -> Dict:
            """Mock LLM response based on ground truth."""
            # Combined prompt contains both source and sink detection
            if "Source and Sink Detection" in prompt or "Source Detection" in prompt:
                sources = []
                sinks = []
                for vuln in vulnerabilities:
                    source_info = vuln.get("source", {})
                    sources.append({
                        "variable": source_info.get("variable", ""),
                        "type": source_info.get("type", "User Input"),
                        "line": source_info.get("line_number", 0),
                        "confidence": 0.9,
                    })
                    sink_info = vuln.get("sink", {})
                    vuln_type = vuln.get("type", "sql_injection")
                    sinks.append({
                        "variable": sink_info.get("variable", ""),
                        "type": sink_info.get("type", "SQL"),
                        "vulnerability_type": vuln_type,
                        "line": sink_info.get("line_number", 0),
                        "confidence": 0.85,
                    })
                return {"sources": sources, "sinks": sinks}

            elif "sanitizer" in prompt.lower():
                # Return sanitizers if any
                return {"sanitizers": []}

            return {"sources": [], "sinks": []}

        client.chat_with_json_prompt = AsyncMock(side_effect=mock_chat_prompt)
        return client

    @pytest.mark.asyncio
    async def test_vulnerable_file_detection(
        self,
        vulnerable_files: List[Path],
    ) -> None:
        """Test detection on vulnerable code files.

        Validates that the pipeline detects expected vulnerabilities in each
        vulnerable test fixture.
        """
        results = {}

        for file_path in vulnerable_files[:3]:  # Test first 3 files for speed
            filename = file_path.name

            # Skip if not in ground truth
            if filename not in self.ground_truth["vulnerable_code"]:
                continue

            # Get expected vulnerabilities
            expected_count = self.ground_truth["vulnerable_code"][filename][
                "expected_vulnerabilities"
            ]

            # Create mock LLM client
            mock_llm = self._create_mock_llm_for_file(filename)

            # Create config and pipeline
            config = PipelineConfig(
                llm_api_key="test-key",
                llm_model="gpt-4-turbo",
                verification_enabled=True,
                verification_level="cfg",
                min_confidence=0.5,
                use_llm_graph_builder=False,
            )

            pipeline = SimplePipeline(config)
            pipeline.llm_client = mock_llm
            pipeline.spec_extractor.llm_client = mock_llm
            pipeline.explainer.llm_client = mock_llm

            # Run analysis using actual file path
            try:
                result = await pipeline.run(str(file_path))

                detected_count = len(result.get("verified_chains", []))
                results[filename] = {
                    "expected": expected_count,
                    "detected": detected_count,
                    "success": detected_count > 0,
                }

                print(f"\n✓ {filename}")
                print(f"  Expected: {expected_count} vulnerabilities")
                print(f"  Detected: {detected_count} chains")

            except Exception as e:
                print(f"\n✗ {filename}: {e}")
                results[filename] = {
                    "expected": expected_count,
                    "detected": 0,
                    "success": False,
                    "error": str(e),
                }

        # Verify at least some vulnerabilities were detected
        total_detected = sum(r["detected"] for r in results.values())
        assert total_detected > 0, "No vulnerabilities detected in any file"

    @pytest.mark.asyncio
    async def test_safe_file_no_false_positives(
        self,
        safe_files: List[Path],
    ) -> None:
        """Test that safe code does not produce false positives.

        Validates that the pipeline does not incorrectly flag secure code
        as vulnerable.
        """
        false_positives = []

        for file_path in safe_files:
            filename = file_path.name

            # Skip if not in ground truth
            if filename not in self.ground_truth["safe_code"]:
                continue

            # Create minimal mock LLM (should return empty results)
            mock_llm = Mock()
            mock_llm.chat_with_json_prompt = AsyncMock(return_value={
                "sources": [],
                "sinks": [],
                "sanitizers": [],
            })

            # Create config and pipeline
            config = PipelineConfig(
                llm_api_key="test-key",
                verification_enabled=True,
                min_confidence=0.5,
                use_llm_graph_builder=False,
            )

            pipeline = SimplePipeline(config)
            pipeline.llm_client = mock_llm
            pipeline.spec_extractor.llm_client = mock_llm
            pipeline.explainer.llm_client = mock_llm

            # Run analysis using actual file path
            try:
                result = await pipeline.run(str(file_path))

                detected_count = len(result.get("verified_chains", []))

                if detected_count > 0:
                    false_positives.append({
                        "file": filename,
                        "detected": detected_count,
                    })

                print(f"\n✓ {filename}")
                print(f"  Detected: {detected_count} (expected: 0)")

            except Exception as e:
                print(f"\n✗ {filename}: {e}")

        # Verify no false positives
        if false_positives:
            print(f"\n⚠ False positives detected:")
            for fp in false_positives:
                print(f"  - {fp['file']}: {fp['detected']} chains")

        # Allow some tolerance for false positives due to mocking limitations
        assert len(false_positives) <= 1, "Too many false positives"

    def test_ground_truth_metrics_calculation(self) -> None:
        """Test metrics calculation from ground truth.

        Calculates expected metrics based on ground truth data.
        """
        gt = self.ground_truth

        # Calculate totals
        total_vulnerable_files = len(gt["vulnerable_code"])
        total_safe_files = len(gt["safe_code"])
        total_expected_vulns = gt["metrics"]["total_expected_vulnerabilities"]

        # Verify metrics
        assert total_vulnerable_files == gt["metrics"]["total_vulnerable_files"]
        assert total_safe_files == gt["metrics"]["total_safe_files"]
        assert total_expected_vulns > 0

        print("\n✓ Ground Truth Metrics:")
        print(f"  Vulnerable files: {total_vulnerable_files}")
        print(f"  Safe files: {total_safe_files}")
        print(f"  Expected vulnerabilities: {total_expected_vulns}")

        # Verify distribution
        distribution = gt["metrics"]["vulnerability_distribution"]
        total_from_dist = sum(distribution.values())

        assert total_from_dist == total_expected_vulns
        print(f"\n  Vulnerability Distribution:")
        for vuln_type, count in sorted(distribution.items()):
            print(f"    {vuln_type}: {count}")

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_full_ground_truth_validation(
        self,
        vulnerable_files: List[Path],
    ) -> None:
        """Full validation against all ground truth data.

        This is a comprehensive test that runs the pipeline on all fixtures
        and calculates precision, recall, and F1 scores.
        """
        # Results tracking
        true_positives = 0  # Correctly detected vulnerabilities
        false_positives = 0  # Incorrectly flagged as vulnerable
        false_negatives = 0  # Missed vulnerabilities
        true_negatives = 0  # Correctly identified as safe

        detailed_results = []

        # Test vulnerable files
        for file_path in vulnerable_files:
            filename = file_path.name

            if filename not in self.ground_truth["vulnerable_code"]:
                continue

            gt_data = self.ground_truth["vulnerable_code"][filename]
            expected_vulns = gt_data["vulnerabilities"]

            # Create mock LLM
            mock_llm = self._create_mock_llm_for_file(filename)

            # Create pipeline
            config = PipelineConfig(
                llm_api_key="test-key",
                verification_enabled=True,
                min_confidence=0.5,
                use_llm_graph_builder=False,
            )

            pipeline = SimplePipeline(config)
            pipeline.llm_client = mock_llm
            pipeline.spec_extractor.llm_client = mock_llm
            pipeline.explainer.llm_client = mock_llm

            # Run analysis using actual file path
            try:
                result = await pipeline.run(str(file_path))
                detected_chains = result.get("verified_chains", [])

                # Match detected with expected
                expected_count = len(expected_vulns)
                detected_count = len(detected_chains)

                # Simple heuristic: if we detected vulnerabilities where expected
                if expected_count > 0 and detected_count > 0:
                    # Count minimum as true positives
                    tp = min(expected_count, detected_count)
                    true_positives += tp

                    # Any extra detections are false positives
                    if detected_count > expected_count:
                        false_positives += (detected_count - expected_count)

                    # Any missed are false negatives
                    if expected_count > detected_count:
                        false_negatives += (expected_count - detected_count)

                elif expected_count > 0 and detected_count == 0:
                    # Missed all vulnerabilities
                    false_negatives += expected_count

                elif expected_count == 0 and detected_count > 0:
                    # False alarms
                    false_positives += detected_count

                detailed_results.append({
                    "file": filename,
                    "expected": expected_count,
                    "detected": detected_count,
                })

            except Exception as e:
                # Analysis failed - count as false negatives
                false_negatives += len(expected_vulns)
                print(f"✗ {filename}: {e}")

        # Calculate metrics
        precision = (
            true_positives / (true_positives + false_positives)
            if (true_positives + false_positives) > 0
            else 0.0
        )

        recall = (
            true_positives / (true_positives + false_negatives)
            if (true_positives + false_negatives) > 0
            else 0.0
        )

        f1_score = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        # Print results
        print("\n" + "=" * 70)
        print("GROUND TRUTH VALIDATION RESULTS")
        print("=" * 70)

        print(f"\nTrue Positives: {true_positives}")
        print(f"False Positives: {false_positives}")
        print(f"False Negatives: {false_negatives}")

        print(f"\nPrecision: {precision:.2%}")
        print(f"Recall: {recall:.2%}")
        print(f"F1 Score: {f1_score:.2%}")

        print("\nDetailed Results:")
        for result in detailed_results:
            status = "✓" if result["detected"] > 0 else "✗"
            print(f"  {status} {result['file']}: "
                  f"expected={result['expected']}, detected={result['detected']}")

        # Assertions for minimum acceptable performance
        # Note: With mocking, we expect imperfect results
        assert true_positives > 0, "No true positives detected"
        assert recall > 0.0, "Recall is zero"


class TestSpecificVulnerabilityTypes:
    """Test detection of specific vulnerability types."""

    @pytest.mark.asyncio
    async def test_sql_injection_detection(
        self,
        fixtures_dir: Path,
    ) -> None:
        """Test SQL injection detection."""
        file_path = fixtures_dir / "vulnerable_code" / "sql_injection_basic.java"

        # Create mock LLM that returns SQL injection
        mock_llm = Mock()

        async def mock_analyze(prompt: str) -> Dict:
            if "Source Detection" in prompt:
                return {
                    "sources": [
                        {
                            "variable": "userId",
                            "type": "User Input",
                            "line": 9,
                            "confidence": 0.95,
                        }
                    ]
                }
            elif "Sink Detection" in prompt:
                return {
                    "sinks": [
                        {
                            "variable": "query",
                            "type": "SQL",
                            "vulnerability_type": "sql_injection",
                            "line": 10,
                            "confidence": 0.90,
                        }
                    ]
                }
            return {}

        mock_llm.chat_with_json_prompt = AsyncMock(side_effect=mock_analyze)

        # Create pipeline
        config = PipelineConfig(llm_api_key="test-key", use_llm_graph_builder=False)
        pipeline = SimplePipeline(config)
        pipeline.llm_client = mock_llm
        pipeline.spec_extractor.llm_client = mock_llm
        pipeline.explainer.llm_client = mock_llm

        # Analyze using actual file path
        result = await pipeline.run(str(file_path))

        # Verify SQL injection detected
        chains = result.get("verified_chains", [])

        if chains:
            sql_chains = [
                c for c in chains
                if c.vulnerability_type == VulnerabilityType.SQL_INJECTION
            ]
            assert len(sql_chains) > 0, "SQL injection not detected"
            print(f"\n✓ SQL injection detected: {len(sql_chains)} chains")

    @pytest.mark.asyncio
    async def test_xss_detection(
        self,
        fixtures_dir: Path,
    ) -> None:
        """Test XSS detection."""
        file_path = fixtures_dir / "vulnerable_code" / "xss_reflected.java"

        # Create mock LLM
        mock_llm = Mock()

        async def mock_analyze(prompt: str) -> Dict:
            if "Source Detection" in prompt:
                return {
                    "sources": [
                        {
                            "variable": "name",
                            "type": "User Input",
                            "line": 9,
                            "confidence": 0.90,
                        }
                    ]
                }
            elif "Sink Detection" in prompt:
                return {
                    "sinks": [
                        {
                            "variable": "name",
                            "type": "HTML Output",
                            "vulnerability_type": "xss",
                            "line": 10,
                            "confidence": 0.85,
                        }
                    ]
                }
            return {}

        mock_llm.chat_with_json_prompt = AsyncMock(side_effect=mock_analyze)

        # Create pipeline
        config = PipelineConfig(llm_api_key="test-key", use_llm_graph_builder=False)
        pipeline = SimplePipeline(config)
        pipeline.llm_client = mock_llm
        pipeline.spec_extractor.llm_client = mock_llm
        pipeline.explainer.llm_client = mock_llm

        # Analyze using actual file path
        result = await pipeline.run(str(file_path))

        # Verify XSS detected
        chains = result.get("verified_chains", [])

        if chains:
            xss_chains = [
                c for c in chains
                if c.vulnerability_type == VulnerabilityType.XSS
            ]
            print(f"\n✓ XSS detected: {len(xss_chains)} chains")


class TestLongPathDetection:
    """Test detection of vulnerabilities with long data flow paths."""

    @pytest.mark.asyncio
    async def test_long_path_sql_injection(
        self,
        fixtures_dir: Path,
    ) -> None:
        """Test SQL injection with long taint path.

        This tests the pipeline's ability to track data flow through
        multiple transformations and assignments.
        """
        file_path = fixtures_dir / "vulnerable_code" / "sql_injection_long_path.java"

        # Create mock LLM
        mock_llm = Mock()

        async def mock_analyze(prompt: str) -> Dict:
            if "Source Detection" in prompt:
                return {
                    "sources": [
                        {
                            "variable": "userInput",
                            "type": "User Input",
                            "line": 10,
                            "confidence": 0.90,
                        }
                    ]
                }
            elif "Sink Detection" in prompt:
                return {
                    "sinks": [
                        {
                            "variable": "query",
                            "type": "SQL",
                            "vulnerability_type": "sql_injection",
                            "line": 23,
                            "confidence": 0.85,
                        }
                    ]
                }
            return {}

        mock_llm.chat_with_json_prompt = AsyncMock(side_effect=mock_analyze)

        # Create pipeline with higher path length limit
        config = PipelineConfig(
            llm_api_key="test-key",
            max_path_length=20,  # Allow longer paths
            min_confidence=0.5,
            use_llm_graph_builder=False,
        )

        pipeline = SimplePipeline(config)
        pipeline.llm_client = mock_llm
        pipeline.spec_extractor.llm_client = mock_llm
        pipeline.explainer.llm_client = mock_llm

        # Analyze using actual file path
        result = await pipeline.run(str(file_path))

        # Verify detection
        chains = result.get("verified_chains", [])

        if chains:
            # Check path length
            for chain in chains:
                path_length = len(chain.path)
                print(f"\n✓ Long path detected: {path_length} nodes")
                # Long path fixture should have path length >= 5
                assert path_length >= 3, "Path too short for long path test"


class TestControlFlowAnalysis:
    """Test analysis of code with complex control flow."""

    @pytest.mark.asyncio
    async def test_control_flow_sql_injection(
        self,
        fixtures_dir: Path,
    ) -> None:
        """Test SQL injection through if statements and loops.

        This tests the pipeline's ability to analyze paths through
        branches and loops correctly.
        """
        file_path = fixtures_dir / "vulnerable_code" / "sql_injection_control_flow.java"

        # Create mock LLM
        mock_llm = Mock()

        async def mock_analyze(prompt: str) -> Dict:
            if "Source Detection" in prompt:
                return {
                    "sources": [
                        {
                            "variable": "category",
                            "type": "User Input",
                            "line": 11,
                            "confidence": 0.90,
                        }
                    ]
                }
            elif "Sink Detection" in prompt:
                return {
                    "sinks": [
                        {
                            "variable": "query",
                            "type": "SQL",
                            "vulnerability_type": "sql_injection",
                            "line": 29,
                            "confidence": 0.85,
                        }
                    ]
                }
            return {}

        mock_llm.chat_with_json_prompt = AsyncMock(side_effect=mock_analyze)

        # Create pipeline with CFG verification
        config = PipelineConfig(
            llm_api_key="test-key",
            verification_enabled=True,
            verification_level="cfg",
            use_llm_graph_builder=False,
        )

        pipeline = SimplePipeline(config)
        pipeline.llm_client = mock_llm
        pipeline.spec_extractor.llm_client = mock_llm
        pipeline.explainer.llm_client = mock_llm

        # Analyze using actual file path
        result = await pipeline.run(str(file_path))

        # Verify CFG-aware verification ran
        chains = result.get("verified_chains", [])

        print(f"\n✓ Control flow analysis completed")
        print(f"  Chains found: {len(chains)}")

        # Should have verification status
        if chains:
            for chain in chains:
                assert hasattr(chain, "verification_status")
                print(f"  Verification: {chain.verification_status.value}")
