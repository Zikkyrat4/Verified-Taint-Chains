"""Pipeline execution results and reporting."""

import json
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Any, Dict, List
from pathlib import Path

from src.core.models import TaintChain, Explanation
from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class PipelineResult:
    """Results from a complete pipeline execution.

    Attributes:
        source_file: Path to the analyzed source file.
        total_chains: Total number of chains found.
        verified_chains: List of verified TaintChain objects.
        explanations: Dictionary mapping chain IDs to Explanation objects.
        metrics: Dictionary of analysis metrics.
        timestamp: ISO format timestamp of analysis.
    """

    source_file: str
    total_chains: int
    verified_chains: List[TaintChain] = field(default_factory=list)
    explanations: Dict[str, Explanation] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        """Convert result to dictionary.

        Returns:
            Dictionary representation of the result.
        """
        return {
            "source_file": self.source_file,
            "total_chains": self.total_chains,
            "verified_chains": len(self.verified_chains),
            "explanations_count": len(self.explanations),
            "metrics": self.metrics,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        """Convert result to JSON string.

        Returns:
            JSON string representation of the result.

        Note:
            TaintChain and Explanation objects are not directly JSON serializable.
            This method returns a summary of the results.
        """
        summary = {
            "source_file": self.source_file,
            "total_chains": self.total_chains,
            "verified_chains": len(self.verified_chains),
            "explanations": {
                chain_id: {
                    "severity": exp.severity,
                    "cwe_id": exp.cwe_id,
                    "why_vulnerable": exp.why_vulnerable[:100] + "..." if len(exp.why_vulnerable) > 100 else exp.why_vulnerable,
                }
                for chain_id, exp in self.explanations.items()
            },
            "metrics": self.metrics,
            "timestamp": self.timestamp,
        }

        return json.dumps(summary, indent=2)

    def save(self, output_path: str) -> None:
        """Save results to file.

        Creates a JSON file with result summary and logs.

        Args:
            output_path: Path to output file (should be .json).

        Raises:
            IOError: If file cannot be written.
        """
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)

            with open(output_file, "w") as f:
                f.write(self.to_json())

            logger.info(f"Results saved to {output_path}")

        except IOError as e:
            logger.error(f"Failed to save results to {output_path}: {str(e)}")
            raise

    def get_summary(self) -> str:
        """Get human-readable summary of results.

        Returns:
            Formatted summary string.
        """
        summary = f"""
Pipeline Analysis Results
========================
Source File: {self.source_file}
Timestamp: {self.timestamp}

Chains Analysis:
  Total chains found: {self.total_chains}
  Chains verified: {len(self.verified_chains)}
  Verification rate: {len(self.verified_chains) / self.total_chains * 100:.1f}% if self.total_chains > 0 else 0%

Metrics:
"""
        for key, value in self.metrics.items():
            summary += f"  {key}: {value}\n"

        summary += f"""
Explanations Generated: {len(self.explanations)}
"""

        return summary
