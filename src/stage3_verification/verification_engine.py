"""Verification engine with two-level verification strategy.

Coordinates CFG-based verification and symbolic execution.

Strategy:
1. Fast CFG check (always enabled)
   - If UNREACHABLE -> return FALSE (fast reject)
2. Slow symbolic execution (optional, config-based)
   - If enabled -> run symbolic execution
   - If disabled -> return UNVERIFIABLE
"""

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Dict, List, Optional

from src.core.config import PipelineConfig
from src.core.models import TaintChain, VerificationStatus
from src.stage3_verification.cfg_verifier import CFGVerifier
from src.stage3_verification.symbolic_executor import SymbolicExecutor
from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class VerificationResult:
    """Result from verification engine.

    Attributes:
        status: Overall verification status.
        cfg_status: CFG verification result.
        symbolic_status: Symbolic execution result (None if not run).
        confidence: Confidence score (0.0-1.0).
        method_used: Verification method ("cfg", "symbolic", or "cfg+symbolic").
        details: Additional details about verification.
    """
    status: VerificationStatus
    cfg_status: VerificationStatus
    symbolic_status: Optional[VerificationStatus] = None
    confidence: float = 0.5
    method_used: str = "cfg"
    details: str = ""

    def to_dict(self) -> Dict:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "status": self.status.value,
            "cfg_status": self.cfg_status.value,
            "symbolic_status": self.symbolic_status.value if self.symbolic_status else None,
            "confidence": self.confidence,
            "method_used": self.method_used,
            "details": self.details,
        }


class VerificationEngine:
    """Two-level verification engine.

    Combines fast CFG checking with optional symbolic execution.

    Verification strategy:
    1. Always run CFG check first (fast)
       - If CFG says UNREACHABLE -> return FALSE immediately
       - If CFG says VERIFIED -> proceed to step 2

    2. If symbolic_execution_enabled:
       - Run symbolic execution (slow but accurate)
       - Return symbolic execution result
    3. Else:
       - Return UNVERIFIABLE (needs manual check)
    """

    def __init__(
        self,
        config: PipelineConfig,
        max_loop_iterations: int = 10,
        symbolic_timeout: int = 30
    ) -> None:
        """Initialize verification engine.

        Args:
            config: Pipeline configuration.
            max_loop_iterations: Maximum loop iterations for CFG.
            symbolic_timeout: Timeout for symbolic execution in seconds.
        """
        self.config = config
        self.max_loop_iterations = max_loop_iterations
        self.symbolic_timeout = symbolic_timeout

        # Initialize CFG verifier (always used)
        self.cfg_verifier = CFGVerifier(max_loop_iterations=max_loop_iterations)

        # Initialize symbolic executor (optional)
        if config.symbolic_execution_enabled:
            self.symbolic_executor = SymbolicExecutor(
                backend=None,  # Auto-detect
                timeout=symbolic_timeout
            )
            logger.debug("Symbolic execution enabled")
        else:
            self.symbolic_executor = None
            logger.debug(
                "Symbolic execution disabled "
                "(set symbolic_execution_enabled=True to enable)"
            )

        logger.debug(
            f"Initialized VerificationEngine: "
            f"cfg_enabled=True, "
            f"symbolic_enabled={config.symbolic_execution_enabled}"
        )

    def verify_chain(
        self,
        chain: TaintChain,
        source_code: str
    ) -> VerificationResult:
        """Verify a taint chain using two-level strategy.

        Args:
            chain: TaintChain to verify.
            source_code: Source code containing the chain.

        Returns:
            VerificationResult with detailed verification information.
        """
        logger.debug(
            f"Verifying chain: {chain.source.variable_name} -> "
            f"{chain.sink.variable_name}"
        )

        # ========== LEVEL 0: Sanitizer Check (Fast FP Reject) ==========
        if chain.sanitizers_on_path:
            max_eff = max(s.effectiveness for s in chain.sanitizers_on_path)
            if max_eff >= 0.9:
                logger.debug(
                    f"✗ Sanitizer reject: {chain.source.variable_name} -> "
                    f"{chain.sink.variable_name} (effectiveness={max_eff:.0%})"
                )
                result = VerificationResult(
                    status=VerificationStatus.FALSE,
                    cfg_status=VerificationStatus.FALSE,
                    confidence=max_eff,
                    method_used="sanitizer",
                    details=(
                        "Effective sanitizer detected "
                        f"(effectiveness={max_eff:.0%})"
                    ),
                )
                return self._attach_result(chain, result)

        # ========== LEVEL 1: CFG Check (Fast) ==========
        cfg_status = self.cfg_verifier.verify_chain(chain, source_code)

        # The lightweight CFG parser is conservative and incomplete. Failure
        # to find a route is not proof that the route is impossible.
        if cfg_status == VerificationStatus.FALSE:
            if self.cfg_verifier.limit_exceeded:
                details = (
                    "Lightweight CFG skipped due to complexity limit: "
                    f"{self.cfg_verifier.limit_reason}"
                )
            else:
                details = "Lightweight CFG could not establish reachability"
            logger.debug(
                f"? CFG could not establish reachability: "
                f"{chain.source.variable_name} -> {chain.sink.variable_name}"
            )
            result = VerificationResult(
                status=VerificationStatus.UNVERIFIABLE,
                cfg_status=cfg_status,
                symbolic_status=None,
                confidence=0.4,
                method_used="cfg",
                details=details,
            )
            return self._attach_result(chain, result)

        if self.config.verification_level == "cfg":
            result = VerificationResult(
                status=VerificationStatus.VERIFIED,
                cfg_status=cfg_status,
                symbolic_status=None,
                confidence=0.8,
                method_used="cfg",
                details="Independent source CFG establishes control-flow reachability",
            )
            return self._attach_result(chain, result)

        # ========== LEVEL 2: Symbolic Execution (Slow, Optional) ==========
        if self.config.symbolic_execution_enabled and self.symbolic_executor:
            logger.debug("Running symbolic execution (Level 2)")

            symbolic_status = self.symbolic_executor.execute_path(chain, source_code)

            # Determine final status based on symbolic execution
            if symbolic_status == VerificationStatus.VERIFIED:
                final_status = VerificationStatus.VERIFIED
                confidence = 0.95  # High confidence with symbolic execution
                details = "CFG + symbolic execution both confirm vulnerability"
                method = "cfg+symbolic"

            elif symbolic_status == VerificationStatus.FALSE:
                final_status = VerificationStatus.FALSE
                confidence = 0.9
                details = "Symbolic execution shows path constraints unsatisfiable"
                method = "cfg+symbolic"

            else:  # UNVERIFIABLE
                final_status = VerificationStatus.UNVERIFIABLE
                confidence = 0.7  # CFG says yes, but symbolic execution inconclusive
                details = "CFG reachable, but symbolic execution inconclusive"
                method = "cfg+symbolic"

            result = VerificationResult(
                status=final_status,
                cfg_status=cfg_status,
                symbolic_status=symbolic_status,
                confidence=confidence,
                method_used=method,
                details=details
            )

        else:
            logger.debug("Symbolic execution required but disabled")

            result = VerificationResult(
                status=VerificationStatus.UNVERIFIABLE,
                cfg_status=cfg_status,
                symbolic_status=None,
                confidence=0.6,  # Medium confidence with CFG only
                method_used="cfg",
                details="CFG reachable, but required symbolic execution is disabled"
            )

        self._attach_result(chain, result)

        logger.debug(
            f"Verification complete: {chain.source.variable_name} -> "
            f"{chain.sink.variable_name} = {result.status.value} "
            f"(confidence: {result.confidence:.2f}, method: {result.method_used})"
        )

        return result

    @staticmethod
    def _attach_result(
        chain: TaintChain, result: VerificationResult
    ) -> VerificationResult:
        """Persist verification evidence on the chain for downstream reports."""
        chain.verification_status = result.status
        chain.verification_method = result.method_used
        chain.verification_details = result.details
        chain.cfg_verification_status = result.cfg_status
        chain.symbolic_verification_status = result.symbolic_status
        chain.verification_confidence = result.confidence
        return result

    def verify_all_chains(
        self,
        chains: List[TaintChain],
        source_code: str
    ) -> Dict:
        """Verify multiple taint chains.

        Args:
            chains: List of TaintChain objects.
            source_code: Source code containing all chains.

        Returns:
            Dictionary with verification results and statistics.
        """
        logger.debug(f"Verifying {len(chains)} chains with VerificationEngine...")

        verified: List[TaintChain] = []
        false: List[TaintChain] = []
        unverifiable: List[TaintChain] = []
        results: List[VerificationResult] = []

        # Build CFG once for all chains
        self.cfg_verifier.build_cfg(source_code)

        for chain in chains:
            result = self.verify_chain(chain, source_code)
            results.append(result)

            if result.status == VerificationStatus.VERIFIED:
                verified.append(chain)
            elif result.status == VerificationStatus.FALSE:
                false.append(chain)
            else:
                unverifiable.append(chain)

        # Compute statistics
        total = len(chains)
        avg_confidence = sum(r.confidence for r in results) / total if total > 0 else 0.0

        # Count verification methods used
        method_counts = {
            "sanitizer": sum(1 for r in results if r.method_used == "sanitizer"),
            "cfg": sum(1 for r in results if r.method_used == "cfg"),
            "cfg+symbolic": sum(1 for r in results if r.method_used == "cfg+symbolic"),
        }

        logger.debug(
            f"✓ Verification complete: "
            f"{len(verified)} verified, "
            f"{len(false)} false, "
            f"{len(unverifiable)} unverifiable"
        )

        return {
            "verified": verified,
            "false": false,
            "unverifiable": unverifiable,
            "total": total,
            "verification_rate": len(verified) / total if total > 0 else 0.0,
            "avg_confidence": avg_confidence,
            "method_counts": method_counts,
            "results": results,
        }

    def verify_all_chains_scoped(
        self,
        chains: list[TaintChain],
        file_code_map: Mapping[str, str],
    ) -> dict:
        """Verify project chains against only the files they actually touch.

        Building the lightweight CFG from an entire project is both
        semantically ambiguous and unbounded for large batches. Chains that
        share the same file set are grouped so each relevant CFG is still
        built only once.
        """
        normalized_files = {
            path.replace("\\", "/"): path for path in file_code_map
        }

        def resolve_path(reported: str) -> str | None:
            normalized = reported.replace("\\", "/")
            if normalized in normalized_files:
                return normalized_files[normalized]
            matches = [
                original
                for candidate, original in normalized_files.items()
                if candidate.endswith("/" + normalized)
                or normalized.endswith("/" + candidate)
            ]
            return matches[0] if len(matches) == 1 else None

        groups: dict[tuple[str, ...], list[TaintChain]] = defaultdict(list)
        for chain in chains:
            nodes = [chain.source, *chain.path, chain.sink]
            paths = {
                resolved
                for node in nodes
                if (resolved := resolve_path(node.location.file_path)) is not None
            }
            groups[tuple(sorted(paths))].append(chain)

        logger.info(
            f"Scoped verification: {len(chains)} chains in {len(groups)} file group(s)"
        )

        combined = {
            "verified": [],
            "false": [],
            "unverifiable": [],
            "results": [],
        }
        for paths, grouped_chains in groups.items():
            source_code = "\n".join(file_code_map[path] for path in paths)
            group_result = self.verify_all_chains(grouped_chains, source_code)
            for key in combined:
                combined[key].extend(group_result[key])

        results = combined["results"]
        total = len(chains)
        method_counts = {
            "sanitizer": sum(result.method_used == "sanitizer" for result in results),
            "cfg": sum(result.method_used == "cfg" for result in results),
            "cfg+symbolic": sum(
                result.method_used == "cfg+symbolic" for result in results
            ),
        }
        logger.info(
            f"Scoped verification complete: {len(combined['verified'])} confirmed, "
            f"{len(combined['unverifiable'])} unverifiable, "
            f"{len(combined['false'])} rejected"
        )
        return {
            **combined,
            "total": total,
            "verification_rate": len(combined["verified"]) / total if total else 0.0,
            "avg_confidence": (
                sum(result.confidence for result in results) / total if total else 0.0
            ),
            "method_counts": method_counts,
        }

    def get_statistics(self) -> Dict:
        """Get verification engine statistics.

        Returns:
            Dictionary with statistics about verification components.
        """
        stats = {
            "cfg_enabled": True,
            "symbolic_enabled": self.config.symbolic_execution_enabled,
            "max_loop_iterations": self.max_loop_iterations,
            "symbolic_timeout": self.symbolic_timeout,
        }

        # Add CFG info
        stats["cfg"] = self.cfg_verifier.get_cfg_info()

        # Add symbolic executor info
        if self.symbolic_executor:
            stats["symbolic"] = self.symbolic_executor.get_backend_info()
        else:
            stats["symbolic"] = {"enabled": False}

        return stats

    def verify_single_chain_simple(
        self,
        chain: TaintChain,
        source_code: str
    ) -> VerificationStatus:
        """Verify a single chain and return simple status.

        Convenience method that returns just the VerificationStatus.

        Args:
            chain: TaintChain to verify.
            source_code: Source code.

        Returns:
            VerificationStatus.
        """
        result = self.verify_chain(chain, source_code)
        return result.status
