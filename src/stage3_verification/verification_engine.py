"""Verification engine with two-level verification strategy.

Coordinates CFG-based verification and symbolic execution.

Strategy:
1. Fast CFG check (always enabled)
   - If UNREACHABLE -> return FALSE (fast reject)
2. Slow symbolic execution (optional, config-based)
   - If enabled -> run symbolic execution
   - If disabled -> return UNVERIFIABLE
"""

from typing import Dict, List, Optional
from dataclasses import dataclass

from src.core.models import TaintChain, VerificationStatus
from src.core.config import PipelineConfig
from src.stage3_verification.cfg_verifier import CFGVerifier
from src.stage3_verification.symbolic_executor import SymbolicExecutor, SymbolicBackend
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
            logger.info("Symbolic execution enabled")
        else:
            self.symbolic_executor = None
            logger.info("Symbolic execution disabled (set symbolic_execution_enabled=True to enable)")

        logger.info(
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
                logger.info(
                    f"✗ Sanitizer reject: {chain.source.variable_name} -> "
                    f"{chain.sink.variable_name} (effectiveness={max_eff:.0%})"
                )
                chain.verification_status = VerificationStatus.FALSE
                return VerificationResult(
                    status=VerificationStatus.FALSE,
                    cfg_status=VerificationStatus.FALSE,
                    confidence=max_eff,
                    method_used="sanitizer",
                    details=f"Effective sanitizer detected (effectiveness={max_eff:.0%})",
                )

        # ========== LEVEL 1: CFG Check (Fast) ==========
        cfg_status = self.cfg_verifier.verify_chain(chain, source_code)

        # Fast reject: If CFG says unreachable, no need for symbolic execution
        if cfg_status == VerificationStatus.FALSE:
            logger.info(
                f"✗ CFG fast reject: {chain.source.variable_name} -> "
                f"{chain.sink.variable_name} UNREACHABLE"
            )
            result = VerificationResult(
                status=VerificationStatus.FALSE,
                cfg_status=cfg_status,
                symbolic_status=None,
                confidence=0.9,  # High confidence in CFG-based rejection
                method_used="cfg",
                details="CFG analysis shows path is unreachable"
            )
            chain.verification_status = result.status
            return result

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
            # Symbolic execution not enabled
            logger.debug("Symbolic execution disabled, returning based on CFG only")

            result = VerificationResult(
                status=VerificationStatus.UNVERIFIABLE,
                cfg_status=cfg_status,
                symbolic_status=None,
                confidence=0.6,  # Medium confidence with CFG only
                method_used="cfg",
                details="CFG reachable, but symbolic execution disabled (enable for higher confidence)"
            )

        # Update chain with verification status
        chain.verification_status = result.status

        logger.info(
            f"Verification complete: {chain.source.variable_name} -> "
            f"{chain.sink.variable_name} = {result.status.value} "
            f"(confidence: {result.confidence:.2f}, method: {result.method_used})"
        )

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
        logger.info(f"Verifying {len(chains)} chains with VerificationEngine...")

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

        logger.info(
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
