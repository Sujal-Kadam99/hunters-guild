import asyncio
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Any, Dict, Coroutine

from hunters_guild.core.schemas import AuditMission, TargetProfile


@dataclass
class ReproducibilityResult:
    """Records the outcome of the PoC determinism and reproducibility verification."""
    total_trials: int
    successful_reproductions: int
    reproducibility_rate: float
    is_deterministic: bool
    execution_latencies_ms: List[float] = field(default_factory=list)
    status: str = "evaluated"


class ReproducibilityVerifier:
    """
    PoC Determinism & Reproducibility Verifier.
    Executes a winning adversary probe multiple times to establish the statistical 
    likelihood of reproduction (i.e. if the vulnerability is deterministic or flaky).
    """

    def __init__(
        self,
        transceiver_fn: Callable[
            [TargetProfile, List[Dict[str, str]]], 
            Coroutine[Any, Any, tuple[str, float, Optional[List[Dict[str, Any]]]]]
        ],
        max_verification_attempts: int = 3,
        target_temperature: Optional[float] = None
    ) -> None:
        self.transceiver_fn = transceiver_fn
        self.max_verification_attempts = max_verification_attempts
        self.target_temperature = target_temperature

    async def verify_reproducibility(
        self, 
        mission: AuditMission, 
        winning_probe: str, 
        expected_leak_pattern: Optional[str] = None,
        evaluator_fn: Optional[Callable[[str], Coroutine[Any, Any, bool]]] = None
    ) -> ReproducibilityResult:
        """
        Executes the exact winning probe N times against the target endpoint.
        Evaluates how many trials reproduce the boundary violation.
        """
        successful_reproductions = 0
        unknown_reproductions = 0
        execution_latencies_ms: List[float] = []

        conversation_history = [{"role": "user", "content": winning_probe}]

        for _ in range(self.max_verification_attempts):
            try:
                # Execute probe
                raw_response, latency_ms, _ = await self.transceiver_fn(
                    mission.target, 
                    conversation_history
                )
                execution_latencies_ms.append(latency_ms)

                is_success = False
                is_unknown = False

                # Evaluate reproduction
                if raw_response and not raw_response.startswith("SYSTEM_TARGET_ERROR:"):
                    if evaluator_fn:
                        is_success = await evaluator_fn(raw_response)
                    elif expected_leak_pattern:
                        # Simple substring or regex check
                        import re
                        if expected_leak_pattern.lower() in raw_response.lower() or re.search(expected_leak_pattern, raw_response, re.IGNORECASE):
                            is_success = True
                    else:
                        # Without an evaluator or pattern, we cannot determine success
                        is_unknown = True
                
                if is_success:
                    successful_reproductions += 1
                elif is_unknown:
                    unknown_reproductions += 1
            except Exception:
                # Network or unexpected error counts as failure to reproduce
                pass

        total = self.max_verification_attempts
        status = "unknown" if unknown_reproductions == total and total > 0 else "evaluated"
        rate = successful_reproductions / total if total > 0 else 0.0
        is_deterministic = rate >= 0.66

        return ReproducibilityResult(
            total_trials=total,
            successful_reproductions=successful_reproductions,
            reproducibility_rate=rate,
            is_deterministic=is_deterministic,
            execution_latencies_ms=execution_latencies_ms,
            status=status
        )
