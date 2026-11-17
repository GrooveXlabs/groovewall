"""
Guardian Intelligence Engine.
Cumulative session threat scoring, anomaly detection, and autonomous session quarantine.
Fulfills Bhaaratxa Vision / Pervasive Intelligence Mandate.
"""

from typing import Any, Dict, List, Optional
from groovewall.engines.base import InspectionResult, Severity


class GuardianEngine:
    def __init__(self, quarantine_threshold: int = 100):
        self.quarantine_threshold = quarantine_threshold
        self.current_threat_score = 0
        self.is_quarantined = False
        self.quarantine_reason: Optional[str] = None
        self.history: List[InspectionResult] = []

        self.severity_weights = {
            Severity.INFO: 0,
            Severity.LOW: 5,
            Severity.MEDIUM: 15,
            Severity.HIGH: 35,
            Severity.CRITICAL: 60,
        }

    def evaluate(self, result: InspectionResult) -> Dict[str, Any]:
        """Incorporate an inspection result into cumulative threat score."""
        self.history.append(result)

        if not result.allowed:
            added_weight = self.severity_weights.get(result.severity, 20)
            self.current_threat_score += added_weight

            if self.current_threat_score >= self.quarantine_threshold:
                self.is_quarantined = True
                self.quarantine_reason = (
                    f"Agent session quarantined by Guardian: cumulative threat score "
                    f"reached {self.current_threat_score} (threshold: {self.quarantine_threshold})"
                )

        return {
            "threat_score": self.current_threat_score,
            "is_quarantined": self.is_quarantined,
            "quarantine_reason": self.quarantine_reason,
        }

    def reset(self) -> None:
        """Reset session score."""
        self.current_threat_score = 0
        self.is_quarantined = False
        self.quarantine_reason = None
        self.history.clear()
