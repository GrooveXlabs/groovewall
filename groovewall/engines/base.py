"""
Abstract Base Engine and Inspection Result definitions.
Zero-debt, strictly typed.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Protocol


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class InspectionResult:
    allowed: bool
    engine: str
    severity: Severity = Severity.INFO
    reason: Optional[str] = None
    violation_code: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def permit(cls, engine: str, metadata: Optional[Dict[str, Any]] = None) -> "InspectionResult":
        return cls(
            allowed=True,
            engine=engine,
            severity=Severity.INFO,
            metadata=metadata or {},
        )

    @classmethod
    def deny(
        cls,
        engine: str,
        reason: str,
        violation_code: str,
        severity: Severity = Severity.HIGH,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "InspectionResult":
        return cls(
            allowed=False,
            engine=engine,
            severity=severity,
            reason=reason,
            violation_code=violation_code,
            metadata=metadata or {},
        )


class SecurityEngine(Protocol):
    """Protocol for all deterministic and heuristic firewall engines."""
    name: str

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> InspectionResult:
        """Inspect an outgoing tool call arguments dictionary."""
        ...
