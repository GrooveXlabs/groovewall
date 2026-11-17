"""
Sliding Window Rate Limiter & Runaway Agent Guard.
Prevents rapid infinite loops, denial-of-service, and resource exhaustion.
"""

import time
from collections import defaultdict, deque
from typing import Any, DefaultDict, Deque, Dict
from groovewall.engines.base import InspectionResult, Severity


class RateLimitGuard:
    name: str = "RateLimitGuard"

    def __init__(self, max_calls_per_minute: int = 60, burst_limit: int = 15):
        self.max_calls_per_minute = max_calls_per_minute
        self.burst_limit = burst_limit
        self._history: DefaultDict[str, Deque[float]] = defaultdict(deque)

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> InspectionResult:
        now = time.time()
        window_start = now - 60.0
        records = self._history[tool_name]

        # Purge timestamps older than 60 seconds
        while records and records[0] < window_start:
            records.popleft()

        # Check minute rate limit
        if len(records) >= self.max_calls_per_minute:
            return InspectionResult.deny(
                engine=self.name,
                reason=f"Rate limit exceeded: tool '{tool_name}' exceeded {self.max_calls_per_minute} calls/min",
                violation_code="RATE_LIMIT_EXCEEDED",
                severity=Severity.HIGH,
                metadata={"tool": tool_name, "count": len(records)},
            )

        # Check burst window (last 5 seconds)
        burst_start = now - 5.0
        recent_burst = sum(1 for t in records if t >= burst_start)
        if recent_burst >= self.burst_limit:
            return InspectionResult.deny(
                engine=self.name,
                reason=f"Burst limit exceeded: tool '{tool_name}' exceeded {self.burst_limit} calls in 5 seconds",
                violation_code="BURST_LIMIT_EXCEEDED",
                severity=Severity.HIGH,
                metadata={"tool": tool_name, "burst_count": recent_burst},
            )

        records.append(now)
        return InspectionResult.permit(engine=self.name)
