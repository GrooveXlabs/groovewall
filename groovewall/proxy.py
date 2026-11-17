"""
GrooveWall Proxy & JSON-RPC Stdio Interceptor.
Transparently wraps any MCP server process, enforcing Zero-Trust security rules on every tool call.
"""

import json
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from groovewall.config import EnforcementMode, FirewallPolicy
from groovewall.core.guardian import GuardianEngine
from groovewall.core.ledger import AuditLedger
from groovewall.engines.base import InspectionResult, SecurityEngine, Severity
from groovewall.engines.command import CommandInjectionGuard
from groovewall.engines.path import PathTraversalGuard
from groovewall.engines.ratelimit import RateLimitGuard
from groovewall.engines.secrets import SecretLeakGuard
from groovewall.engines.ssrf import SSRFGuard


@dataclass
class InspectionDecision:
    allowed: bool
    reason: Optional[str] = None
    engine: Optional[str] = None
    violation_code: Optional[str] = None
    severity: Severity = Severity.INFO
    threat_score: int = 0
    quarantined: bool = False


class FirewallSupervisor:
    def __init__(self, policy: FirewallPolicy):
        self.policy = policy
        self.ledger = AuditLedger(log_path=policy.audit_ledger_path)
        self.guardian = GuardianEngine(quarantine_threshold=policy.quarantine_threshold)

        self.engines: List[SecurityEngine] = []
        if policy.enable_command_guard:
            self.engines.append(CommandInjectionGuard(block_chaining=policy.block_shell_chaining))
        if policy.enable_ssrf_guard:
            self.engines.append(SSRFGuard(allow_private_networks=policy.allow_private_networks))
        if policy.enable_path_guard:
            self.engines.append(PathTraversalGuard())
        if policy.enable_secret_guard:
            self.engines.append(SecretLeakGuard())
        if policy.enable_rate_limit_guard:
            self.engines.append(
                RateLimitGuard(
                    max_calls_per_minute=policy.max_calls_per_minute,
                    burst_limit=policy.burst_limit,
                )
            )

    def evaluate_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> InspectionDecision:
        # Check Guardian quarantine status
        if self.guardian.is_quarantined:
            return InspectionDecision(
                allowed=False,
                reason=self.guardian.quarantine_reason or "Session quarantined by Guardian",
                violation_code="SESSION_QUARANTINED",
                severity=Severity.CRITICAL,
                quarantined=True,
                threat_score=self.guardian.current_threat_score,
            )

        # Check explicit policy denylist
        if tool_name in self.policy.denied_tools:
            res = InspectionResult.deny(
                engine="PolicyEnforcer",
                reason=f"Tool '{tool_name}' is explicitly denied by firewall policy",
                violation_code="TOOL_DENIED_BY_POLICY",
                severity=Severity.HIGH,
            )
            g_status = self.guardian.evaluate(res)
            self.ledger.record_event(
                event_type="TOOL_CALL_REJECTED",
                tool_name=tool_name,
                allowed=False,
                engine=res.engine,
                reason=res.reason,
                violation_code=res.violation_code,
                arguments_summary={"tool": tool_name},
            )
            return InspectionDecision(
                allowed=False,
                reason=res.reason,
                engine=res.engine,
                violation_code=res.violation_code,
                severity=res.severity,
                threat_score=g_status["threat_score"],
                quarantined=g_status["is_quarantined"],
            )

        # Check explicit policy allowlist (if configured)
        if self.policy.allowed_tools and tool_name not in self.policy.allowed_tools:
            res = InspectionResult.deny(
                engine="PolicyEnforcer",
                reason=f"Tool '{tool_name}' is not in policy allowed_tools list",
                violation_code="TOOL_NOT_ALLOWLISTED",
                severity=Severity.MEDIUM,
            )
            g_status = self.guardian.evaluate(res)
            self.ledger.record_event(
                event_type="TOOL_CALL_REJECTED",
                tool_name=tool_name,
                allowed=False,
                engine=res.engine,
                reason=res.reason,
                violation_code=res.violation_code,
                arguments_summary={"tool": tool_name},
            )
            return InspectionDecision(
                allowed=False,
                reason=res.reason,
                engine=res.engine,
                violation_code=res.violation_code,
                severity=res.severity,
                threat_score=g_status["threat_score"],
                quarantined=g_status["is_quarantined"],
            )

        # Run all active security engines
        for engine in self.engines:
            result = engine.inspect_tool_call(tool_name, arguments)
            if not result.allowed:
                g_status = self.guardian.evaluate(result)
                self.ledger.record_event(
                    event_type="TOOL_CALL_REJECTED",
                    tool_name=tool_name,
                    allowed=False,
                    engine=result.engine,
                    reason=result.reason,
                    violation_code=result.violation_code,
                    arguments_summary={"tool": tool_name, "meta": result.metadata},
                )

                # In AUDIT mode, we record but allow execution
                is_permitted = (self.policy.mode == EnforcementMode.AUDIT)

                return InspectionDecision(
                    allowed=is_permitted,
                    reason=result.reason,
                    engine=result.engine,
                    violation_code=result.violation_code,
                    severity=result.severity,
                    threat_score=g_status["threat_score"],
                    quarantined=g_status["is_quarantined"],
                )

        # All passed
        self.ledger.record_event(
            event_type="TOOL_CALL_ALLOWED",
            tool_name=tool_name,
            allowed=True,
            engine="GrooveWall",
            arguments_summary={"tool": tool_name},
        )
        return InspectionDecision(
            allowed=True,
            threat_score=self.guardian.current_threat_score,
            quarantined=False,
        )


def run_stdio_interceptor(cmd_args: List[str], policy: FirewallPolicy) -> int:
    """
    Spawns downstream MCP server command as a subprocess, piping and intercepting stdio JSON-RPC streams.
    """
    supervisor = FirewallSupervisor(policy)

    # Launch child process
    child = subprocess.Popen(
        cmd_args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    def relay_stderr():
        if child.stderr:
            for line in child.stderr:
                sys.stderr.write(line)
                sys.stderr.flush()

    def relay_stdout():
        if child.stdout:
            for line in child.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()

    stderr_thread = threading.Thread(target=relay_stderr, daemon=True)
    stdout_thread = threading.Thread(target=relay_stdout, daemon=True)
    stderr_thread.start()
    stdout_thread.start()

    try:
        for line in sys.stdin:
            line_str = line.strip()
            if not line_str:
                continue

            try:
                rpc_msg = json.loads(line_str)
            except json.JSONDecodeError:
                # Not JSON, forward as-is
                if child.stdin:
                    child.stdin.write(line)
                    child.stdin.flush()
                continue

            # Check if this is a tool call request
            is_tool_call = (
                isinstance(rpc_msg, dict)
                and rpc_msg.get("method") == "tools/call"
                and "params" in rpc_msg
            )

            if is_tool_call:
                params = rpc_msg.get("params", {})
                tool_name = params.get("name", "unknown")
                args = params.get("arguments", {})
                req_id = rpc_msg.get("id")

                decision = supervisor.evaluate_tool_call(tool_name, args)

                if not decision.allowed:
                    # Construct JSON-RPC error response and deliver immediately to client
                    err_response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32600,
                            "message": f"GrooveWall Security Violation: {decision.reason} [{decision.violation_code}]",
                            "data": {
                                "engine": decision.engine,
                                "severity": decision.severity,
                                "threat_score": decision.threat_score,
                                "quarantined": decision.quarantined,
                            },
                        },
                    }
                    sys.stdout.write(json.dumps(err_response) + "\n")
                    sys.stdout.flush()
                    continue

            # Forward to child process stdin
            if child.stdin:
                child.stdin.write(line)
                child.stdin.flush()

    except (KeyboardInterrupt, BrokenPipeError):
        pass
    finally:
        child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()

    return child.returncode or 0
