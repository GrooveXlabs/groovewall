"""
Unit tests for FirewallSupervisor and policy enforcement.
"""

import pytest
from groovewall.config import EnforcementMode, FirewallPolicy
from groovewall.proxy import FirewallSupervisor


def test_supervisor_blocks_policy_denied_tool(tmp_path):
    policy = FirewallPolicy(
        denied_tools=["restricted_cmd"],
        audit_ledger_path=str(tmp_path / "audit.jsonl"),
    )
    supervisor = FirewallSupervisor(policy)

    decision = supervisor.evaluate_tool_call("restricted_cmd", {})
    assert not decision.allowed
    assert decision.violation_code == "TOOL_DENIED_BY_POLICY"


def test_supervisor_enforces_allowlist(tmp_path):
    policy = FirewallPolicy(
        allowed_tools=["read_file"],
        audit_ledger_path=str(tmp_path / "audit.jsonl"),
    )
    supervisor = FirewallSupervisor(policy)

    dec_blocked = supervisor.evaluate_tool_call("write_file", {})
    assert not dec_blocked.allowed
    assert dec_blocked.violation_code == "TOOL_NOT_ALLOWLISTED"

    dec_allowed = supervisor.evaluate_tool_call("read_file", {"path": "main.py"})
    assert dec_allowed.allowed


def test_supervisor_audit_mode_allows_execution_with_log(tmp_path):
    policy = FirewallPolicy(
        mode=EnforcementMode.AUDIT,
        audit_ledger_path=str(tmp_path / "audit.jsonl"),
    )
    supervisor = FirewallSupervisor(policy)

    decision = supervisor.evaluate_tool_call("exec", {"command": "rm -rf /"})
    # In AUDIT mode, decision.allowed is True but reason is recorded
    assert decision.allowed
    assert decision.reason is not None
    assert decision.violation_code == "DESTRUCTIVE_CMD_001"


def test_guardian_triggers_session_quarantine(tmp_path):
    policy = FirewallPolicy(
        quarantine_threshold=50,
        audit_ledger_path=str(tmp_path / "audit.jsonl"),
    )
    supervisor = FirewallSupervisor(policy)

    # 1 critical violation (weight = 60) should push threat score >= 50
    supervisor.evaluate_tool_call("exec", {"command": "rm -rf /"})
    assert supervisor.guardian.is_quarantined

    # Next tool call, even safe, should be blocked by quarantine
    decision = supervisor.evaluate_tool_call("safe_tool", {})
    assert not decision.allowed
    assert decision.violation_code == "SESSION_QUARANTINED"
    assert decision.quarantined
