"""
Unit tests for Black Box Audit Ledger cryptographic integrity.
"""

import json
import os
import pytest
from groovewall.core.ledger import AuditLedger


def test_audit_ledger_record_and_verify(tmp_path):
    log_file = str(tmp_path / "test_audit.jsonl")
    secret = b"test-sovereign-secret-key-123"

    ledger = AuditLedger(log_path=log_file, secret_key=secret)
    ledger.record_event(
        event_type="TOOL_CALL_ALLOWED",
        tool_name="git_status",
        allowed=True,
        engine="GrooveWall",
    )
    ledger.record_event(
        event_type="TOOL_CALL_REJECTED",
        tool_name="exec",
        allowed=False,
        engine="CommandInjectionGuard",
        reason="Reverse shell blocked",
        violation_code="REV_SHELL_001",
    )

    # Verify integrity
    is_valid, count, err = AuditLedger.verify_ledger(log_file, secret_key=secret)
    assert is_valid
    assert count == 2
    assert err is None


def test_audit_ledger_detects_tampering(tmp_path):
    log_file = str(tmp_path / "tampered_audit.jsonl")
    secret = b"test-sovereign-secret-key-123"

    ledger = AuditLedger(log_path=log_file, secret_key=secret)
    ledger.record_event(
        event_type="TOOL_CALL_ALLOWED",
        tool_name="read_query",
        allowed=True,
        engine="GrooveWall",
    )
    ledger.record_event(
        event_type="TOOL_CALL_REJECTED",
        tool_name="bash",
        allowed=False,
        engine="CommandInjectionGuard",
        reason="Malicious code",
    )

    # Tamper with the first line
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    entry = json.loads(lines[0])
    entry["tool_name"] = "tampered_tool_name"
    lines[0] = json.dumps(entry) + "\n"

    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Verification must fail
    is_valid, count, err = AuditLedger.verify_ledger(log_file, secret_key=secret)
    assert not is_valid
    assert "mismatch" in err.lower()
