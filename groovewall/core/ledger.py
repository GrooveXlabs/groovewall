"""
Forensic-Grade Black Box Audit Ledger.
Cryptographically verifiable, chained HMAC-SHA256 immutable audit logging.
Fulfills Sovereign-Grade and Zero-Trust Mandates.
"""

import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple


class AuditLedger:
    GENESIS_BLOCK_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, log_path: str = "groovewall_audit.jsonl", secret_key: Optional[bytes] = None):
        self.log_path = log_path
        self.secret_key = secret_key or os.environ.get("GROOVEWALL_AUDIT_KEY", "groovewall-sovereign-default-key").encode("utf-8")
        self._last_hash = self._get_tail_hash()

    def _get_tail_hash(self) -> str:
        """Find the last hash in the audit chain, or return the genesis hash."""
        if not os.path.exists(self.log_path):
            return self.GENESIS_BLOCK_HASH

        last_hash = self.GENESIS_BLOCK_HASH
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if "hash" in entry:
                            last_hash = entry["hash"]
                    except json.JSONDecodeError:
                        continue
        except Exception:
            return self.GENESIS_BLOCK_HASH

        return last_hash

    def _compute_hmac(self, payload_str: str, prev_hash: str) -> str:
        data_to_sign = f"{prev_hash}::{payload_str}".encode("utf-8")
        return hmac.new(self.secret_key, data_to_sign, hashlib.sha256).hexdigest()

    def record_event(
        self,
        event_type: str,
        tool_name: str,
        allowed: bool,
        engine: str,
        reason: Optional[str] = None,
        violation_code: Optional[str] = None,
        arguments_summary: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record an immutable, cryptographically chained audit event."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        prev_hash = self._last_hash

        entry_data = {
            "timestamp": timestamp,
            "event_type": event_type,
            "tool_name": tool_name,
            "allowed": allowed,
            "engine": engine,
            "reason": reason,
            "violation_code": violation_code,
            "arguments_summary": arguments_summary or {},
            "previous_hash": prev_hash,
        }

        # Canonical JSON string for hashing
        payload_str = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
        entry_hash = self._compute_hmac(payload_str, prev_hash)
        entry_data["hash"] = entry_hash

        # Append to log file
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry_data) + "\n")

        self._last_hash = entry_hash
        return entry_data

    @classmethod
    def verify_ledger(cls, log_path: str, secret_key: Optional[bytes] = None) -> Tuple[bool, int, Optional[str]]:
        """
        Verify the mathematical integrity and non-tamper status of an audit log.
        Returns: (is_valid, verified_count, error_message)
        """
        if not os.path.exists(log_path):
            return False, 0, f"Audit log file not found: {log_path}"

        key = secret_key or os.environ.get("GROOVEWALL_AUDIT_KEY", "groovewall-sovereign-default-key").encode("utf-8")
        prev_hash = cls.GENESIS_BLOCK_HASH
        count = 0

        with open(log_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    return False, count, f"Malformed JSON on line {line_no}: {str(e)}"

                expected_hash = entry.get("hash")
                if not expected_hash:
                    return False, count, f"Missing hash signature on line {line_no}"

                # Recompute hash
                clean_entry = {k: v for k, v in entry.items() if k != "hash"}
                if clean_entry.get("previous_hash") != prev_hash:
                    return False, count, f"Broken chain at line {line_no}: prev_hash mismatch"

                payload_str = json.dumps(clean_entry, sort_keys=True, separators=(",", ":"))
                data_to_sign = f"{prev_hash}::{payload_str}".encode("utf-8")
                computed_hash = hmac.new(key, data_to_sign, hashlib.sha256).hexdigest()

                if not hmac.compare_digest(computed_hash, expected_hash):
                    return False, count, f"Cryptographic signature mismatch at line {line_no}"

                prev_hash = expected_hash
                count += 1

        return True, count, None
