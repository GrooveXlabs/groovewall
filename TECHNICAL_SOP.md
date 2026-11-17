# GrooveWall: Technical Standard Operating Procedure (SOP)

## 1. Scope & Objective
This SOP defines the deployment, policy configuration, incident verification, and auditing procedures for GrooveWall across enterprise, developer workstation, and sovereign infrastructure environments.

---

## 2. Prerequisites & Environment Setup
* **Runtime:** Python >= 3.10
* **Build Tool:** Hatchling / pip
* **Audit Key:** For production environments, configure `GROOVEWALL_AUDIT_KEY` as a 32+ byte high-entropy secret in your environment variables:
  ```bash
  export GROOVEWALL_AUDIT_KEY="sovereign-production-key-change-me"
  ```

---

## 3. Installation & Verification
1. Install package in editable or wheel mode:
   ```bash
   cd groovewall
   pip install -e .
   ```
2. Verify test suite pass:
   ```bash
   pytest tests/ -v
   ```
3. Verify status output:
   ```bash
   groovewall status
   ```

---

## 4. Operational Modes & Policy Management
Configure `groovewall.yaml` to match your organization's risk tolerance:

* **Enforcement Mode `BLOCK` (Default / Sovereign Standard):**
  Any tool call violating any engine immediately fails with JSON-RPC error code `-32600`. The child MCP server never sees the malicious instruction.
* **Enforcement Mode `AUDIT` (Staging / Discovery):**
  Violations are logged to the cryptographic ledger and Guardian threat scores accumulate, but execution is permitted. Use to baseline existing workflows.
* **Enforcement Mode `MONITOR`:**
  Passive observation mode.

---

## 5. Forensic Audit & Incident Verification
If an agent is suspected of malicious actions, data exfiltration, or breach attempts:

1. Retrieve the audit log `groovewall_audit.jsonl`.
2. Run cryptographic verification:
   ```bash
   groovewall verify-ledger --log /path/to/groovewall_audit.jsonl
   ```
3. If the chain is broken, report the exact line number where the HMAC signature was invalidated.
4. If valid, parse the entries with `jq` or Python to isolate all `TOOL_CALL_REJECTED` events and threat scores.
