# GrooveWall: Architecture Map & Domain Model

## 1. Architectural Philosophy: Clean Architecture & Zero-Trust
GrooveWall adheres to **Domain-Driven Design (DDD)** and **Zero-Trust principles**. The core business domain (security rules, cryptographic ledgers, threat evaluation) is completely decoupled from protocols (JSON-RPC), transport layers (stdio, SSE), and frameworks (Click, Rich).

```
┌───────────────────────────────────────────────────────────┐
│                      UI / CLI LAYER                       │
│              (groovewall.cli, Click, Rich)                │
└─────────────────────────────┬─────────────────────────────┘
                              │
┌─────────────────────────────▼─────────────────────────────┐
│                    INTERCEPTION LAYER                     │
│    (groovewall.proxy, Stdio Interceptor, JSON-RPC Router) │
└─────────────────────────────┬─────────────────────────────┘
                              │
┌─────────────────────────────▼─────────────────────────────┐
│                   POLICY SUPERVISOR LAYER                 │
│              (groovewall.proxy.FirewallSupervisor)        │
└──────────────┬──────────────────────────────┬─────────────┘
               │                              │
┌──────────────▼─────────────┐ ┌──────────────▼─────────────┐
│      DETERMINISTIC         │ │       HEURISTIC /          │
│     SECURITY ENGINES       │ │     INTELLIGENCE CORE      │
│  - CommandInjectionGuard   │ │  - Guardian Threat Scorer  │
│  - SSRFGuard               │ │  - Quarantine Engine       │
│  - PathTraversalGuard      │ └────────────────────────────┘
│  - SecretLeakGuard         │                │
│  - RateLimitGuard          │                │
└──────────────┬─────────────┘                │
               │                              │
┌──────────────▼──────────────────────────────▼─────────────┐
│               FORENSIC BLACK BOX AUDIT LAYER              │
│       (groovewall.core.ledger.AuditLedger, HMAC-SHA256)   │
└───────────────────────────────────────────────────────────┘
```

---

## 2. Core Subsystems

### A. Interception & Transport Layer (`groovewall.proxy`)
* **Stdio Interceptor:** Spawns downstream MCP server command as a isolated child subprocess.
* **JSON-RPC Filter:** Parses incoming `tools/call` methods from `sys.stdin`.
* **Zero-Bypass Pipe:** Non-tool messages (`initialize`, `ping`, `resources/*`, `prompts/*`) are passed transparently. Tool execution messages are blocked if non-compliant.

### B. Deterministic Engines (`groovewall.engines.*`)
* Strictly typed implementing the `SecurityEngine` protocol:
  * `CommandInjectionGuard`: AST/regex-based detection of dangerous subshells, reverse shells, download cradles.
  * `SSRFGuard`: RFC 1918 private subnet protection, cloud metadata blocking (`169.254.169.254`), and octal/hex IP evasion detection.
  * `PathTraversalGuard`: Directory traversal, null-byte injection, and restricted project/system path protection.
  * `SecretLeakGuard`: High-entropy regex scanners matching AWS, GitHub, Slack, and private keys.
  * `RateLimitGuard`: Sliding-window token tracking with burst protection.

### C. Guardian Intelligence Core (`groovewall.core.guardian`)
* Maintains stateful telemetry across an agent session.
* Assigns dynamic risk weights per violation (Critical = 60, High = 35, Medium = 15, Low = 5).
* Autonomously quarantines compromised or hallucinating agents when the cumulative threat score hits the threshold.

### D. Cryptographic Audit Ledger (`groovewall.core.ledger`)
* Forensic accountability layer.
* Chained HMAC-SHA256 log (`groovewall_audit.jsonl`).
* Ensures mathematical tamper-evidence for post-incident audits.
