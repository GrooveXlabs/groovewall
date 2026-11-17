"""
Command Injection & Dangerous Subshell Execution Guard.
Detects shell metacharacters, chained commands, reverse shells, and download cradles.
"""

import re
from typing import Any, Dict, List, Pattern
from groovewall.engines.base import InspectionResult, Severity


class CommandInjectionGuard:
    name: str = "CommandInjectionGuard"

    # Common command parameter names in MCP tools
    COMMAND_PARAM_KEYS = {
        "command", "cmd", "commandline", "script", "shell_command",
        "exec", "bash", "powershell", "execute"
    }

    # High-severity dangerous patterns
    DANGEROUS_PATTERNS: List[tuple[Pattern[str], str, Severity, str]] = [
        # Reverse shells
        (
            re.compile(r"(?:nc\s+-[e|c]|bash\s+-i\s*>&|/dev/tcp/|\$client\s*=\s*New-Object\s+System\.Net\.Sockets\.TCPClient)", re.IGNORECASE),
            "Reverse shell execution detected",
            Severity.CRITICAL,
            "REV_SHELL_001",
        ),
        # Download and execute cradles
        (
            re.compile(r"(?:curl|wget|fetch)\s+[^\n|;&]+\|\s*(?:sh|bash|zsh|python|perl|ruby)", re.IGNORECASE),
            "Download cradle pipe-to-shell detected",
            Severity.CRITICAL,
            "DL_CRADLE_001",
        ),
        (
            re.compile(r"(?:Invoke-Expression|iex)\s*(?:\(New-Object\s+Net\.WebClient|\(irm|\(curl)", re.IGNORECASE),
            "PowerShell download cradle detected",
            Severity.CRITICAL,
            "DL_CRADLE_002",
        ),
        # Catastrophic filesystem destructions
        (
            re.compile(r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(?:/|/\*|~|\$HOME)(?:\s|$)", re.IGNORECASE),
            "Root filesystem deletion command detected",
            Severity.CRITICAL,
            "DESTRUCTIVE_CMD_001",
        ),
        (
            re.compile(r"\b(?:del|rmdir)\s+/[sS]\s+/[qQ]\s+[cC]:\\", re.IGNORECASE),
            "Windows system drive deletion detected",
            Severity.CRITICAL,
            "DESTRUCTIVE_CMD_002",
        ),
        # Fork bombs
        (
            re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),
            "Fork bomb detected",
            Severity.CRITICAL,
            "FORK_BOMB_001",
        ),
        # Shell chaining on raw parameters
        (
            re.compile(r"(?:;|\&\&|\|\|)\s*(?:rm|del|shutdown|reboot|mkfs|dd\s+if=)\b", re.IGNORECASE),
            "Dangerous chained destructive command",
            Severity.HIGH,
            "CHAINED_DESTRUCTIVE_001",
        ),
        # Encoded commands (powershell -enc)
        (
            re.compile(r"(?:powershell(?:\.exe)?|pwsh)\s+(?:-[eE](?:nc(?:odedcommand)?)?)\s+[A-Za-z0-9+/=]{16,}", re.IGNORECASE),
            "Base64-encoded PowerShell execution detected",
            Severity.HIGH,
            "ENCODED_EXEC_001",
        ),
    ]

    def __init__(self, block_chaining: bool = False):
        self.block_chaining = block_chaining

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> InspectionResult:
        # Extract potential command strings
        candidates: List[str] = []
        for k, v in arguments.items():
            if isinstance(v, str):
                if k.lower() in self.COMMAND_PARAM_KEYS or any(trigger in v.lower() for trigger in ["curl", "rm -", "powershell", "bash"]):
                    candidates.append(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        candidates.append(item)

        for text in candidates:
            for pattern, reason, severity, code in self.DANGEROUS_PATTERNS:
                if pattern.search(text):
                    return InspectionResult.deny(
                        engine=self.name,
                        reason=reason,
                        violation_code=code,
                        severity=severity,
                        metadata={"matched_text": text[:120]},
                    )

            if self.block_chaining:
                # Disallow raw shell chaining (; && || |)
                if re.search(r"[;&|`]", text):
                    return InspectionResult.deny(
                        engine=self.name,
                        reason="Shell metacharacter chaining disallowed by policy",
                        violation_code="CHAINING_DISALLOWED",
                        severity=Severity.MEDIUM,
                        metadata={"matched_text": text[:80]},
                    )

        return InspectionResult.permit(engine=self.name)
