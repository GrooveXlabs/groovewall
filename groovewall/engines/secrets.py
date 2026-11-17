"""
Secret & Credential Leakage Guard.
Scans tool call arguments and results for AWS keys, GitHub PATs, private keys, and API tokens.
"""

import re
from typing import Any, Dict, List, Pattern
from groovewall.engines.base import InspectionResult, Severity


class SecretLeakGuard:
    name: str = "SecretLeakGuard"

    PATTERNS: List[tuple[Pattern[str], str, str]] = [
        # AWS Access Key ID
        (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS Access Key ID detected", "SECRET_AWS_KEY"),
        # GitHub Personal Access Token (classic & fine-grained)
        (re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"), "GitHub Personal Access Token detected", "SECRET_GITHUB_PAT"),
        (re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b"), "GitHub Fine-Grained Token detected", "SECRET_GITHUB_FINE_PAT"),
        # Private Keys
        (re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"), "Cryptographic private key detected", "SECRET_PRIVATE_KEY"),
        # Slack Tokens
        (re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"), "Slack Token detected", "SECRET_SLACK_TOKEN"),
        # OpenAI / Anthropic Keys
        (re.compile(r"\bsk-(?:proj-)?[0-9a-zA-Z_-]{20,}\b"), "AI Provider API Key detected", "SECRET_AI_API_KEY"),
        # Generic High-Entropy JWT
        (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "JSON Web Token (JWT) detected", "SECRET_JWT"),
    ]

    def _extract_strings(self, data: Any) -> List[str]:
        collected: List[str] = []
        if isinstance(data, str):
            collected.append(data)
        elif isinstance(data, dict):
            for v in data.values():
                collected.extend(self._extract_strings(v))
        elif isinstance(data, list):
            for item in data:
                collected.extend(self._extract_strings(item))
        return collected

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> InspectionResult:
        strings = self._extract_strings(arguments)

        for text in strings:
            for pattern, reason, code in self.PATTERNS:
                match = pattern.search(text)
                if match:
                    masked = match.group(0)[:6] + "..." + match.group(0)[-4:]
                    return InspectionResult.deny(
                        engine=self.name,
                        reason=reason,
                        violation_code=code,
                        severity=Severity.HIGH,
                        metadata={"masked_match": masked},
                    )

        return InspectionResult.permit(engine=self.name)
