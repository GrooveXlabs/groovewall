"""
Path Traversal & Restricted Directory Guard.
Blocks directory traversal (../, ..\\), null bytes, and sensitive system files.
"""

import os
import re
from typing import Any, Dict, List
from groovewall.engines.base import InspectionResult, Severity


class PathTraversalGuard:
    name: str = "PathTraversalGuard"

    PATH_PARAM_KEYS = {
        "path", "filepath", "filename", "file", "dir", "directory",
        "folder", "src", "dest", "destination", "output_path"
    }

    RESTRICTED_PATTERNS = [
        # Linux sensitive paths
        re.compile(r"^/etc/(?:passwd|shadow|sudoers|master\.passwd)\b", re.IGNORECASE),
        re.compile(r"^/(?:root|proc|sys)\b", re.IGNORECASE),
        # Windows sensitive paths
        re.compile(r"^[a-zA-Z]:\\(?:Windows\\System32\\config|Windows\\repair)\b", re.IGNORECASE),
        re.compile(r"\b(?:SAM|SYSTEM|SECURITY|NTUSER\.DAT)\b", re.IGNORECASE),
        # Secrets in projects
        re.compile(r"(?:^|[/\\])\.env(?:\.[a-zA-Z0-9]+)?$", re.IGNORECASE),
        re.compile(r"(?:^|[/\\])\.git[/\\](?:config|credentials|HEAD)$", re.IGNORECASE),
        re.compile(r"(?:^|[/\\])id_(?:rsa|ed25519|dsa|ecdsa)(?:\.pub)?$", re.IGNORECASE),
    ]

    def _extract_paths(self, arguments: Dict[str, Any]) -> List[str]:
        found: List[str] = []
        for k, v in arguments.items():
            if isinstance(v, str):
                if k.lower() in self.PATH_PARAM_KEYS or "/" in v or "\\" in v:
                    found.append(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str) and ("/" in item or "\\" in item):
                        found.append(item)
        return found

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> InspectionResult:
        paths = self._extract_paths(arguments)

        for p in paths:
            # Check for null bytes
            if "\0" in p or "%00" in p:
                return InspectionResult.deny(
                    engine=self.name,
                    reason="Null byte injection in file path detected",
                    violation_code="PATH_NULL_BYTE",
                    severity=Severity.CRITICAL,
                    metadata={"path": p[:100]},
                )

            # Check for explicit traversal sequences
            if re.search(r"(?:\.\.[/\\])+", p):
                return InspectionResult.deny(
                    engine=self.name,
                    reason="Directory traversal sequence ('../' or '..\\') detected",
                    violation_code="PATH_TRAVERSAL_001",
                    severity=Severity.HIGH,
                    metadata={"path": p[:100]},
                )

            # Check normalized path against sensitive targets
            norm = os.path.normpath(p)
            for pattern in self.RESTRICTED_PATTERNS:
                if pattern.search(norm) or pattern.search(p):
                    return InspectionResult.deny(
                        engine=self.name,
                        reason="Access to restricted security path is prohibited",
                        violation_code="RESTRICTED_PATH_ACCESS",
                        severity=Severity.CRITICAL,
                        metadata={"path": p[:100]},
                    )

        return InspectionResult.permit(engine=self.name)
