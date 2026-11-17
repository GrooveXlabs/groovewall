"""
SSRF & Private Network Access Guard.
Detects loopback, private subnets (RFC 1918), link-local metadata endpoints, and obfuscated IPs.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from groovewall.engines.base import InspectionResult, Severity


class SSRFGuard:
    name: str = "SSRFGuard"

    URL_PARAM_KEYS = {
        "url", "uri", "target", "host", "endpoint", "link", "destination"
    }

    # Cloud metadata endpoints
    METADATA_HOSTS = {
        "169.254.169.254",               # AWS, Azure, GCP, OpenStack
        "metadata.google.internal",       # GCP internal
        "100.100.100.200",               # Alibaba Cloud
        "fd00:ec2::254",                 # AWS IPv6
    }

    def __init__(self, allow_private_networks: bool = False):
        self.allow_private_networks = allow_private_networks

    def _extract_urls(self, arguments: Dict[str, Any]) -> List[str]:
        found: List[str] = []
        for k, v in arguments.items():
            if isinstance(v, str):
                if k.lower() in self.URL_PARAM_KEYS or v.startswith(("http://", "https://", "ftp://")):
                    found.append(v)
            elif isinstance(v, dict):
                found.extend(self._extract_urls(v))
        return found

    def _check_host(self, host: str) -> Optional[tuple[str, str, Severity]]:
        clean_host = host.split(":")[0].strip("[]").lower()

        # Check cloud metadata endpoints
        if clean_host in self.METADATA_HOSTS:
            return ("Access to cloud metadata endpoint is blocked", "SSRF_METADATA_001", Severity.CRITICAL)

        if clean_host in {"localhost", "loopback", "0.0.0.0"}:
            if not self.allow_private_networks:
                return ("Access to loopback interface is blocked", "SSRF_LOOPBACK_001", Severity.HIGH)

        # Attempt IP parsing
        try:
            ip = ipaddress.ip_address(clean_host)
            if ip.is_loopback:
                if not self.allow_private_networks:
                    return ("Access to loopback IP is blocked", "SSRF_LOOPBACK_002", Severity.HIGH)
            if ip.is_private and not self.allow_private_networks:
                return (f"Access to private RFC1918 network ({ip}) is blocked", "SSRF_PRIVATE_NET_001", Severity.HIGH)
            if ip.is_link_local:
                return (f"Access to link-local address ({ip}) is blocked", "SSRF_LINK_LOCAL_001", Severity.HIGH)
        except ValueError:
            # Not an IP string directly, check for octal / hex encoded bypasses
            if re.match(r"^(?:0x[0-9a-fA-F]+\.?)+$", clean_host) or re.match(r"^(?:0[0-7]+\.?)+$", clean_host):
                return ("Obfuscated IP representation detected", "SSRF_OBFUSCATED_IP", Severity.CRITICAL)

        return None

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> InspectionResult:
        urls = self._extract_urls(arguments)
        for raw_url in urls:
            parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
            host = parsed.hostname or parsed.netloc

            if not host:
                continue

            violation = self._check_host(host)
            if violation:
                reason, code, severity = violation
                return InspectionResult.deny(
                    engine=self.name,
                    reason=reason,
                    violation_code=code,
                    severity=severity,
                    metadata={"target_host": host, "url": raw_url[:120]},
                )

        return InspectionResult.permit(engine=self.name)
