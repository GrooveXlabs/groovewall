"""
GrooveWall Configuration & Policy Schema.
"""

from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import yaml


class EnforcementMode(str, Enum):
    BLOCK = "BLOCK"    # Default: zero-trust reject
    AUDIT = "AUDIT"    # Log violation to ledger, allow execution
    MONITOR = "MONITOR" # Shadow mode


class FirewallPolicy(BaseModel):
    version: str = "1.0.0"
    mode: EnforcementMode = EnforcementMode.BLOCK
    allowed_tools: List[str] = Field(default_factory=list)
    denied_tools: List[str] = Field(default_factory=list)
    
    # Engine toggles
    enable_command_guard: bool = True
    enable_ssrf_guard: bool = True
    enable_path_guard: bool = True
    enable_secret_guard: bool = True
    enable_rate_limit_guard: bool = True
    
    # Detailed parameters
    block_shell_chaining: bool = False
    allow_private_networks: bool = False
    max_calls_per_minute: int = 60
    burst_limit: int = 15
    quarantine_threshold: int = 100
    
    audit_ledger_path: str = "groovewall_audit.jsonl"


def load_policy(policy_path: Optional[str] = None) -> FirewallPolicy:
    """Load policy from YAML file or return default sovereign policy."""
    if policy_path and Path(policy_path).exists():
        with open(policy_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return FirewallPolicy(**data)
    
    default_config_file = Path("groovewall.yaml")
    if default_config_file.exists():
        with open(default_config_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return FirewallPolicy(**data)
            
    return FirewallPolicy()
