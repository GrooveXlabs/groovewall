"""
GrooveWall CLI Application.
Built with Click & Rich. Adheres to OLED-Black high-contrast aesthetic.
"""

import json
import sys
from typing import Optional
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from groovewall import __version__
from groovewall.config import EnforcementMode, FirewallPolicy, load_policy
from groovewall.core.ledger import AuditLedger
from groovewall.proxy import FirewallSupervisor, run_stdio_interceptor

console = Console()


def print_banner():
    banner = f"""[bold red] ██████╗ [/bold red][bold white]██████╗  ██████╗  ██████╗ ██╗   ██╗███████╗██╗    ██╗ █████╗ ██╗     ██╗     [/bold white]
[bold red]██╔════╝ [/bold red][bold white]██╔══██╗██╔═══██╗██╔═══██╗██║   ██║██╔════╝██║    ██║██╔══██╗██║     ██║     [/bold white]
[bold red]██║  ███╗[/bold red][bold white]██████╔╝██║   ██║██║   ██║██║   ██║█████╗  ██║ █╗ ██║███████║██║     ██║     [/bold white]
[bold red]██║   ██║[/bold red][bold white]██╔══██╗██║   ██║██║   ██║╚██╗ ██╔╝██╔══╝  ██║███╗██║██╔══██║██║     ██║     [/bold white]
[bold red]╚██████╔╝[/bold red][bold white]██║  ██║╚██████╔╝╚██████╔╝ ╚████╔╝ ███████╗╚███╔███╔╝██║  ██║███████╗███████╗[/bold white]
[bold red] ╚═════╝ [/bold red][bold white]╚═╝  ╚═╝ ╚═════╝  ╚═════╝   ╚═══╝  ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝[/bold white]
[dim cyan]  Zero-Trust Runtime Proxy & Security Firewall for Model Context Protocol (v{__version__})[/dim cyan]
[dim yellow]  GrooveXlabs Sovereign Defense Ecosystem[/dim yellow]
"""
    console.print(banner)


@click.group()
@click.version_option(version=__version__)
def main():
    """GrooveWall: Zero-Trust Security Firewall & Runtime Proxy for MCP Servers."""
    pass


@main.command(name="status")
@click.option("--config", "-c", "config_path", help="Path to groovewall.yaml config file.")
def status_cmd(config_path: Optional[str]):
    """Display active firewall configuration and engine health."""
    print_banner()
    policy = load_policy(config_path)

    table = Table(title="[bold green]Active Firewall Status[/bold green]", border_style="dim white")
    table.add_column("Parameter", style="cyan")
    table.add_column("Value", style="bold white")

    table.add_row("Enforcement Mode", f"[bold yellow]{policy.mode.value}[/bold yellow]")
    table.add_row("Command Injection Guard", "✅ Enabled" if policy.enable_command_guard else "❌ Disabled")
    table.add_row("SSRF & Metadata Guard", "✅ Enabled" if policy.enable_ssrf_guard else "❌ Disabled")
    table.add_row("Path Traversal Guard", "✅ Enabled" if policy.enable_path_guard else "❌ Disabled")
    table.add_row("Secret & Token Leak Guard", "✅ Enabled" if policy.enable_secret_guard else "❌ Disabled")
    table.add_row("Rate Limit Guard", f"✅ {policy.max_calls_per_minute} calls/min (Burst: {policy.burst_limit})")
    table.add_row("Guardian Quarantine Threshold", str(policy.quarantine_threshold))
    table.add_row("Audit Ledger Log", f"[underline]{policy.audit_ledger_path}[/underline]")

    console.print(table)


@main.command(name="check")
@click.option("--tool", "-t", required=True, help="Tool name to simulate.")
@click.option("--args", "-a", "args_json", required=True, help="JSON arguments dictionary string.")
@click.option("--config", "-c", "config_path", help="Path to groovewall.yaml config file.")
def check_cmd(tool: str, args_json: str, config_path: Optional[str]):
    """Simulate and inspect a tool call against the security firewall."""
    policy = load_policy(config_path)
    supervisor = FirewallSupervisor(policy)

    try:
        arguments = json.loads(args_json)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Invalid JSON passed to --args:[/bold red] {e}")
        sys.exit(1)

    decision = supervisor.evaluate_tool_call(tool, arguments)

    if decision.allowed:
        console.print(Panel(
            f"[bold green]✔ TOOL CALL PERMITTED[/bold green]\n"
            f"[dim]Tool:[/dim] {tool}\n"
            f"[dim]Cumulative Threat Score:[/dim] {decision.threat_score}",
            title="Firewall Verdict",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[bold red]✖ TOOL CALL BLOCKED[/bold red]\n"
            f"[bold]Reason:[/bold] {decision.reason}\n"
            f"[bold]Engine:[/bold] {decision.engine}\n"
            f"[bold]Violation Code:[/bold] {decision.violation_code}\n"
            f"[bold]Severity:[/bold] {decision.severity.value}\n"
            f"[bold]Threat Score:[/bold] {decision.threat_score}\n"
            f"[bold]Quarantined:[/bold] {decision.quarantined}",
            title="Firewall Security Alert",
            border_style="red",
        ))
        sys.exit(2)


@main.command(name="verify-ledger")
@click.option("--log", "-l", "log_path", default="groovewall_audit.jsonl", help="Path to audit ledger file.")
def verify_ledger_cmd(log_path: str):
    """Verify cryptographic HMAC-SHA256 integrity of the Black Box audit ledger."""
    console.print(f"[cyan]Verifying cryptographic audit chain for:[/cyan] [bold]{log_path}[/bold]")
    is_valid, count, error = AuditLedger.verify_ledger(log_path)

    if is_valid:
        console.print(Panel(
            f"[bold green]✔ LEDGER INTEGRITY VERIFIED[/bold green]\n"
            f"[bold]Entries Verified:[/bold] {count}\n"
            f"[dim]All HMAC-SHA256 blocks are valid. Zero tampering detected.[/dim]",
            title="Forensic Audit Certificate",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[bold red]✖ TAMPERING OR CORRUPTION DETECTED[/bold red]\n"
            f"[bold]Verified Entries Before Failure:[/bold] {count}\n"
            f"[bold]Error:[/bold] {error}",
            title="Forensic Verification Failed",
            border_style="red",
        ))
        sys.exit(1)


@main.command(name="init")
def init_cmd():
    """Generate default sovereign configuration template (groovewall.yaml)."""
    template = """# GrooveWall Security Policy Configuration
version: "1.0.0"
mode: "BLOCK" # Options: BLOCK (enforce zero-trust), AUDIT (log violations only), MONITOR

# Explicit list of permitted tools (empty = allow all tools that pass security engine rules)
allowed_tools: []

# Explicit list of banned tools
denied_tools:
  - "format_disk"
  - "drop_all_tables"

# Deterministic Security Engines
enable_command_guard: true
block_shell_chaining: false

enable_ssrf_guard: true
allow_private_networks: false

enable_path_guard: true

enable_secret_guard: true

enable_rate_limit_guard: true
max_calls_per_minute: 60
burst_limit: 15

# Guardian Intelligence Engine
quarantine_threshold: 100

# Black Box Audit Trail
audit_ledger_path: "groovewall_audit.jsonl"
"""
    with open("groovewall.yaml", "w", encoding="utf-8") as f:
        f.write(template)

    console.print("[bold green]Created groovewall.yaml with sovereign security defaults.[/bold green]")


@main.command(name="run", context_settings=dict(ignore_unknown_options=True))
@click.option("--config", "-c", "config_path", help="Path to groovewall.yaml config file.")
@click.argument("server_cmd", nargs=-1, required=True)
def run_cmd(config_path: Optional[str], server_cmd: tuple[str, ...]):
    """Transparently intercept an MCP server stdio process."""
    policy = load_policy(config_path)
    exit_code = run_stdio_interceptor(list(server_cmd), policy)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
