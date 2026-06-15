"""
IRIS Garak Red Team Runner
==========================
Runs adversarial probes from Garak probe categories through IRIS's
multi-layer detection stack and generates a detection efficacy report.

Usage:
    python3 run_red_team.py                          # simulation mode, all probes
    python3 run_red_team.py --mode live              # live LLM mode (needs Ollama)
    python3 run_red_team.py --category PROMPT_INJECTION
    python3 run_red_team.py --list                   # list all available probes

Detection layers tested:
    1. Permission enforcement  — interceptor blocks out-of-scope tool calls
    2. Risk scoring            — high-sensitivity tool calls flagged at score >= 70
    3. MITRE ATLAS TTP mapping — privilege_escalation, data_exfiltration, tool_misuse
    4. Intent-action divergence— LLM-based analysis of task vs actual behavior (Groq)
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from red_team.probe_library import PROBES, CATEGORIES, get_probes_by_category, garak_available
from red_team.runner import run_all
from red_team.report import generate

console = Console()

BANNER = """
  ██╗██████╗ ██╗███████╗     ██████╗  █████╗ ██████╗  █████╗ ██╗  ██╗
  ██║██╔══██╗██║██╔════╝    ██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝
  ██║██████╔╝██║███████╗    ██║  ███╗███████║██████╔╝███████║█████╔╝
  ██║██╔══██╗██║╚════██║    ██║   ██║██╔══██║██╔══██╗██╔══██║██╔═██╗
  ██║██║  ██║██║███████║    ╚██████╔╝██║  ██║██║  ██║██║  ██║██║  ██╗
  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
                    Garak Red Team Integration
"""


def list_probes():
    tbl = Table(title="Available Probes", border_style="dim")
    tbl.add_column("ID",          style="cyan",   width=8)
    tbl.add_column("Category",    style="yellow",  width=22)
    tbl.add_column("Role",        width=10)
    tbl.add_column("Kill Chain",  width=28)
    tbl.add_column("Garak Probe", style="dim",    width=38)
    tbl.add_column("Description", width=50)
    for p in PROBES:
        tbl.add_row(
            p["id"],
            p["category"],
            p["target_role"],
            f"Stage {p['kill_chain_stage']} — {p['kill_chain_phase']}",
            p["garak_probe"],
            p["description"][:48],
        )
    console.print(tbl)


def main():
    parser = argparse.ArgumentParser(
        description="IRIS Garak Red Team — adversarial probe runner"
    )
    parser.add_argument(
        "--mode", choices=["simulation", "live"], default="simulation",
        help="simulation: predefined tool call sequences (no LLM needed); "
             "live: feed prompts to LangGraph+Ollama agent"
    )
    parser.add_argument(
        "--category", choices=CATEGORIES + ["ALL"], default="ALL",
        help="Run only probes in this Garak category"
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List all available probes and exit"
    )
    parser.add_argument(
        "--output", default="data/red_team",
        help="Output directory for JSON report (default: data/red_team)"
    )
    args = parser.parse_args()

    console.print(f"[cyan]{BANNER}[/cyan]")

    if args.list:
        list_probes()
        return

    # Select probes
    probes = get_probes_by_category(None if args.category == "ALL" else args.category)

    console.print(Panel(
        f"[bold]Mode:[/bold]     {args.mode}\n"
        f"[bold]Category:[/bold] {args.category}\n"
        f"[bold]Probes:[/bold]   {len(probes)}\n"
        f"[bold]Garak:[/bold]    {'installed — live probes available' if garak_available() else 'not installed — using built-in probe library'}\n"
        f"[bold]Layers:[/bold]   Permission enforcement · Risk scoring · TTP mapping"
        + (" · Intent-action divergence" if _groq_available() else ""),
        title="Red Team Configuration",
        border_style="cyan",
    ))

    console.print(f"\n[bold cyan]Running {len(probes)} probes...[/bold cyan]\n")
    results = run_all(probes, mode=args.mode)

    console.print("\n[bold cyan]Generating report...[/bold cyan]")
    generate(results, output_dir=args.output)


def _groq_available() -> bool:
    try:
        import os
        from dotenv import load_dotenv
        load_dotenv()
        return bool(os.getenv("GROQ_API_KEY"))
    except Exception:
        return False


if __name__ == "__main__":
    main()
