"""
Day 1 smoke test  -  run this to verify everything works before Day 2.
Usage: python run_day1.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import sqlite3

console = Console()

def main():
    console.print(Panel("[bold cyan]AgentGuard  -  Day 1 Smoke Test[/bold cyan]", expand=False))

    # 1. Import check
    console.print("\n[bold]1. Importing modules...[/bold]")
    try:
        from config import AGENT_ROLES
        from agents.tools import TOOL_REGISTRY
        from agents.agent import AdminAgent, AnalystAgent, ReaderAgent
        from interceptor.core import intercept, init_db
        from attacks.scenarios import (generate_benign_traffic,
                                        attack_prompt_injection,
                                        attack_privilege_escalation,
                                        attack_data_exfiltration)
        console.print("  [green]ok All modules imported[/green]")
    except Exception as e:
        console.print(f"  [red]fail Import error: {e}[/red]")
        return

    # 2. Tool registry check
    console.print("\n[bold]2. Tool registry...[/bold]")
    for name, fn in TOOL_REGISTRY.items():
        console.print(f"  [green]ok[/green] {name}")

    # 3. Generate benign traffic
    console.print("\n[bold]3. Generating benign traffic (20 sessions)...[/bold]")
    benign = generate_benign_traffic(20)
    console.print(f"  [green]ok {len(benign)} benign events logged[/green]")

    # 4. Run all 3 attacks
    console.print("\n[bold]4. Running attack scenarios...[/bold]")
    r1 = attack_prompt_injection()
    r2 = attack_privilege_escalation()
    r3 = attack_data_exfiltration()
    total_blocked = sum(1 for r in r1+r2+r3 if r["blocked"])
    console.print(f"  [green]ok {len(r1+r2+r3)} attack events | {total_blocked} blocked[/green]")

    # 5. DB summary
    console.print("\n[bold]5. Database summary...[/bold]")
    con = sqlite3.connect("data/logs/agentguard.db")

    total = con.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
    blocked = con.execute("SELECT COUNT(*) FROM tool_calls WHERE allowed=0").fetchone()[0]
    sessions = con.execute("SELECT COUNT(*) FROM agent_sessions").fetchone()[0]
    ledger = con.execute("SELECT COUNT(*) FROM ledger").fetchone()[0]

    t = Table(show_header=True, header_style="bold cyan")
    t.add_column("Metric");  t.add_column("Value", justify="right")
    t.add_row("Total tool calls",   str(total))
    t.add_row("Blocked calls",      f"[red]{blocked}[/red]")
    t.add_row("Active sessions",    str(sessions))
    t.add_row("Ledger entries",     str(ledger))
    console.print(t)

    # 6. Top risk events
    console.print("\n[bold]6. Top 5 highest-risk events...[/bold]")
    rows = con.execute("""
        SELECT agent_role, tool_name, risk_score, label, ttp_name, allowed
        FROM tool_calls ORDER BY risk_score DESC LIMIT 5
    """).fetchall()
    con.close()

    t2 = Table(show_header=True, header_style="bold red")
    for col in ["Role","Tool","Risk","Label","TTP","Allowed"]:
        t2.add_column(col)
    for row in rows:
        allowed_str = "[green]Yes[/green]" if row[5] else "[red]No[/red]"
        t2.add_row(row[0], row[1], f"{row[2]:.1f}", row[3], row[4] or " - ", allowed_str)
    console.print(t2)

    console.print(Panel(
        "[bold green]Day 1 complete![/bold green]\n"
        "Next: Day 2  -  ML feature extraction + XGBoost classifier\n"
        "DB: data/logs/agentguard.db",
        expand=False
    ))

if __name__ == "__main__":
    main()
