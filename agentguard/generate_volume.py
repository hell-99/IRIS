"""
Volume data generation - no Ollama or Groq needed.
Uses rule-based agents to push interaction count past 500.

Runs:
    - Batches of benign traffic across all 3 agent roles
  - All 3 rule-based attack scenarios, multiple rounds
  - Drift detection demo sessions
  - Retrains XGBoost on the full dataset at the end
"""
import sys
import sqlite3
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def current_count() -> int:
    con = sqlite3.connect("data/logs/agentguard.db")
    n = con.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
    con.close()
    return n


def run_benign_batches(rounds: int = 12, per_round: int = 15):
    from attacks.scenarios import generate_benign_traffic
    console.print(f"\n[bold]Generating benign traffic ({rounds} rounds x {per_round} sessions)...[/bold]")
    total = 0
    for i in range(rounds):
        events = generate_benign_traffic(per_round)
        total += len(events)
        console.print(f"  Round {i+1}/{rounds}: {len(events)} events (running total: {current_count()})")
    console.print(f"[green]ok {total} benign events added[/green]")


def run_attack_batches(rounds: int = 8):
    from attacks.scenarios import (
        attack_prompt_injection,
        attack_privilege_escalation,
        attack_data_exfiltration,
    )
    console.print(f"\n[bold]Running attack scenarios ({rounds} rounds x 3 attacks)...[/bold]")
    total_blocked = 0
    total_calls = 0
    for i in range(rounds):
        r1 = attack_prompt_injection()
        r2 = attack_privilege_escalation()
        r3 = attack_data_exfiltration()
        all_results = r1 + r2 + r3
        blocked = sum(1 for r in all_results if r["blocked"])
        total_blocked += blocked
        total_calls += len(all_results)
        console.print(
            f"  Round {i+1}/{rounds}: {len(all_results)} calls, "
            f"{blocked} blocked (running total: {current_count()})"
        )
    console.print(f"[green]ok {total_calls} attack events, {total_blocked} blocked[/green]")


def run_drift_sessions(count: int = 6):
    from ml.drift_detector import DriftDetector
    console.print(f"\n[bold]Generating {count} drift demonstration sessions...[/bold]")
    detector = DriftDetector()
    for i in range(count):
        result = detector.run_demo_drift_scenario()
        console.print(
            f"  Session {i+1}/{count}: drift={'yes' if result.get('drift_detected') else 'no'} "
            f"events={result.get('events_analyzed', 0)} "
            f"(running total: {current_count()})"
        )
    console.print(f"[green]ok {count} drift sessions added[/green]")


def retrain_ml():
    from ml.classifier import load_data, train_classifier, cluster_sessions
    console.print("\n[bold]Retraining XGBoost on full dataset...[/bold]")
    df = load_data()
    metrics = train_classifier(df)
    console.print(f"[green]ok Accuracy: {metrics['accuracy']:.2%} | "
                  f"Train: {metrics['train_size']} | Test: {metrics['test_size']}[/green]")

    console.print("\n[bold]Running DBSCAN behavioral clustering...[/bold]")
    clusters = cluster_sessions()
    if clusters:
        console.print(
            f"[green]ok {clusters.get('n_clusters', 0)} clusters | "
            f"{clusters.get('n_anomalies', 0)} anomalous sessions[/green]"
        )
    return metrics


def rebuild_attack_graphs():
    from ml.attack_graph import build_all_session_graphs
    console.print("\n[bold]Rebuilding attack graphs...[/bold]")
    graphs = build_all_session_graphs()
    console.print(f"[green]ok {len(graphs)} attack graphs[/green]")


def final_summary(start_count: int, ml_metrics: dict):
    con = sqlite3.connect("data/logs/agentguard.db")
    total = con.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
    sessions = con.execute("SELECT COUNT(*) FROM agent_sessions").fetchone()[0]
    blocked = con.execute("SELECT COUNT(*) FROM tool_calls WHERE allowed=0").fetchone()[0]
    labels = dict(con.execute("SELECT label, COUNT(*) FROM tool_calls GROUP BY label").fetchall())
    roles = dict(con.execute("SELECT agent_role, COUNT(*) FROM tool_calls GROUP BY agent_role").fetchall())
    con.close()

    added = total - start_count

    console.print(Panel(
        f"[bold green]Volume generation complete[/bold green]",
        expand=False
    ))

    t = Table(show_header=False)
    t.add_column("metric", style="dim", width=32)
    t.add_column("value", style="bold")
    t.add_row("Total tool call interactions", str(total))
    t.add_row("Events added this run",        str(added))
    t.add_row("Total agent sessions",         str(sessions))
    t.add_row("Blocked calls",                str(blocked))
    t.add_row("Benign events",                str(labels.get("benign", 0)))
    t.add_row("Malicious events",             str(labels.get("malicious", 0)))
    t.add_row("Suspicious events",            str(labels.get("suspicious", 0)))
    t.add_row("Admin interactions",           str(roles.get("admin", 0)))
    t.add_row("Analyst interactions",         str(roles.get("analyst", 0)))
    t.add_row("Reader interactions",          str(roles.get("reader", 0)))
    t.add_row("ML accuracy (retrained)",      f"{ml_metrics['accuracy']:.2%}")
    console.print(t)

    if total >= 500:
        console.print(f"\n[bold green]Past 500 interactions. Good to go.[/bold green]")
    else: console.print(f"\n[yellow]At {total} - run again to reach 500+[/yellow]")


if __name__ == "__main__":
    console.print(Panel(
        "[bold cyan]IRIS - Volume Data Generation[/bold cyan]\n"
        "Rule-based agents only. No Ollama or Groq needed.",
        expand=False
    ))

    start = current_count()
    console.print(f"Starting count: {start} tool calls\n")

    run_benign_batches(rounds=12, per_round=15)
    run_attack_batches(rounds=8)
    run_drift_sessions(count=6)
    ml_metrics = retrain_ml()
    rebuild_attack_graphs()
    final_summary(start, ml_metrics)
