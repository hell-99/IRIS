"""
Day 3 runner  -  Cross-agent collusion detection + Attack graphs.
Run after Day 2 is complete.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import sqlite3

console = Console()


def main():
    console.print(Panel(
        "[bold cyan]IRIS  -  Day 3[/bold cyan]\n"
        "Cross-Agent Collusion Detection + Attack Graph Reconstruction",
        expand=False
    ))

    # 1. Retrain ML on existing data
    console.print("\n[bold]1. Retraining ML on current data...[/bold]")
    from ml.classifier import load_data, train_classifier, cluster_sessions
    df = load_data()
    metrics = train_classifier(df)
    console.print(f"[green]ok XGBoost retrained | Accuracy: {metrics['accuracy']:.2%}[/green]")

    # 2. Generate benign multi-agent traffic
    console.print("\n[bold]2. Generating benign multi-agent traffic...[/bold]")
    from attacks.collusion_scenarios import generate_multi_agent_benign
    benign_sessions = generate_multi_agent_benign()
    console.print(f"[green]ok {len(benign_sessions)} benign sessions generated[/green]")

    # 3. Run collusion attacks
    console.print("\n[bold]3. Running collusion attack scenarios...[/bold]")
    from attacks.collusion_scenarios import (
        attack_split_exfiltration,
        attack_recon_escalation,
    )
    s1a, s1b = attack_split_exfiltration()
    s2a, s2b = attack_recon_escalation()
    console.print(f"[green]ok 2 collusion attacks executed[/green]")

    # 4. Collusion detection
    console.print("\n[bold]4. Running cross-agent collusion detection...[/bold]")
    from ml.collusion_detector import CollusionDetector
    cd = CollusionDetector(time_window_seconds=120)
    detections = cd.detect()
    cd.print_detections(detections)
    console.print(f"[green]ok {len(detections)} collusion patterns detected[/green]")

    # 5. Attack graph reconstruction
    console.print("\n[bold]5. Building attack graphs for all sessions...[/bold]")
    from ml.attack_graph import build_all_session_graphs
    graphs = build_all_session_graphs()
    console.print(f"[green]ok {len(graphs)} attack graphs built[/green]")

    # 6. Retrain ML with Day 3 data
    console.print("\n[bold]6. Retraining ML with Day 3 data...[/bold]")
    df2 = load_data()
    metrics2 = train_classifier(df2)
    console.print(f"[green]ok Retrained | Accuracy: {metrics2['accuracy']:.2%}[/green]")

    # 7. Final summary
    console.print("\n[bold]Final database summary...[/bold]")
    con = sqlite3.connect("data/logs/agentguard.db")
    total = con.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
    blocked = con.execute("SELECT COUNT(*) FROM tool_calls WHERE allowed=0").fetchone()[0]
    sessions = con.execute("SELECT COUNT(*) FROM agent_sessions").fetchone()[0]
    div = con.execute("SELECT COUNT(*) FROM divergence_analysis").fetchone()[0]
    collusions = con.execute("SELECT COUNT(*) FROM collusion_detections").fetchone()[0]
    ag_graphs = con.execute("SELECT COUNT(*) FROM attack_graphs").fetchone()[0]
    con.close()

    t = Table(show_header=True, header_style="bold cyan")
    t.add_column("Metric"); t.add_column("Value", justify="right")
    t.add_row("Total tool calls",       str(total))
    t.add_row("Blocked calls",          f"[red]{blocked}[/red]")
    t.add_row("Active sessions",        str(sessions))
    t.add_row("Divergence analyses",    str(div))
    t.add_row("Collusion detections",   f"[red]{collusions}[/red]")
    t.add_row("Attack graphs built",    str(ag_graphs))
    t.add_row("ML accuracy",            f"[green]{metrics2['accuracy']:.2%}[/green]")
    console.print(t)

    console.print(Panel(
        "[bold green]Day 3 complete![/bold green]\n"
        "Next: Day 4  -  OPA policy engine + OpenTelemetry traces\n"
        f"Collusion patterns caught: {collusions}\n"
        f"Attack graphs reconstructed: {ag_graphs}",
        expand=False
    ))


if __name__ == "__main__":
    main()
