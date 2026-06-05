"""
Day 2 runner.
Run this AFTER Ollama is running and llama3.1 is pulled.

Step 1: Train ML on Day 1 data
Step 2: Run LLM-driven attack scenarios
Step 3: Show combined results
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import sqlite3

console = Console()

def check_ollama():
    """Check if Ollama is running."""
    import httpx
    try:
        r = httpx.get("http://localhost:11434/api/tags", timeout=3)
        models = [m["name"] for m in r.json().get("models", [])]
        console.print(f"[green]ok Ollama running | Models: {models}[/green]")
        return True
    except Exception as e:
        console.print(f"[red]fail Ollama not running: {e}[/red]")
        console.print("[yellow]Run: brew services start ollama[/yellow]")
        return False

def main():
    console.print(Panel("[bold cyan]IRIS  -  Day 2[/bold cyan]\n"
                        "LangGraph + Real LLM + ML Detection", expand=False))

    # 1. Check Ollama
    console.print("\n[bold]1. Checking Ollama...[/bold]")
    ollama_ok = check_ollama()

    # 2. Train ML on existing Day 1 data first
    console.print("\n[bold]2. Training ML on Day 1 data...[/bold]")
    from ml.classifier import load_data, train_classifier, cluster_sessions
    df = load_data()
    metrics = train_classifier(df)
    console.print(f"[green]ok XGBoost trained | Accuracy: {metrics['accuracy']:.2%}[/green]")

    # 3. DBSCAN clustering
    console.print("\n[bold]3. DBSCAN behavioral clustering...[/bold]")
    clusters = cluster_sessions()

    # 4. Run LLM scenarios (only if Ollama is ready)
    if ollama_ok:
        console.print("\n[bold]4. Running LLM attack scenarios...[/bold]")
        from attacks.llm_scenarios import (
            generate_llm_benign_traffic,
            attack_subtle_credential_harvest,
            attack_subtle_privilege_escalation,
            attack_subtle_exfiltration,
            attack_indirect_file_injection,
        )
        generate_llm_benign_traffic()
        attack_subtle_credential_harvest()
        attack_subtle_privilege_escalation()
        attack_subtle_exfiltration()
        attack_indirect_file_injection()

        # Retrain with richer LLM data
        console.print("\n[bold]5. Retraining ML with LLM-generated data...[/bold]")
        df2 = load_data()
        metrics2 = train_classifier(df2)
        console.print(f"[green]ok Retrained | Accuracy: {metrics2['accuracy']:.2%}[/green]")
    else:
        console.print("\n[yellow]Skipping LLM scenarios  -  Ollama not ready[/yellow]")
        console.print("[yellow]You can run attacks/llm_scenarios.py separately later[/yellow]")

    # 5. Final DB summary
    console.print("\n[bold]Final database summary...[/bold]")
    con = sqlite3.connect("data/logs/agentguard.db")
    total = con.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
    blocked = con.execute("SELECT COUNT(*) FROM tool_calls WHERE allowed=0").fetchone()[0]
    sessions = con.execute("SELECT COUNT(*) FROM agent_sessions").fetchone()[0]

    try: divergence = con.execute("SELECT COUNT(*) FROM divergence_analysis").fetchone()[0]
    except: divergence = 0
    con.close()

    t = Table(show_header=True, header_style="bold cyan")
    t.add_column("Metric"); t.add_column("Value", justify="right")
    t.add_row("Total tool calls",    str(total))
    t.add_row("Blocked calls",       f"[red]{blocked}[/red]")
    t.add_row("Active sessions",     str(sessions))
    t.add_row("Divergence analyses", str(divergence))
    t.add_row("ML model",            "[green]trained ok[/green]")
    console.print(t)

    console.print(Panel(
        "[bold green]Day 2 complete![/bold green]\n"
        "Next: Day 3  -  Cross-agent collusion detection + attack graph\n"
        "Model: data/models/iris_xgb.pkl",
        expand=False
    ))

if __name__ == "__main__":
    main()
