"""
IRIS  -  Day 7 Runner

Behavioral drift detection + Policy engine + Comprehensive metrics
+ Package verification.

Usage: python3 run_day7.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import sqlite3
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def check_db():
    from config import DB_PATH
    db = Path(DB_PATH)
    if not db.exists():
        console.print("[red]fail Database not found. Run day1/day2/day3 first.[/red]")
        return False
    con = sqlite3.connect(DB_PATH)
    total = con.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
    con.close()
    console.print(f"[green]ok Database ready | {total} events[/green]")
    return True


def run_drift_detection():
    """Run CUSUM behavioral drift detection  -  genuine slow drift demo."""
    console.print("\n[bold]1. Behavioral Drift Detection (CUSUM)[/bold]")
    try:
        from ml.drift_detector import DriftDetector

        detector = DriftDetector(k=0.5, h=4.0, min_events=8)

        # First: genuine slow-drift demo
        console.print("[bold yellow]Running slow-drift demonstration...[/bold yellow]")
        demo = detector.run_demo_drift_scenario()

        # Then: analyze all real sessions
        results = detector.analyze_all_sessions()
        detector.print_results(results)

        drifted = [r for r in results if r.get("drift_detected")]
        early = [r for r in drifted if r.get("early_warning")]
        console.print(
            f"[green]ok Drift complete | {len(results)} sessions | "
            f"{len(drifted)} drift | {len(early)} early warnings[/green]"
        )
        return results
    except Exception as e:
        console.print(f"[red]fail Drift failed: {e}[/red]")
        import traceback; traceback.print_exc()
        return []


def run_policy_engine():
    """Demonstrate the IRIS policy engine."""
    console.print("\n[bold]2. Policy Engine Demo[/bold]")
    try:
        from config import DB_PATH
        from ml.policy_engine import PolicyEngine
        import uuid

        engine = PolicyEngine(db_path=DB_PATH)

        # Export default policies as YAML
        engine.export_policy_yaml("policies/agent_policies.yaml")

        # Demo evaluations
        test_cases = [
            ("reader",  "read_file",          {"path": "public/readme.txt"}, 10),
            ("reader",  "read_file",          {"path": "private/credentials.txt"}, 12),
            ("reader",  "modify_permissions", {"username": "analyst"}, 100),
            ("analyst", "call_api",           {"endpoint": "/api/secrets"}, 27),
            ("analyst", "query_db",           {"query": "SELECT * FROM employees"}, 20),
            ("admin",   "execute_command",    {"command": "ps aux"}, 46),
        ]

        t = Table(show_header=True, header_style="bold cyan",
                  title="Policy Engine Evaluations")
        t.add_column("Role",     width=10)
        t.add_column("Tool",     width=20)
        t.add_column("Args",     width=30)
        t.add_column("Decision", width=10)
        t.add_column("Rule",     width=25)

        session = str(uuid.uuid4())
        for role, tool, args, risk in test_cases:
            decision = engine.evaluate(role, session, tool, args, risk)
            verdict = "[green]ALLOW[/green]" if decision.allowed else "[red]BLOCK[/red]"
            t.add_row(role, tool, str(args)[:28], verdict, decision.rule_triggered)

        console.print(t)
        console.print("[green]ok Policy engine working | policies/agent_policies.yaml[/green]")
        return True
    except Exception as e:
        console.print(f"[red]fail Policy engine failed: {e}[/red]")
        import traceback; traceback.print_exc()
        return False


def run_comprehensive_metrics():
    """Compute and display multi-layer detection metrics."""
    console.print("\n[bold]3. Comprehensive Detection Metrics[/bold]")
    try:
        from config import DB_PATH
        from ml.comprehensive_metrics import compute_comprehensive_metrics, print_comprehensive_metrics
        m = compute_comprehensive_metrics(DB_PATH)
        print_comprehensive_metrics(m)
        return m
    except Exception as e:
        console.print(f"[red]fail Metrics failed: {e}[/red]")
        import traceback; traceback.print_exc()
        return {}


def verify_package():
    """Verify all files present."""
    console.print("\n[bold]4. Package Verification[/bold]")
    required = [
        "setup.py",
        "agents/groq_agent.py", "agents/langgraph_agent.py",
        "interceptor/core.py",
        "ml/classifier.py", "ml/intent_detector.py",
        "ml/collusion_detector.py", "ml/attack_graph.py",
        "ml/drift_detector.py", "ml/policy_engine.py",
        "ml/comprehensive_metrics.py",
        "exports/sigma_exporter.py", "exports/fingerprint_engine.py",
        "integrations/langchain_callback.py",
        "api/main.py", "dashboard/app.py",
        "run_day1.py", "run_day2.py", "run_day3.py",
        "run_day4.py", "run_day5.py", "run_day6.py", "run_day7.py",
    ]

    missing = [f for f in required if not Path(f).exists()]
    present = len(required) - len(missing)

    if missing:
        for f in missing:
            console.print(f"[red]fail MISSING: {f}[/red]")
    console.print(
        f"[green]ok {present}/{len(required)} files present[/green]"
        + ("  -  package ready" if not missing else "")
    )
    return len(missing) == 0


def main():
    console.print(Panel(
        "[bold cyan]IRIS  -  Day 7[/bold cyan]\n"
        "Drift Detection + Policy Engine + "
        "Comprehensive Metrics + Package Verification",
        expand=False,
    ))

    console.print("\n[bold]0. Checking database...[/bold]")
    if not check_db():
        sys.exit(1)

    drift_results = run_drift_detection()
    policy_ok = run_policy_engine()
    metrics = run_comprehensive_metrics()
    pkg_ok = verify_package()

    drifted = [r for r in drift_results if r.get("drift_detected")]
    early = [r for r in drifted if r.get("early_warning")]

    console.print(Panel(
        "[bold green]done IRIS  -  Complete![/bold green]\n\n"
        f"Drift: {len(drifted)} detected | {len(early)} early warnings\n"
        f"Policy engine: {'ok' if policy_ok else 'fail'}\n"
        f"Comprehensive detection rate: "
        f"{metrics.get('comprehensive_rate', 0)}%\n"
        f"Package: {'ok ready' if pkg_ok else 'warning missing files'}\n\n"
        "Next:\n"
        "  1. Push to GitHub\n"
        "  2. Record 3-min demo video\n"
        "  3. Write Medium blog post\n"
        "  4. Update resume + LinkedIn\n"
        "  5. Start applying\n\n"
        "[cyan]github.com/hell-99/IRIS[/cyan]",
        expand=False,
    ))


if __name__ == "__main__":
    main()
