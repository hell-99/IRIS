"""
IRIS  -  Day 5 runner.
Starts both the FastAPI backend and the Streamlit dashboard.

Usage:
    # Terminal 1  -  start the API
    python3 run_day4.py

    # Terminal 2  -  start the dashboard
    python3 run_day5.py

Then open: http://localhost:8501
"""
import sys
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel

console = Console()


def check_api():
    import requests
    try:
        r = requests.get("http://localhost:8000/", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def install_deps():
    deps = ["streamlit", "plotly", "pandas", "requests"]
    missing = []
    for d in deps:
        try: __import__(d.split("[")[0])
        except ImportError:
            missing.append(d)

    if missing:
        console.print(f"[yellow]Installing: {missing}[/yellow]")
        subprocess.run(
            [sys.executable, "-m", "pip", "install"] + missing,
            check=True, capture_output=True
        )
        console.print("[green]ok Installed[/green]")


def main():
    console.print(Panel(
        "[bold cyan]IRIS  -  Day 5[/bold cyan]\n"
        "Live Security Dashboard",
        expand=False
    ))

    console.print("\n[bold]1. Checking dependencies...[/bold]")
    install_deps()

    console.print("\n[bold]2. Checking API...[/bold]")
    if not check_api():
        console.print("[yellow]warning API not running. Start it first:[/yellow]")
        console.print("  [cyan]python3 run_day4.py[/cyan]")
        console.print("\n[dim]Starting dashboard anyway  -  it will show offline status.[/dim]")
    else: console.print("[green]ok API online[/green]")

    console.print(Panel(
        "[bold green]Starting IRIS Dashboard...[/bold green]\n"
        "Opening: [cyan]http://localhost:8501[/cyan]\n\n"
        "Keep [cyan]python3 run_day4.py[/cyan] running in another terminal",
        expand=False
    ))

    subprocess.run([
        sys.executable, "-m", "streamlit", "run",
        "dashboard/app.py",
        "--server.port", "8501",
        "--server.headless", "true",
        "--theme.base", "dark",
        "--theme.backgroundColor", "#0a0e1a",
        "--theme.primaryColor", "#00ff88",
        "--theme.textColor", "#e2e8f0",
    ])


if __name__ == "__main__":
    main()
