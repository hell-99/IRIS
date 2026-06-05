"""
IRIS  -  Unified Launcher

One command to start the complete IRIS platform:
    python3 iris_start.py

Starts:
    - FastAPI backend    -> http://localhost:8000
    - Streamlit dashboard -> http://localhost:8501
    - Live monitoring active

Press Ctrl+C to stop everything.
"""
import sys
import time
import subprocess
import threading
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def check_db():
    import sqlite3
    from config import DB_PATH
    db = Path(DB_PATH)
    if not db.exists():
        return 0
    con = sqlite3.connect(DB_PATH)
    total = con.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
    con.close()
    return total


def stream_output(proc, prefix: str, color: str):
    """Stream subprocess output with prefix."""
    for line in iter(proc.stdout.readline, b''):
        try:
            text = line.decode().rstrip()
            if text:
                console.print(f"[{color}]{prefix}[/{color}] {text}")
        except Exception:
            pass


def main():
    console.clear()
    console.print(Panel(
        "[bold green]IRIS[/bold green]  -  Agentic Identity Risk Intelligence System\n\n"
        "[dim]Starting complete platform...[/dim]",
        width=60,
        border_style="green",
    ))

    # Check database
    total = check_db()
    if total == 0:
        console.print("[yellow]warning No data found. Run the pipeline first:[/yellow]")
        console.print("  python3 run_day1.py")
        console.print("  python3 run_day2.py")
        console.print("  python3 run_day3.py")
        console.print("\n[dim]Or run the demo:[/dim]")
        console.print("  python3 demo_impossible_attack.py")
        sys.exit(1)

    console.print(f"[green]ok Database ready | {total} events[/green]")

    # Install deps silently
    try:
        import uvicorn
        import streamlit
        import fastapi
    except ImportError:
        console.print("[yellow]Installing dependencies...[/yellow]")
        subprocess.run(
            [sys.executable, "-m", "pip", "install",
             "fastapi", "uvicorn", "streamlit", "plotly", "pandas"],
            capture_output=True, check=True
        )

    console.print("\n[bold]Starting services...[/bold]\n")

    # Start API
    api_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.main:app",
         "--host", "0.0.0.0", "--port", "8000", "--log-level", "warning"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    # Wait for API to be ready
    time.sleep(2)
    try:
        import requests
        r = requests.get("http://localhost:8000/", timeout=3)
        if r.status_code == 200:
            console.print("[green]ok API server running  -> http://localhost:8000/docs[/green]")
    except Exception:
        console.print("[yellow]warning API starting...[/yellow]")

    # Start dashboard
    dash_proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run",
         "dashboard/app.py",
         "--server.port", "8501",
         "--server.headless", "true",
         "--theme.base", "dark",
         "--theme.backgroundColor", "#0a0e1a",
         "--theme.primaryColor", "#00ff88",
         "--theme.textColor", "#e2e8f0",
         "--logger.level", "error"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    time.sleep(3)
    console.print("[green]ok Dashboard running  -> http://localhost:8501[/green]")

    # Print final status
    console.print()
    console.print(Panel(
        "[bold green]done IRIS Platform Running[/bold green]\n\n"
        "  [cyan]Dashboard:[/cyan]  http://localhost:8501\n"
        "  [cyan]API:[/cyan]        http://localhost:8000\n"
        "  [cyan]API Docs:[/cyan]   http://localhost:8000/docs\n\n"
        "[dim]Run attacks in a new terminal:[/dim]\n"
        "  [yellow]python3 demo_impossible_attack.py[/yellow]\n\n"
        "[dim]Press Ctrl+C to stop[/dim]",
        border_style="green",
        width=55,
    ))

    # Open dashboard in browser
    try:
        time.sleep(1)
        webbrowser.open("http://localhost:8501")
    except Exception:
        pass

    # Keep running until Ctrl+C
    try:
        while True:
            # Check if processes are still alive
            if api_proc.poll() is not None:
                console.print("[red]warning API server stopped unexpectedly[/red]")
                break
            if dash_proc.poll() is not None:
                console.print("[red]warning Dashboard stopped unexpectedly[/red]")
                break
            time.sleep(2)
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down IRIS...[/yellow]")
        api_proc.terminate()
        dash_proc.terminate()
        api_proc.wait()
        dash_proc.wait()
        console.print("[green]ok IRIS stopped cleanly[/green]")


if __name__ == "__main__":
    main()
