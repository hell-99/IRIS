"""
IRIS  -  Day 4 runner.
Starts the FastAPI risk score API server.

Usage: python3 run_day4.py

Then visit:
    http://localhost:8000/docs     -  interactive API docs
    http://localhost:8000/api/status
    http://localhost:8000/api/metrics
    ws://localhost:8000/ws/live   -  live event stream
"""
import sys
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def check_db():
    """Verify database exists and has data."""
    import sqlite3
    from config import DB_PATH

    db = Path(DB_PATH)
    if not db.exists():
        console.print("[red]fail Database not found.[/red]")
        console.print("[yellow]Run day1, day2, day3 first:[/yellow]")
        console.print("  python3 run_day1.py")
        console.print("  python3 run_day2.py")
        console.print("  python3 run_day3.py")
        return False

    con = sqlite3.connect(DB_PATH)
    total = con.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
    con.close()

    if total == 0:
        console.print("[red]fail Database is empty. Run day1 first.[/red]")
        return False

    console.print(f"[green]ok Database ready | {total} events[/green]")
    return True


def check_deps():
    """Check FastAPI and uvicorn are installed."""
    missing = []
    for pkg in ["fastapi", "uvicorn"]:
        try: __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        console.print(f"[yellow]Installing: {missing}[/yellow]")
        subprocess.run(
            [sys.executable, "-m", "pip", "install"] + missing,
            check=True, capture_output=True
        )
        console.print("[green]ok Dependencies installed[/green]")
    else: console.print("[green]ok Dependencies ready[/green]")


def print_endpoints():
    """Print all available API endpoints."""
    t = Table(show_header=True, header_style="bold cyan")
    t.add_column("Method", style="bold")
    t.add_column("Endpoint")
    t.add_column("Description")

    endpoints = [
        ("GET",  "http://localhost:8000/",                      "Health check"),
        ("GET",  "http://localhost:8000/api/status",            "System overview"),
        ("GET",  "http://localhost:8000/api/risk/{agent_id}",   "Agent risk score"),
        ("GET",  "http://localhost:8000/api/sessions",          "All sessions"),
        ("GET",  "http://localhost:8000/api/sessions/{id}",     "Session detail"),
        ("GET",  "http://localhost:8000/api/detections",        "Divergence analyses"),
        ("GET",  "http://localhost:8000/api/collusion",         "Collusion detections"),
        ("GET",  "http://localhost:8000/api/graphs",            "Attack graph summaries"),
        ("GET",  "http://localhost:8000/api/graphs/{id}",       "Full attack graph"),
        ("GET",  "http://localhost:8000/api/events",            "Raw event stream"),
        ("GET",  "http://localhost:8000/api/metrics",           "Detection metrics"),
        ("WS",   "ws://localhost:8000/ws/live",                 "Real-time stream"),
        ("DOCS", "http://localhost:8000/docs",                  "Interactive API docs"),
    ]

    for method, url, desc in endpoints:
        color = {
            "GET": "green", "WS": "cyan", "DOCS": "yellow"
        }.get(method, "white")
        t.add_row(f"[{color}]{method}[/{color}]", url, desc)

    console.print(t)


def main():
    console.print(Panel(
        "[bold cyan]IRIS  -  Day 4[/bold cyan]\n"
        "FastAPI Risk Score API",
        expand=False
    ))

    console.print("\n[bold]1. Checking dependencies...[/bold]")
    check_deps()

    console.print("\n[bold]2. Checking database...[/bold]")
    if not check_db():
        sys.exit(1)

    console.print("\n[bold]3. API endpoints:[/bold]")
    print_endpoints()

    console.print(Panel(
        "[bold green]Starting IRIS API server...[/bold green]\n"
        "Press Ctrl+C to stop\n\n"
        "[cyan]Interactive docs: http://localhost:8000/docs[/cyan]",
        expand=False
    ))

    # Start uvicorn
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
