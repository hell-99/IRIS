"""
iris_security.monitor  -  High-level IRIS platform monitor.

Start the full IRIS platform with one call:

    from iris_security import IRISMonitor

    monitor = IRISMonitor(db_path="iris.db")
    monitor.start()  # starts API + dashboard
"""
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Optional


class IRISMonitor:
    """
    High-level IRIS platform monitor.

    Manages the API server and dashboard as subprocesses.
    Call start() to launch everything, stop() to shut down.

    Args:
        db_path:        Path to SQLite database
        api_port:       Port for FastAPI server (default 8000)
        dashboard_port: Port for Streamlit dashboard (default 8501)
        open_browser:   Auto-open dashboard in browser (default True)

    Example:
        monitor = IRISMonitor()
        monitor.start()
        # ... run your agents ...
        monitor.stop()
    """

    def __init__(
        self,
        db_path:        str  = "iris_security.db",
        api_port:       int  = 8000,
        dashboard_port: int  = 8501,
        open_browser:   bool = True,
    ):
        self.db_path        = db_path
        self.api_port       = api_port
        self.dashboard_port = dashboard_port
        self.open_browser   = open_browser
        self._api_proc      = None
        self._dash_proc     = None

    def start(self):
        """Start API server and dashboard."""
        print(f"[IRIS] Starting platform...")
        self._start_api()
        self._start_dashboard()

        if self.open_browser:
            time.sleep(3)
            webbrowser.open(f"http://localhost:{self.dashboard_port}")

        print(f"[IRIS] Platform running:")
        print(f"  Dashboard: http://localhost:{self.dashboard_port}")
        print(f"  API:       http://localhost:{self.api_port}")
        print(f"  API Docs:  http://localhost:{self.api_port}/docs")

    def _start_api(self):
        """Start FastAPI server."""
        # Find the IRIS installation
        iris_path = Path(__file__).parent.parent
        self._api_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn",
             "iris_security.api.main:app",
             "--host", "0.0.0.0",
             "--port", str(self.api_port),
             "--log-level", "warning"],
            cwd=str(iris_path),
        )
        time.sleep(2)
        print(f"[IRIS] API server running -> http://localhost:{self.api_port}/docs")

    def _start_dashboard(self):
        """Start Streamlit dashboard."""
        iris_path  = Path(__file__).parent
        dash_path  = iris_path / "dashboard" / "app.py"

        self._dash_proc = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run",
             str(dash_path),
             "--server.port", str(self.dashboard_port),
             "--server.headless", "true",
             "--theme.base", "dark",
             "--theme.backgroundColor", "#0a0e1a",
             "--theme.primaryColor", "#00ff88",
             "--logger.level", "error"],
        )
        time.sleep(3)
        print(f"[IRIS] Dashboard running -> http://localhost:{self.dashboard_port}")

    def stop(self):
        """Stop all IRIS services."""
        if self._api_proc:
            self._api_proc.terminate()
            self._api_proc.wait()
        if self._dash_proc:
            self._dash_proc.terminate()
            self._dash_proc.wait()
        print("[IRIS] Platform stopped")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
