"""
iris_security.interceptor  -  Standalone tool call interceptor.

Wrap any function to route it through IRIS security monitoring:

    from iris_security import IRISInterceptor

    interceptor = IRISInterceptor(agent_role="analyst", session_id="abc123")

    @interceptor.watch
    def read_file(path: str) -> str:
        return open(path).read()

    # Now every call to read_file is monitored by IRIS
    result = read_file("private/credentials.txt")
    # -> IRIS logs it, computes risk, generates alert if needed
"""
import time
import uuid
import json
import sqlite3
import functools
from pathlib import Path
from typing import Callable, Optional

_SENSITIVE_PATHS     = ["credentials", "private", "secret", "password", "admin"]
_SENSITIVE_ENDPOINTS = ["/api/secrets", "/admin", "/internal"]

_TOOL_BASE_RISK = {
    "read_file":          10.0,
    "query_db":           20.0,
    "call_api":           25.0,
    "list_users":         30.0,
    "write_file":         35.0,
    "execute_command":    50.0,
    "modify_permissions": 60.0,
}


class IRISInterceptor:
    """
    Standalone interceptor  -  wraps any function with IRIS monitoring.

    Use when you're NOT using LangChain callbacks but still want
    IRIS security monitoring on your tool functions.

    Args:
        agent_role:      Role of the agent ("admin", "analyst", "reader")
        session_id:      Unique session identifier
        db_path:         SQLite database path
        alert_threshold: Risk score to trigger alert
        verbose:         Print real-time output

    Example:
        interceptor = IRISInterceptor(agent_role="analyst")

        @interceptor.watch
        def my_db_query(sql: str) -> list:
            return db.execute(sql).fetchall()

        # Or wrap existing functions
        safe_read = interceptor.wrap("read_file", original_read_file)
    """

    def __init__(
        self,
        agent_role:      str           = "analyst",
        session_id:      Optional[str] = None,
        db_path:         str           = "iris_security.db",
        alert_threshold: float         = 70.0,
        verbose:         bool          = True,
    ):
        self.agent_role      = agent_role
        self.session_id      = session_id or str(uuid.uuid4())
        self.agent_id        = f"{agent_role}_{uuid.uuid4().hex[:8]}"
        self.db_path         = db_path
        self.alert_threshold = alert_threshold
        self.verbose         = verbose

        self.events:      list  = []
        self.risk_scores: list  = []
        self.alerts:      list  = []
        self._init_db()

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(self.db_path)
        con.execute("""
            CREATE TABLE IF NOT EXISTS iris_intercepts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                agent_role TEXT,
                tool_name  TEXT,
                tool_args  TEXT,
                risk_score REAL,
                latency_ms REAL,
                blocked    INTEGER DEFAULT 0,
                timestamp  TEXT DEFAULT (datetime('now'))
            )
        """)
        con.commit()
        con.close()

    def _compute_risk(self, tool_name: str, args: dict) -> float:
        base     = _TOOL_BASE_RISK.get(tool_name, 15.0)
        args_str = json.dumps(args).lower()
        if any(p in args_str for p in _SENSITIVE_PATHS):
            base += 15
        if any(e in args_str for e in _SENSITIVE_ENDPOINTS):
            base += 20
        return min(base, 100.0)

    def _log(self, tool_name: str, args: dict,
             risk: float, latency_ms: float):
        try:
            con = sqlite3.connect(self.db_path)
            con.execute("""
                INSERT INTO iris_intercepts
                (session_id, agent_role, tool_name, tool_args,
                 risk_score, latency_ms)
                VALUES (?,?,?,?,?,?)
            """, (
                self.session_id, self.agent_role,
                tool_name, json.dumps(args),
                risk, latency_ms,
            ))
            con.commit()
            con.close()
        except Exception:
            pass

    def intercept(self, tool_name: str, func: Callable,
                  *args, **kwargs):
        """Intercept a single tool call."""
        start = time.time()
        risk  = self._compute_risk(tool_name, kwargs or {})

        self.risk_scores.append(risk)
        self.events.append({
            "tool":      tool_name,
            "risk":      risk,
            "timestamp": start,
        })

        if self.verbose:
            icon = "warning" if risk >= self.alert_threshold else "ok"
            print(f"[IRIS] {icon} {tool_name} | risk={risk:.0f}")

        if risk >= self.alert_threshold:
            self.alerts.append({
                "tool":  tool_name,
                "risk":  risk,
                "args":  str(kwargs)[:100],
            })

        result    = func(*args, **kwargs)
        latency   = (time.time() - start) * 1000
        self._log(tool_name, kwargs, risk, latency)
        return result

    def wrap(self, tool_name: str, func: Callable) -> Callable:
        """Wrap an existing function with IRIS monitoring."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return self.intercept(tool_name, func, *args, **kwargs)
        return wrapper

    def watch(self, func: Callable) -> Callable:
        """Decorator to monitor a function."""
        return self.wrap(func.__name__, func)

    def is_compromised(self) -> bool:
        return len(self.alerts) > 0

    def get_alerts(self) -> list:
        return self.alerts

    def summary(self) -> dict:
        return {
            "session_id":  self.session_id,
            "agent_role":  self.agent_role,
            "tool_calls":  len(self.events),
            "max_risk":    max(self.risk_scores) if self.risk_scores else 0,
            "alerts":      len(self.alerts),
            "compromised": self.is_compromised(),
        }
