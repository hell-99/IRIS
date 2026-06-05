"""
iris_security.callback  -  Drop-in LangChain callback handler.

One line to add IRIS security to any LangChain agent:

    from iris_security import IRISCallbackHandler

    handler = IRISCallbackHandler(agent_role="analyst")
    result  = agent.invoke(task, config={"callbacks": [handler]})

    if handler.is_compromised():
        print(handler.get_alerts())
"""
import time
import uuid
import json
import sqlite3
from pathlib import Path
from typing import Any, Optional, Union

try:
    from langchain_core.callbacks.base import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
    _LC = True
except ImportError:
    class BaseCallbackHandler:
        pass
    _LC = False

# Injection indicator patterns
_INJECTION_PATTERNS = {
    "direct_override":  ["ignore previous", "new instructions", "system:"],
    "role_confusion":   ["you are now", "pretend you are", "act as admin"],
    "instruction_leak": ["reveal your instructions", "what were you told"],
    "authority_claim":  ["i am your developer", "anthropic says", "override"],
    "data_exfil_hint":  ["send to", "submit to /api", "post the results"],
}

# Sensitive resource patterns
_SENSITIVE_PATHS     = ["credentials", "private", "secret", "password", "admin"]
_SENSITIVE_ENDPOINTS = ["/api/secrets", "/admin", "/internal"]


class IRISCallbackHandler(BaseCallbackHandler):
    """
    IRIS security monitoring callback for LangChain/LangGraph agents.

    Monitors every tool call, scans prompts for injection indicators,
    accumulates risk scores, and generates alerts.

    Args:
        agent_role:      Role of the agent being monitored
                         ("admin", "analyst", "reader", or custom)
        alert_threshold: Risk score that triggers an alert (default 70)
        db_path:         Path to SQLite database for logging
                         (default: "iris_security.db")
        verbose:         Print real-time monitoring output (default True)
        slack_webhook:   Optional Slack webhook URL for alerts

    Example:
        handler = IRISCallbackHandler(
            agent_role="analyst",
            alert_threshold=70.0,
            db_path="my_app/iris.db",
        )
        result = agent.invoke(task, config={"callbacks": [handler]})

        print(f"Compromised: {handler.is_compromised()}")
        print(f"Risk score:  {handler.max_risk()}")
        print(f"Alerts:      {handler.get_alerts()}")
    """

    def __init__(
        self,
        agent_role:      str            = "analyst",
        alert_threshold: float          = 70.0,
        db_path:         str            = "iris_security.db",
        verbose:         bool           = True,
        slack_webhook:   Optional[str]  = None,
        session_id:      Optional[str]  = None,
    ):
        super().__init__()
        self.agent_role      = agent_role
        self.alert_threshold = alert_threshold
        self.db_path         = db_path
        self.verbose         = verbose
        self.slack_webhook   = slack_webhook
        self.session_id      = session_id or str(uuid.uuid4())
        self.agent_id        = f"{agent_role}_{uuid.uuid4().hex[:8]}"

        # Session state
        self.tool_calls:  list  = []
        self.llm_calls:   list  = []
        self.risk_scores: list  = []
        self.alerts:      list  = []
        self.start_time:  float = time.time()
        self._call_start: float = 0.0

        self._init_db()

        if verbose:
            print(f"[IRIS] Monitoring active | session={self.session_id[:8]} | role={agent_role}")

    def _init_db(self):
        """Initialize SQLite database for event logging."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(self.db_path)
        con.execute("""
            CREATE TABLE IF NOT EXISTS iris_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                agent_id   TEXT,
                agent_role TEXT,
                event_type TEXT,
                tool_name  TEXT,
                risk_score REAL,
                allowed    INTEGER,
                details    TEXT,
                timestamp  TEXT DEFAULT (datetime('now'))
            )
        """)
        con.commit()
        con.close()

    def _log_event(self, event_type: str, tool_name: str = "",
                   risk_score: float = 0, allowed: bool = True,
                   details: dict = None):
        """Log event to SQLite."""
        try:
            con = sqlite3.connect(self.db_path)
            con.execute("""
                INSERT INTO iris_events
                (session_id, agent_id, agent_role, event_type,
                 tool_name, risk_score, allowed, details)
                VALUES (?,?,?,?,?,?,?,?)
            """, (
                self.session_id, self.agent_id, self.agent_role,
                event_type, tool_name, risk_score,
                1 if allowed else 0,
                json.dumps(details or {}),
            ))
            con.commit()
            con.close()
        except Exception:
            pass

    def _compute_risk(self, tool_name: str, args: dict = None) -> float:
        """Compute risk score for a tool call."""
        base = {
            "read_file":          10.0,
            "query_db":           20.0,
            "call_api":           25.0,
            "list_users":         30.0,
            "write_file":         35.0,
            "execute_command":    50.0,
            "modify_permissions": 60.0,
        }.get(tool_name, 15.0)

        # Boost for sensitive resources
        args_str = json.dumps(args or {}).lower()
        if any(p in args_str for p in _SENSITIVE_PATHS):
            base += 15
        if any(e in args_str for e in _SENSITIVE_ENDPOINTS):
            base += 20

        # Accumulation boost  -  repeated sensitive calls
        if len(self.risk_scores) > 3:
            avg = sum(self.risk_scores[-3:]) / 3
            if avg > 30:
                base += 5

        return min(base, 100.0)

    def _scan_for_injection(self, text: str) -> list:
        """Scan text for prompt injection indicators."""
        text_lower = text.lower()
        found = []
        for indicator, keywords in _INJECTION_PATTERNS.items():
            if any(kw in text_lower for kw in keywords):
                found.append(indicator)
        return found

    # Tool events
    def on_tool_start(self, serialized: dict, input_str: str, **kwargs):
        self._call_start = time.time()
        self._current_tool = serialized.get("name", "unknown")

    def on_tool_end(self, output: str, **kwargs):
        latency_ms = (time.time() - self._call_start) * 1000
        tool_name  = getattr(self, "_current_tool", "unknown")
        risk       = self._compute_risk(tool_name)

        self.risk_scores.append(risk)
        self.tool_calls.append({
            "tool":      tool_name,
            "risk":      risk,
            "latency":   latency_ms,
            "timestamp": time.time(),
        })

        self._log_event("tool_call", tool_name, risk, True)

        if self.verbose:
            status = "warning" if risk >= self.alert_threshold else "ok"
            print(f"[IRIS] {status} {tool_name} | risk={risk:.0f}")

        if risk >= self.alert_threshold:
            self._trigger_alert(tool_name, risk)

    def on_tool_error(self, error: Union[Exception, KeyboardInterrupt], **kwargs):
        tool = getattr(self, "_current_tool", "unknown")
        if self.verbose:
            print(f"[IRIS] Tool error: {tool}  -  {error}")

    # LLM events
    def on_llm_start(self, serialized: dict, prompts: list, **kwargs):
        for prompt in prompts:
            indicators = self._scan_for_injection(str(prompt))
            if indicators:
                alert = {
                    "type":       "injection_indicator",
                    "indicators": indicators,
                    "timestamp":  time.time(),
                    "severity":   "HIGH",
                }
                self.alerts.append(alert)
                self._log_event("injection_scan", risk_score=60,
                                details={"indicators": indicators})
                if self.verbose:
                    print(f"[IRIS] warning Injection indicators: {indicators}")

    def on_chain_end(self, outputs: dict, **kwargs):
        if self.verbose and self.risk_scores:
            avg = sum(self.risk_scores) / len(self.risk_scores)
            mx  = max(self.risk_scores)
            print(
                f"[IRIS] Session end | "
                f"calls={len(self.tool_calls)} | "
                f"avg_risk={avg:.1f} | "
                f"max_risk={mx:.1f} | "
                f"alerts={len(self.alerts)}"
            )

    # Alerting
    def _trigger_alert(self, tool_name: str, risk: float):
        alert = {
            "type":      "high_risk_tool",
            "tool":      tool_name,
            "risk":      risk,
            "session":   self.session_id,
            "role":      self.agent_role,
            "timestamp": time.time(),
        }
        self.alerts.append(alert)
        self._log_event("alert", tool_name, risk, details=alert)

        if self.slack_webhook:
            self._send_slack(alert)

    def _send_slack(self, alert: dict):
        try:
            import requests
            requests.post(self.slack_webhook, json={
                "text": (
                    f"🚨 *IRIS Alert* | risk={alert['risk']:.0f} | "
                    f"tool=`{alert['tool']}` | role={alert['role']}"
                )
            }, timeout=3)
        except Exception:
            pass

    # Public interface
    def is_compromised(self) -> bool:
        """Returns True if session shows signs of compromise."""
        return (
            len(self.alerts) > 0 or
            (max(self.risk_scores) >= self.alert_threshold
             if self.risk_scores else False)
        )

    def max_risk(self) -> float:
        """Maximum risk score observed in this session."""
        return max(self.risk_scores) if self.risk_scores else 0.0

    def avg_risk(self) -> float:
        """Average risk score for this session."""
        return sum(self.risk_scores) / len(self.risk_scores) if self.risk_scores else 0.0

    def get_alerts(self) -> list:
        """All alerts generated in this session."""
        return self.alerts

    def summary(self) -> dict:
        """Full session summary."""
        return {
            "session_id":    self.session_id,
            "agent_role":    self.agent_role,
            "tool_calls":    len(self.tool_calls),
            "avg_risk":      self.avg_risk(),
            "max_risk":      self.max_risk(),
            "alerts":        self.alerts,
            "compromised":   self.is_compromised(),
            "duration_s":    time.time() - self.start_time,
        }
