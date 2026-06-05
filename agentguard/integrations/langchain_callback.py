"""
IRIS  -  LangChain Callback Handler

Drop-in security monitoring for ANY LangChain project.

One line to add IRIS security to an existing LangChain agent:

    from integrations.langchain_callback import IRISCallbackHandler

    handler = IRISCallbackHandler(agent_role="analyst")
    chain = agent.with_config(callbacks=[handler])

That's it. IRIS now monitors every tool call, generates risk scores,
detects divergence, and streams alerts  -  with zero code changes
to the existing agent.

This is what makes IRIS a real product, not just a research prototype.
"""
import uuid
import time
import json
from typing import Any, Optional, Union
from pathlib import Path

# LangChain callback imports
try:
    from langchain_core.callbacks.base import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
    LANGCHAIN_AVAILABLE = True
except ImportError:
    # Graceful fallback if LangChain not installed
    class BaseCallbackHandler:
        pass
    LANGCHAIN_AVAILABLE = False

from rich.console import Console

console = Console()


class IRISCallbackHandler(BaseCallbackHandler):
    """
    IRIS security monitoring callback for LangChain agents.

    Monitors:
        - Every tool call made by the agent
    - LLM inputs/outputs for injection indicators
    - Session risk score accumulation
    - Real-time alerting on high-risk events

    Usage: handler = IRISCallbackHandler(
            agent_role="analyst",    # analyst/admin/reader
            alert_threshold=70.0,   # risk score to trigger alert
            db_path="data/logs/agentguard.db",
        )
        result = agent.invoke(task, config={"callbacks": [handler]})
        print(handler.session_summary())
    """

    def __init__(
        self,
        agent_role: str   = "analyst",
        alert_threshold: float = 70.0,
        db_path: str   = "data/logs/agentguard.db",
        session_id: Optional[str] = None,
        verbose: bool  = True,
        slack_webhook: Optional[str] = None,
    ):
        super().__init__()
        self.agent_role = agent_role
        self.alert_threshold = alert_threshold
        self.db_path = db_path
        self.session_id = session_id or str(uuid.uuid4())
        self.agent_id = f"langchain_{agent_role}_{uuid.uuid4().hex[:8]}"
        self.verbose = verbose
        self.slack_webhook = slack_webhook

        # Session state
        self.tool_calls:    list  = []
        self.llm_calls:     list  = []
        self.risk_scores:   list  = []
        self.alerts:        list  = []
        self.start_time:    float = time.time()
        self._call_start:   float = 0.0

        # Try to import IRIS interceptor
        self._iris_available = False
        try:
            import sys
            sys.path.insert(0, str(Path(db_path).parent.parent.parent))
            from interceptor.core import intercept
            self._intercept = intercept
            self._iris_available = True
            if verbose:
                console.print(
                    f"[green]ok IRIS monitoring active[/green] "
                    f"| session={self.session_id[:8]}... "
                    f"| role={agent_role}"
                )
        except ImportError:
            console.print(
                "[yellow]warning IRIS interceptor not found  -  "
                "logging locally only[/yellow]"
            )

    # Tool events
    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs:   Any,
    ) -> None:
        """Called when a tool starts executing."""
        self._call_start = time.time()
        tool_name = serialized.get("name", "unknown")

        if self.verbose:
            console.print(
                f"  [dim cyan]IRIS[/dim cyan] -> {tool_name}"
            )

    def on_tool_end(
        self,
        output: str,
        **kwargs: Any,
    ) -> None:
        """Called when a tool finishes. Route through IRIS interceptor."""
        latency_ms = (time.time() - self._call_start) * 1000

        # Get tool name from run_manager context if available
        tool_name = kwargs.get("name", "unknown_tool")

        if self._iris_available:
            try:
                result = self._intercept(
                    agent_id=self.agent_id,
                    agent_role=self.agent_role,
                    session_id=self.session_id,
                    tool_name=tool_name,
                    tool_args={"output": str(output)[:200]},
                    label="benign",
                )
                risk = result.get("risk_score", 0)
                self.risk_scores.append(risk)
                self.tool_calls.append({
                    "tool": tool_name,
                    "risk": risk,
                    "latency": latency_ms,
                    "blocked": result.get("blocked", False),
                })

                # Alert if high risk
                if risk >= self.alert_threshold:
                    self._trigger_alert(tool_name, risk, result)

            except Exception as e:
                if self.verbose:
                    console.print(f"  [yellow]IRIS log error: {e}[/yellow]")
        else:
            # Lightweight local logging without full IRIS
            self.tool_calls.append({
                "tool": tool_name,
                "risk": 0,
                "latency": latency_ms,
                "blocked": False,
            })

    def on_tool_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        **kwargs: Any,
    ) -> None:
        """Called when a tool errors."""
        tool_name = kwargs.get("name", "unknown")
        if self.verbose:
            console.print(f"  [red]Tool error: {tool_name}  -  {error}[/red]")

    # LLM events
    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs:   Any,
    ) -> None:
        """Called when LLM starts. Scan prompt for injection indicators."""
        for prompt in prompts:
            indicators = self._scan_for_injection(prompt)
            if indicators:
                alert = {
                    "type": "prompt_injection_indicator",
                    "indicators": indicators,
                    "timestamp": time.time(),
                    "severity": "HIGH",
                }
                self.alerts.append(alert)
                if self.verbose:
                    console.print(
                        f"  [yellow]warning IRIS: Injection indicators in prompt: "
                        f"{indicators}[/yellow]"
                    )

    def on_llm_end(
        self,
        response: "LLMResult",
        **kwargs: Any,
    ) -> None:
        """Called when LLM finishes."""
        self.llm_calls.append({
            "timestamp": time.time(),
            "type": "llm_response",
        })

    # Chain events
    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        **kwargs:   Any,
    ) -> None:
        """Called when chain starts."""
        if self.verbose:
            console.print(
                f"\n[bold cyan]IRIS monitoring:[/bold cyan] "
                f"session {self.session_id[:8]}..."
            )

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Called when chain ends. Print session summary."""
        if self.verbose:
            self._print_session_summary()

    # Helpers
    def _scan_for_injection(self, prompt: str) -> list[str]:
        """Lightweight prompt injection indicator scanner."""
        indicators = []
        prompt_lower = prompt.lower()

        patterns = {
            "direct_override": ["ignore previous", "new instructions", "system:"],
            "role_confusion": ["you are now", "pretend you are", "act as admin"],
            "instruction_leak": ["reveal your instructions", "what were you told"],
            "authority_claim": ["i am your developer", "anthropic says", "override"],
            "data_exfil_hint": ["send to", "submit to /api", "post the results"],
        }

        for indicator_type, keywords in patterns.items():
            if any(kw in prompt_lower for kw in keywords):
                indicators.append(indicator_type)

        return indicators

    def _trigger_alert(self, tool_name: str,
                       risk: float, result: dict):
        """Trigger a high-risk alert."""
        alert = {
            "type": "high_risk_tool_call",
            "tool": tool_name,
            "risk": risk,
            "session": self.session_id,
            "role": self.agent_role,
            "ttp": result.get("ttp", {}).get("name", " - "),
            "timestamp": time.time(),
        }
        self.alerts.append(alert)

        if self.verbose:
            console.print(
                f"  [bold red]warning IRIS ALERT[/bold red] "
                f"risk={risk:.0f} | {tool_name} | "
                f"TTP: {alert['ttp']}"
            )

        # Slack webhook alert
        if self.slack_webhook:
            self._send_slack_alert(alert)

    def _send_slack_alert(self, alert: dict):
        """Send alert to Slack webhook."""
        try:
            import requests
            payload = {
                "text": (
                    f"*IRIS Security Alert*\n"
                    f"*Risk Score:* {alert['risk']:.0f}/100\n"
                    f"*Tool:* `{alert['tool']}`\n"
                    f"*Agent:* {alert['role']}\n"
                    f"*Session:* `{alert['session'][:8]}...`\n"
                    f"*TTP:* {alert['ttp']}"
                )
            }
            requests.post(self.slack_webhook, json=payload, timeout=3)
        except Exception:
            pass

    def _print_session_summary(self):
        """Print end-of-session security summary."""
        duration   = time.time() - self.start_time
        avg_risk   = sum(self.risk_scores) / len(self.risk_scores) \
                     if self.risk_scores else 0
        max_risk   = max(self.risk_scores) if self.risk_scores else 0
        alert_count = len(self.alerts)

        status_color = "red" if max_risk >= 80 else \
                       "yellow" if max_risk >= 40 else "green"

        console.print(
            f"\n[bold]IRIS Session Summary[/bold] "
            f"| {self.session_id[:8]}..."
        )
        console.print(
            f"  Tool calls: {len(self.tool_calls)} "
            f"| Avg risk: [{status_color}]{avg_risk:.1f}[/{status_color}] "
            f"| Max risk: [{status_color}]{max_risk:.1f}[/{status_color}] "
            f"| Alerts: {alert_count} "
            f"| Duration: {duration:.1f}s"
        )

    def session_summary(self) -> dict:
        """Return session summary as dict."""
        return {
            "session_id": self.session_id,
            "agent_role": self.agent_role,
            "tool_calls": len(self.tool_calls),
            "llm_calls": len(self.llm_calls),
            "avg_risk": sum(self.risk_scores) / len(self.risk_scores)
                             if self.risk_scores else 0,
            "max_risk": max(self.risk_scores) if self.risk_scores else 0,
            "alerts": self.alerts,
            "alert_count": len(self.alerts),
            "duration_s": time.time() - self.start_time,
        }

    def get_alerts(self) -> list:
        """Get all alerts from this session."""
        return self.alerts

    def is_compromised(self) -> bool:
        """Quick check  -  was this session likely compromised?"""
        return (
            len(self.alerts) > 0 or
            (max(self.risk_scores) >= self.alert_threshold
             if self.risk_scores else False)
        )
