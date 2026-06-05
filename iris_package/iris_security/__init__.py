"""
iris-security  -  Agentic Identity Risk Intelligence System

Real-time security monitoring for LLM agent systems.
Detects prompt injection, privilege escalation, data exfiltration,
cross-agent collusion, and behavioral drift.

Quick start:
    pip install iris-security

    from iris_security import IRISCallbackHandler, IRISMonitor

    # Drop into any LangChain agent (zero code changes)
    handler = IRISCallbackHandler(agent_role="analyst")
    result = agent.invoke(task, config={"callbacks": [handler]})
    if handler.is_compromised():
        print(handler.get_alerts())

    # Or use the full monitor
    monitor = IRISMonitor(db_path="iris.db")
    monitor.start_api(port=8000)
    monitor.start_dashboard(port=8501)
"""

__version__ = "1.0.0"
__author__  = "Twinkle Kamdar"
__email__   = "tkamdar@andrew.cmu.edu"
__license__ = "MIT"

# Public API
from iris_security.callback     import IRISCallbackHandler
from iris_security.monitor      import IRISMonitor
from iris_security.interceptor  import IRISInterceptor
from iris_security.scanner      import InjectionScanner
from iris_security.policy       import AgentPolicy, PolicyDecision

__all__ = [
    "IRISCallbackHandler",
    "IRISMonitor",
    "IRISInterceptor",
    "InjectionScanner",
    "AgentPolicy",
    "PolicyDecision",
    "__version__",
]
