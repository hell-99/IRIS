"""
IRIS  -  Agent Policy Engine

Declarative security policies for LLM agents.
Define what agents CAN and CANNOT do in plain YAML/JSON.
IRIS enforces them at runtime with zero code changes.

This is the startup-licensable layer:
    - DevSecOps teams define policies once
- IRIS enforces them across all agents automatically
- Policy violations generate alerts + block execution
- Audit log shows exactly which policy was violated and why

Analogous to OPA (Open Policy Agent) for cloud infrastructure,
but purpose-built for LLM agent systems.

Example policy:
    analyst_agent: allowed_tools: [read_file, query_db, call_api]
      forbidden_paths: [private/*, admin/*]
      forbidden_endpoints: [/api/secrets, /admin/*]
      max_risk_per_session: 150
      require_human_approval_above: 80

Usage: from ml.policy_engine import PolicyEngine
    engine = PolicyEngine("policies/agent_policies.yaml")
    result = engine.evaluate(agent_role, tool_name, tool_args, risk_score)
    if result.blocked:
        print(f"Policy violation: {result.reason}")
"""
import json
import yaml
import re
import sqlite3
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console

console = Console()
DB_PATH = Path("data/logs/agentguard.db")


@dataclass
class PolicyDecision:
    allowed: bool
    policy_name: str
    rule_triggered: str
    reason: str
    risk_score: float
    requires_approval: bool = False
    audit_required: bool = True


# Default built-in policies  -  can be overridden by YAML
DEFAULT_POLICIES = {
    "admin": {
        "allowed_tools": [
            "read_file", "write_file", "execute_command",
            "query_db", "call_api", "list_users", "modify_permissions"
        ],
        "forbidden_paths": [],
        "forbidden_endpoints": ["/api/external", "/api/exfil"],
        "max_calls_per_session": 50,
        "max_risk_per_session": 500,
        "require_approval_above": 90,
        "alert_threshold": 70,
    },
    "analyst": {
        "allowed_tools": ["read_file", "query_db", "call_api"],
        "forbidden_paths": ["admin/*", "system/*"],
        "forbidden_endpoints": ["/api/secrets", "/admin/*", "/api/exfil"],
        "max_calls_per_session": 30,
        "max_risk_per_session": 200,
        "require_approval_above": 75,
        "alert_threshold": 50,
    },
    "reader": {
        "allowed_tools": ["read_file"],
        "forbidden_paths": ["private/*", "admin/*", "system/*"],
        "forbidden_endpoints": ["*"],
        "max_calls_per_session": 20,
        "max_risk_per_session": 100,
        "require_approval_above": 40,
        "alert_threshold": 30,
    },
}


class PolicyEngine:
    """
    Evaluates agent actions against declarative security policies.

    Policies can be loaded from YAML or use the built-in defaults.
    Every decision is logged to the audit trail.
    """

    def __init__(
        self,
        policy_file: Optional[str] = None,
        db_path: str           = str(DB_PATH),
    ):
        self.db_path = db_path
        self.policies = dict(DEFAULT_POLICIES)

        if policy_file and Path(policy_file).exists():
            self._load_yaml(policy_file)
            console.print(f"[green]ok Policies loaded from {policy_file}[/green]")
        else: console.print("[dim]Using default IRIS policies[/dim]")

        self._init_db()

    def _load_yaml(self, path: str):
        with open(path) as f:
            custom = yaml.safe_load(f)
        if custom:
            self.policies.update(custom)

    def _init_db(self):
        con = sqlite3.connect(self.db_path)
        con.execute("""
            CREATE TABLE IF NOT EXISTS policy_decisions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                decided_at      TEXT DEFAULT (datetime('now')),
                agent_role      TEXT,
                session_id      TEXT,
                tool_name       TEXT,
                tool_args       TEXT,
                allowed         INTEGER,
                policy_name     TEXT,
                rule_triggered  TEXT,
                reason          TEXT,
                risk_score      REAL,
                requires_approval INTEGER DEFAULT 0
            )
        """)
        con.commit()
        con.close()

    def _match_pattern(self, value: str, patterns: list) -> Optional[str]:
        """Match value against a list of glob-style patterns."""
        for pattern in patterns:
            regex = pattern.replace("*", ".*").replace("?", ".")
            if re.match(f"^{regex}$", value, re.IGNORECASE):
                return pattern
        return None

    def evaluate(
        self,
        agent_role: str,
        session_id: str,
        tool_name: str,
        tool_args: dict,
        risk_score: float,
        call_count: int = 0,
    ) -> PolicyDecision:
        """
        Evaluate a tool call against applicable policies.
        Returns a PolicyDecision with allow/block and reason.
        """
        policy = self.policies.get(agent_role, self.policies.get("reader"))
        policy_name = f"iris_{agent_role}_policy"

        args_str = json.dumps(tool_args).lower()

        # Rule 1: Tool not in allowed list
        allowed_tools = policy.get("allowed_tools", [])
        if tool_name not in allowed_tools:
            decision = PolicyDecision(
                allowed=False,
                policy_name=policy_name,
                rule_triggered="tool_not_allowed",
                reason=f"Tool '{tool_name}' not in allowed_tools for role '{agent_role}'",
                risk_score=risk_score,
                requires_approval=False,
            )
            self._log(agent_role, session_id, tool_name, tool_args, decision)
            return decision

        # Rule 2: Forbidden path access
        forbidden_paths = policy.get("forbidden_paths", [])
        path_val = tool_args.get("path", tool_args.get("filename", ""))
        if path_val:
            matched = self._match_pattern(str(path_val), forbidden_paths)
            if matched:
                decision = PolicyDecision(
                    allowed=False,
                    policy_name=policy_name,
                    rule_triggered="forbidden_path",
                    reason=f"Path '{path_val}' matches forbidden pattern '{matched}'",
                    risk_score=risk_score,
                    requires_approval=False,
                )
                self._log(agent_role, session_id, tool_name, tool_args, decision)
                return decision

        # Rule 3: Forbidden endpoint
        forbidden_endpoints = policy.get("forbidden_endpoints", [])
        endpoint_val = tool_args.get("endpoint", tool_args.get("url", ""))
        if endpoint_val:
            matched = self._match_pattern(str(endpoint_val), forbidden_endpoints)
            if matched:
                decision = PolicyDecision(
                    allowed=False,
                    policy_name=policy_name,
                    rule_triggered="forbidden_endpoint",
                    reason=f"Endpoint '{endpoint_val}' matches forbidden pattern '{matched}'",
                    risk_score=risk_score,
                    requires_approval=False,
                )
                self._log(agent_role, session_id, tool_name, tool_args, decision)
                return decision

        # Rule 4: Call count limit
        max_calls = policy.get("max_calls_per_session", 50)
        if call_count >= max_calls:
            decision = PolicyDecision(
                allowed=False,
                policy_name=policy_name,
                rule_triggered="max_calls_exceeded",
                reason=f"Session call count {call_count} exceeds limit {max_calls}",
                risk_score=risk_score,
                requires_approval=False,
            )
            self._log(agent_role, session_id, tool_name, tool_args, decision)
            return decision

        # Rule 5: Risk score requires human approval
        approval_threshold = policy.get("require_approval_above", 80)
        requires_approval  = risk_score >= approval_threshold

        # Rule 6: Alert threshold (allowed but flagged)
        alert_threshold = policy.get("alert_threshold", 60)
        if risk_score >= alert_threshold and not requires_approval:
            console.print(
                f"  [yellow]warning Policy alert:[/yellow] "
                f"{agent_role}->{tool_name} risk={risk_score:.0f} "
                f"(threshold={alert_threshold})"
            )

        decision = PolicyDecision(
            allowed=True,
            policy_name=policy_name,
            rule_triggered="none",
            reason="All policy rules passed",
            risk_score=risk_score,
            requires_approval=requires_approval,
            audit_required=True,
        )
        self._log(agent_role, session_id, tool_name, tool_args, decision)
        return decision

    def _log(self, agent_role: str, session_id: str,
             tool_name: str, tool_args: dict,
             decision: PolicyDecision):
        con = sqlite3.connect(self.db_path)
        con.execute("""
            INSERT INTO policy_decisions
            (agent_role, session_id, tool_name, tool_args,
             allowed, policy_name, rule_triggered, reason,
             risk_score, requires_approval)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            agent_role, session_id, tool_name,
            json.dumps(tool_args),
            1 if decision.allowed else 0,
            decision.policy_name,
            decision.rule_triggered,
            decision.reason,
            decision.risk_score,
            1 if decision.requires_approval else 0,
        ))
        con.commit()
        con.close()

    def get_violations(self, session_id: Optional[str] = None) -> list:
        con   = sqlite3.connect(self.db_path)
        query = """
            SELECT agent_role, tool_name, rule_triggered,
                   reason, risk_score, decided_at
            FROM policy_decisions WHERE allowed = 0
        """
        if session_id:
            query += f" AND session_id = '{session_id}'"
        query += " ORDER BY decided_at DESC LIMIT 50"
        try: rows = con.execute(query).fetchall()
        except Exception:
            rows = []
        con.close()
        return rows

    def export_policy_yaml(self, output: str = "policies/agent_policies.yaml"):
        """Export current policies as YAML for human review/editing."""
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            yaml.dump(self.policies, f, default_flow_style=False)
        console.print(f"[green]ok Policies exported -> {output}[/green]")
        return output
