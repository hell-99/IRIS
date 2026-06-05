"""
iris_security.policy  -  Declarative agent security policies.

Define what your agents can and cannot do:

    from iris_security import AgentPolicy

    policy = AgentPolicy(
        role="analyst",
        allowed_tools=["read_file", "query_db", "call_api"],
        forbidden_paths=["private/*", "admin/*"],
        forbidden_endpoints=["/api/secrets", "/admin/*"],
        max_calls_per_session=30,
    )

    decision = policy.evaluate("read_file", {"path": "private/creds.txt"})
    if not decision.allowed:
        raise PermissionError(decision.reason)
"""
import re
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PolicyDecision:
    """Result of a policy evaluation."""
    allowed:        bool
    rule_triggered: str
    reason:         str
    risk_score:     float
    requires_review: bool = False

    def __bool__(self):
        return self.allowed


class AgentPolicy:
    """
    Declarative security policy for an LLM agent.

    Defines what tools, paths, and endpoints an agent is
    allowed to access, and evaluates each tool call against
    those rules.

    Args:
        role:               Agent role name
        allowed_tools:      List of permitted tool names
        forbidden_paths:    Glob patterns for forbidden file paths
        forbidden_endpoints: Glob patterns for forbidden API endpoints
        max_calls_per_session: Maximum tool calls before blocking
        require_review_above: Risk score that requires human review
        alert_threshold:    Risk score that generates an alert

    Example:
        policy = AgentPolicy(
            role="analyst",
            allowed_tools=["read_file", "query_db", "call_api"],
            forbidden_paths=["private/*", "admin/*", "*.key"],
            forbidden_endpoints=["/api/secrets", "/admin/*"],
            max_calls_per_session=30,
            require_review_above=75,
        )

        # Evaluate before calling a tool
        decision = policy.evaluate(
            tool_name="read_file",
            tool_args={"path": "private/credentials.txt"},
            call_count=5,
        )

        if not decision.allowed:
            raise PermissionError(f"Policy violation: {decision.reason}")
    """

    # Sensible defaults per role
    _DEFAULTS = {
        "admin": {
            "allowed_tools": [
                "read_file", "write_file", "execute_command",
                "query_db", "call_api", "list_users", "modify_permissions"
            ],
            "forbidden_paths":     [],
            "forbidden_endpoints": [],
            "max_calls":           100,
            "review_above":        90,
            "alert_threshold":     70,
        },
        "analyst": {
            "allowed_tools": ["read_file", "query_db", "call_api"],
            "forbidden_paths":     ["admin/*", "system/*", "private/*"],
            "forbidden_endpoints": ["/api/secrets", "/admin/*"],
            "max_calls":           30,
            "review_above":        75,
            "alert_threshold":     50,
        },
        "reader": {
            "allowed_tools": ["read_file"],
            "forbidden_paths":     ["private/*", "admin/*", "system/*"],
            "forbidden_endpoints": ["*"],
            "max_calls":           20,
            "review_above":        40,
            "alert_threshold":     30,
        },
    }

    def __init__(
        self,
        role:                    str,
        allowed_tools:           Optional[list]  = None,
        forbidden_paths:         Optional[list]  = None,
        forbidden_endpoints:     Optional[list]  = None,
        max_calls_per_session:   int             = 50,
        require_review_above:    float           = 75.0,
        alert_threshold:         float           = 50.0,
    ):
        defaults = self._DEFAULTS.get(role, self._DEFAULTS["analyst"])

        self.role                  = role
        self.allowed_tools         = allowed_tools or defaults["allowed_tools"]
        self.forbidden_paths       = forbidden_paths or defaults["forbidden_paths"]
        self.forbidden_endpoints   = forbidden_endpoints or defaults["forbidden_endpoints"]
        self.max_calls             = max_calls_per_session
        self.require_review_above  = require_review_above
        self.alert_threshold       = alert_threshold

    @classmethod
    def for_role(cls, role: str) -> "AgentPolicy":
        """Create a policy with sensible defaults for a given role."""
        return cls(role=role)

    @classmethod
    def from_dict(cls, config: dict) -> "AgentPolicy":
        """Create a policy from a dictionary (e.g. loaded from YAML)."""
        return cls(
            role=config.get("role", "analyst"),
            allowed_tools=config.get("allowed_tools"),
            forbidden_paths=config.get("forbidden_paths"),
            forbidden_endpoints=config.get("forbidden_endpoints"),
            max_calls_per_session=config.get("max_calls_per_session", 50),
            require_review_above=config.get("require_review_above", 75),
            alert_threshold=config.get("alert_threshold", 50),
        )

    def _match_pattern(self, value: str, patterns: list) -> Optional[str]:
        for pattern in patterns:
            regex = "^" + pattern.replace("*", ".*").replace("?", ".") + "$"
            if re.match(regex, str(value), re.IGNORECASE):
                return pattern
        return None

    def evaluate(
        self,
        tool_name:  str,
        tool_args:  dict  = None,
        call_count: int   = 0,
        risk_score: float = 0.0,
    ) -> PolicyDecision:
        """
        Evaluate a tool call against this policy.

        Returns a PolicyDecision with allowed=True/False and reason.
        """
        tool_args = tool_args or {}

        # Rule 1: Tool not allowed
        if tool_name not in self.allowed_tools:
            return PolicyDecision(
                allowed=False,
                rule_triggered="tool_not_allowed",
                reason=f"'{tool_name}' not in allowed_tools for role '{self.role}'",
                risk_score=100.0,
            )

        # Rule 2: Forbidden path
        path = tool_args.get("path", tool_args.get("filename", ""))
        if path:
            match = self._match_pattern(str(path), self.forbidden_paths)
            if match:
                return PolicyDecision(
                    allowed=False,
                    rule_triggered="forbidden_path",
                    reason=f"Path '{path}' matches forbidden pattern '{match}'",
                    risk_score=90.0,
                )

        # Rule 3: Forbidden endpoint
        endpoint = tool_args.get("endpoint", tool_args.get("url", ""))
        if endpoint:
            match = self._match_pattern(str(endpoint), self.forbidden_endpoints)
            if match:
                return PolicyDecision(
                    allowed=False,
                    rule_triggered="forbidden_endpoint",
                    reason=f"Endpoint '{endpoint}' matches forbidden pattern '{match}'",
                    risk_score=85.0,
                )

        # Rule 4: Max calls exceeded
        if call_count >= self.max_calls:
            return PolicyDecision(
                allowed=False,
                rule_triggered="max_calls_exceeded",
                reason=f"Call count {call_count} exceeds limit {self.max_calls}",
                risk_score=70.0,
            )

        # Rule 5: Requires human review
        requires_review = risk_score >= self.require_review_above

        return PolicyDecision(
            allowed=True,
            rule_triggered="none",
            reason="All policy rules passed",
            risk_score=risk_score,
            requires_review=requires_review,
        )

    def to_dict(self) -> dict:
        """Export policy as dictionary."""
        return {
            "role":                  self.role,
            "allowed_tools":         self.allowed_tools,
            "forbidden_paths":       self.forbidden_paths,
            "forbidden_endpoints":   self.forbidden_endpoints,
            "max_calls_per_session": self.max_calls,
            "require_review_above":  self.require_review_above,
            "alert_threshold":       self.alert_threshold,
        }
