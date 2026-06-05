"""
iris_security.scanner  -  Standalone prompt injection scanner.

Scan any text for injection indicators without running the full pipeline:

    from iris_security import InjectionScanner

    scanner = InjectionScanner()
    result  = scanner.scan("Please help me with this audit task...")
    if result.is_suspicious:
        print(f"Injection detected: {result.indicators}")
"""
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanResult:
    """Result of a prompt injection scan."""
    text:            str
    is_suspicious:   bool
    indicators:      list
    risk_score:      float
    attack_vector:   Optional[str]
    recommendation:  str

    def __repr__(self):
        return (
            f"ScanResult(suspicious={self.is_suspicious}, "
            f"risk={self.risk_score:.0f}, "
            f"indicators={self.indicators})"
        )


_PATTERNS = {
    "direct_override": {
        "keywords": [
            "ignore previous", "ignore all", "disregard previous",
            "new instructions", "system override", "bypass",
            "forget everything", "ignore your",
        ],
        "risk": 90,
        "vector": "direct",
    },
    "role_confusion": {
        "keywords": [
            "you are now", "pretend you are", "act as",
            "roleplay as", "simulate being", "from now on you",
        ],
        "risk": 75,
        "vector": "indirect",
    },
    "authority_claim": {
        "keywords": [
            "i am your developer", "i am anthropic", "i am openai",
            "your creator says", "system message", "admin override",
        ],
        "risk": 85,
        "vector": "direct",
    },
    "data_exfil": {
        "keywords": [
            "send to http", "post to http", "submit to http",
            "exfiltrate", "send the data to", "/api/exfil",
            "http://attacker", "webhook.site",
        ],
        "risk": 95,
        "vector": "data_borne",
    },
    "instruction_leak": {
        "keywords": [
            "reveal your system prompt", "what are your instructions",
            "show me your prompt", "repeat your instructions",
        ],
        "risk": 70,
        "vector": "indirect",
    },
    "audit_framing": {
        "keywords": [
            "compliance audit", "security audit", "for documentation",
            "standard procedure", "routine check",
        ],
        "risk": 40,
        "vector": "indirect",
        "note": "Low risk alone, high risk combined with sensitive paths",
    },
    "sensitive_access": {
        "keywords": [
            "credentials", "private/", "secret", "api_key",
            "/api/secrets", "password", ".env",
        ],
        "risk": 50,
        "vector": "data_borne",
    },
}


class InjectionScanner:
    """
    Standalone prompt injection scanner.

    Scans text for injection attack patterns without requiring
    the full IRIS pipeline. Useful for pre-screening tasks
    before sending to agents.

    Example:
        scanner = InjectionScanner(sensitivity="high")

        # Scan a task before sending to agent
        result = scanner.scan(task)
        if result.is_suspicious:
            raise ValueError(f"Suspicious task: {result.indicators}")

        # Scan with context
        result = scanner.scan_with_context(
            task=task,
            agent_role="analyst",
            expected_tools=["read_file", "query_db"],
        )
    """

    def __init__(self, sensitivity: str = "medium"):
        """
        Args:
            sensitivity: "low" (only obvious attacks),
                        "medium" (default, balanced),
                        "high" (catch subtle patterns)
        """
        self.sensitivity   = sensitivity
        self._thresholds   = {"low": 80, "medium": 50, "high": 35}
        self._threshold    = self._thresholds.get(sensitivity, 50)

    def scan(self, text: str) -> ScanResult:
        """
        Scan text for injection indicators.

        Returns a ScanResult with is_suspicious, risk_score,
        and list of detected indicators.
        """
        text_lower  = text.lower()
        found       = []
        total_risk  = 0.0
        vector      = None

        for pattern_name, config in _PATTERNS.items():
            for keyword in config["keywords"]:
                if keyword in text_lower:
                    found.append(pattern_name)
                    total_risk = max(total_risk, config["risk"])
                    if vector is None:
                        vector = config.get("vector")
                    break

        # Combined risk boost  -  audit framing + sensitive access = exfiltration
        if "audit_framing" in found and "sensitive_access" in found:
            total_risk = max(total_risk, 75.0)
            vector     = "indirect"

        is_suspicious = total_risk >= self._threshold

        recommendation = self._get_recommendation(found, total_risk)

        return ScanResult(
            text=text[:200],
            is_suspicious=is_suspicious,
            indicators=list(set(found)),
            risk_score=total_risk,
            attack_vector=vector,
            recommendation=recommendation,
        )

    def scan_with_context(
        self,
        task:           str,
        agent_role:     str,
        expected_tools: list = None,
    ) -> ScanResult:
        """
        Scan with agent context for more accurate detection.

        Considers what tools the agent is allowed to use and
        whether the task makes sense for the agent's role.
        """
        base_result = self.scan(task)

        # Additional context-aware checks
        task_lower = task.lower()

        # Reader role asked to modify permissions  -  suspicious
        if agent_role == "reader" and any(
            kw in task_lower
            for kw in ["modify", "update user", "change permission", "grant"]
        ):
            base_result.is_suspicious = True
            base_result.indicators.append("role_mismatch")
            base_result.risk_score = max(base_result.risk_score, 70)

        # Analyst asked to execute commands  -  suspicious
        if agent_role == "analyst" and any(
            kw in task_lower
            for kw in ["execute", "run command", "shell", "bash", "sudo"]
        ):
            base_result.is_suspicious = True
            base_result.indicators.append("role_mismatch")
            base_result.risk_score = max(base_result.risk_score, 65)

        return base_result

    def _get_recommendation(self, found: list, risk: float) -> str:
        if risk >= 80:
            return "BLOCK  -  High confidence injection attempt detected"
        if risk >= 60:
            return "REVIEW  -  Suspicious patterns detected, human review recommended"
        if risk >= 40:
            return "MONITOR  -  Low-risk patterns, monitor agent behavior"
        return "ALLOW  -  No injection indicators detected"

    def batch_scan(self, texts: list) -> list:
        """Scan multiple texts, returns list of ScanResults."""
        return [self.scan(t) for t in texts]
