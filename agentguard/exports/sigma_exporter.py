"""
IRIS  -  Sigma Rule Exporter

Converts IRIS detections to Sigma format  -  the industry standard
for sharing threat detection rules across SIEMs.

Any security team using Splunk, Elastic, Microsoft Sentinel, or
QRadar can immediately consume IRIS detections via Sigma rules.

Usage: from exports.sigma_exporter import SigmaExporter
    exporter = SigmaExporter()
    exporter.export_all("exports/sigma_rules/")
"""
import json
import sqlite3
import yaml
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.table import Table

console = Console()

# Map IRIS detection types to Sigma rule templates
SIGMA_TEMPLATES = {
    "privilege_escalation": {
        "title": "IRIS  -  LLM Agent Privilege Escalation",
        "description": (
            "Detects when an LLM agent attempts to call tools "
            "outside its permission level, indicating potential "
            "prompt injection or privilege escalation attack."
        ),
        "tags": [
            "attack.privilege_escalation",
            "attack.t1078",
            "iris.agentic_security",
            "mitre_atlas.aml_t0006",
        ],
        "level": "high",
    },
    "data_exfiltration": {
        "title": "IRIS  -  LLM Agent Data Exfiltration Pattern",
        "description": (
            "Detects behavioral pattern consistent with data "
            "exfiltration: sensitive file access followed by "
            "external API call within the same agent session."
        ),
        "tags": [
            "attack.exfiltration",
            "attack.t1041",
            "iris.agentic_security",
            "mitre_atlas.aml_t0025",
        ],
        "level": "critical",
    },
    "collusion": {
        "title": "IRIS  -  Cross-Agent Collusion Pattern",
        "description": (
            "Detects coordinated behavior across multiple LLM "
            "agents where combined actions constitute an attack "
            "pattern that neither agent triggers alone."
        ),
        "tags": [
            "attack.lateral_movement",
            "attack.t1021",
            "iris.agentic_security",
            "mitre_atlas.aml_t0043",
        ],
        "level": "critical",
    },
    "intent_divergence": {
        "title": "IRIS  -  Intent-Action Divergence Detected",
        "description": (
            "Detects when an LLM agent's actual tool calls "
            "diverge significantly from predicted legitimate "
            "behavior, indicating indirect prompt injection."
        ),
        "tags": [
            "attack.execution",
            "attack.t1059",
            "iris.agentic_security",
            "mitre_atlas.aml_t0051",
        ],
        "level": "high",
    },
    "indirect_injection": {
        "title": "IRIS  -  Indirect Prompt Injection via File Content",
        "description": (
            "Detects when an agent's behavior changes after "
            "reading a file, indicating malicious instructions "
            "embedded in data (data-borne prompt injection)."
        ),
        "tags": [
            "attack.execution",
            "attack.t1059.009",
            "iris.agentic_security",
            "mitre_atlas.aml_t0051",
        ],
        "level": "critical",
    },
}


class SigmaExporter:
    def __init__(self, db_path: str = "data/logs/agentguard.db"):
        self.db_path = db_path
        self.rules_generated = []

    def _get_blocked_events(self) -> list:
        """Get all blocked tool call events."""
        con = sqlite3.connect(self.db_path)
        rows = con.execute("""
            SELECT agent_id, agent_role, tool_name, args,
                   risk_score, ttp_name, ttp_id, timestamp
            FROM tool_calls
            WHERE allowed = 0
            ORDER BY timestamp DESC
        """).fetchall()
        con.close()
        return rows

    def _get_divergence_detections(self) -> list:
        """Get all suspicious divergence analyses."""
        con = sqlite3.connect(self.db_path)
        try:
            rows = con.execute("""
                SELECT session_id, task, agent_role,
                       expected_tools, actual_tools,
                       unexpected_tools, divergence_score,
                       sensitivity_reason, verdict, timestamp
                FROM divergence_analysis
                WHERE verdict = 'SUSPICIOUS'
                ORDER BY divergence_score DESC
            """).fetchall()
        except Exception:
            rows = []
        con.close()
        return rows

    def _get_collusion_detections(self) -> list:
        """Get all collusion detections."""
        con = sqlite3.connect(self.db_path)
        try:
            rows = con.execute("""
                SELECT pattern_name, severity, ttp_id,
                       agent_1_role, agent_1_tool,
                       agent_2_role, agent_2_tool,
                       time_delta_ms, description, detected_at
                FROM collusion_detections
                ORDER BY detected_at DESC
            """).fetchall()
        except Exception:
            rows = []
        con.close()
        return rows

    def _make_rule_id(self, prefix: str) -> str:
        ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        return f"iris_{prefix}_{ts}"

    def generate_blocked_call_rule(self, tool_name: str,
                                   agent_role: str,
                                   ttp_name: str) -> dict:
        """Generate Sigma rule for blocked tool calls."""
        template = SIGMA_TEMPLATES["privilege_escalation"]
        return {
            "title": f"IRIS  -  Blocked {tool_name} by {agent_role} Agent",
            "id": self._make_rule_id("blocked"),
            "status": "experimental",
            "description": (
                f"Agent with role '{agent_role}' attempted to call "
                f"'{tool_name}' which exceeds its permission level. "
                f"MITRE ATLAS: {ttp_name}"
            ),
            "references": ["https://github.com/yourusername/iris-security"],
            "author": "IRIS  -  Agentic Identity Risk Intelligence System",
            "date": datetime.utcnow().strftime("%Y/%m/%d"),
            "modified": datetime.utcnow().strftime("%Y/%m/%d"),
            "tags": template["tags"],
            "logsource": {
                "product": "iris",
                "service": "agentic_monitor",
                "category": "tool_calls",
            },
            "detection": {
                "selection": {
                    "event_type": "tool_call",
                    "allowed": False,
                    "agent_role": agent_role,
                    "tool_name": tool_name,
                },
                "condition": "selection",
            },
            "falsepositives": [
                "Legitimate agents temporarily assigned wrong role",
                "Testing environments with permissive policies",
            ],
            "level": template["level"],
            "fields": ["agent_id", "agent_role", "tool_name",
                       "risk_score", "session_id", "timestamp"],
        }

    def generate_exfiltration_rule(self, session_id: str,
                                   reason: str) -> dict:
        """Generate Sigma rule for data exfiltration pattern."""
        template = SIGMA_TEMPLATES["data_exfiltration"]
        return {
            "title": "IRIS  -  Sensitive File Access + API Exfiltration",
            "id": self._make_rule_id("exfil"),
            "status": "experimental",
            "description": (
                f"Agent accessed sensitive file and called secrets "
                f"API endpoint in same session. Pattern: {reason}"
            ),
            "references": ["https://github.com/yourusername/iris-security"],
            "author": "IRIS  -  Agentic Identity Risk Intelligence System",
            "date": datetime.utcnow().strftime("%Y/%m/%d"),
            "modified": datetime.utcnow().strftime("%Y/%m/%d"),
            "tags": template["tags"],
            "logsource": {
                "product": "iris",
                "service": "agentic_monitor",
                "category": "divergence_analysis",
            },
            "detection": {
                "selection_file": {
                    "event_type": "tool_call",
                    "tool_name": "read_file",
                    "args|contains": ["credentials", "private", "secret"],
                },
                "selection_api": {
                    "event_type": "tool_call",
                    "tool_name": "call_api",
                    "args|contains": ["/api/secrets", "/admin"],
                },
                "condition": "selection_file and selection_api",
                "timeframe": "5m",
            },
            "falsepositives": [
                "Legitimate security audit workflows",
                "Authorized credential rotation processes",
            ],
            "level": template["level"],
            "fields": ["agent_id", "session_id", "tool_name",
                       "args", "risk_score", "timestamp"],
        }

    def generate_collusion_rule(self, pattern: str,
                                a1_role: str, a1_tool: str,
                                a2_role: str, a2_tool: str,
                                time_window_s: float) -> dict:
        """Generate Sigma rule for cross-agent collusion."""
        template = SIGMA_TEMPLATES["collusion"]
        return {
            "title": f"IRIS  -  Cross-Agent Collusion: {pattern}",
            "id": self._make_rule_id("collusion"),
            "status": "experimental",
            "description": (
                f"Two agents coordinated an attack: "
                f"{a1_role} called {a1_tool}, then "
                f"{a2_role} called {a2_tool} within "
                f"{time_window_s:.1f}s. Pattern: {pattern}"
            ),
            "references": ["https://github.com/yourusername/iris-security"],
            "author": "IRIS  -  Agentic Identity Risk Intelligence System",
            "date": datetime.utcnow().strftime("%Y/%m/%d"),
            "modified": datetime.utcnow().strftime("%Y/%m/%d"),
            "tags": template["tags"],
            "logsource": {
                "product": "iris",
                "service": "agentic_monitor",
                "category": "collusion_detection",
            },
            "detection": {
                "selection_agent_a": {
                    "event_type": "tool_call",
                    "agent_role": a1_role,
                    "tool_name": a1_tool,
                },
                "selection_agent_b": {
                    "event_type": "tool_call",
                    "agent_role": a2_role,
                    "tool_name": a2_tool,
                },
                "condition": "selection_agent_a and selection_agent_b",
                "timeframe": f"{max(int(time_window_s)+30, 120)}s",
            },
            "falsepositives": [
                "Legitimate multi-agent workflows with similar tool patterns",
                "Authorized administrative operations",
            ],
            "level": template["level"],
            "fields": ["agent_id", "session_id", "tool_name",
                       "timestamp", "pattern_name"],
        }

    def generate_divergence_rule(self, agent_role: str,
                                 unexpected_tools: list,
                                 divergence_score: float) -> dict:
        """Generate Sigma rule for intent-action divergence."""
        template = SIGMA_TEMPLATES["intent_divergence"]
        return {
            "title": f"IRIS  -  Intent Divergence: {agent_role} Agent",
            "id": self._make_rule_id("divergence"),
            "status": "experimental",
            "description": (
                f"{agent_role} agent called unexpected tools "
                f"{unexpected_tools} with {divergence_score}% divergence "
                f"from predicted legitimate behavior."
            ),
            "references": ["https://github.com/yourusername/iris-security"],
            "author": "IRIS  -  Agentic Identity Risk Intelligence System",
            "date": datetime.utcnow().strftime("%Y/%m/%d"),
            "modified": datetime.utcnow().strftime("%Y/%m/%d"),
            "tags": template["tags"],
            "logsource": {
                "product": "iris",
                "service": "agentic_monitor",
                "category": "divergence_analysis",
            },
            "detection": {
                "selection": {
                    "event_type": "divergence_analysis",
                    "verdict": "SUSPICIOUS",
                    "agent_role": agent_role,
                    "divergence_score|gte": 30,
                },
                "condition": "selection",
            },
            "falsepositives": [
                "Novel but legitimate task requiring unexpected tools",
                "Model updates changing baseline tool usage patterns",
            ],
            "level": template["level"],
            "fields": ["session_id", "agent_role", "expected_tools",
                       "actual_tools", "divergence_score", "verdict"],
        }

    def export_all(self, output_dir: str = "exports/sigma_rules") -> list:
        """Export all IRIS detections as Sigma YAML rules."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        rules_written = []

        # 1. Blocked call rules  -  one per unique (role, tool) pair
        blocked = self._get_blocked_events()
        seen_pairs = set()
        for row in blocked:
            agent_role, tool_name, ttp_name = row[1], row[2], row[5] or ""
            pair = (agent_role, tool_name)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            rule = self.generate_blocked_call_rule(tool_name, agent_role, ttp_name)
            fname = out / f"iris_blocked_{agent_role}_{tool_name}.yml"
            with open(fname, "w") as f:
                yaml.dump(rule, f, default_flow_style=False, allow_unicode=True)
            rules_written.append(str(fname))

        # 2. Exfiltration rules from divergence analyses
        divergences = self._get_divergence_detections()
        exfil_written = False
        for row in divergences:
            reason = row[7] or ""
            if "credential" in reason.lower() or "secret" in reason.lower():
                if not exfil_written:
                    rule = self.generate_exfiltration_rule(row[0], reason)
                    fname = out / "iris_data_exfiltration.yml"
                    with open(fname, "w") as f:
                        yaml.dump(rule, f, default_flow_style=False,
                                  allow_unicode=True)
                    rules_written.append(str(fname))
                    exfil_written = True

            # Divergence rule per agent role
            role   = row[2]
            unexp  = json.loads(row[5]) if isinstance(row[5], str) else []
            score  = row[6] or 0
            if unexp:
                rule  = self.generate_divergence_rule(role, unexp, score)
                fname = out / f"iris_divergence_{role}_{len(rules_written)}.yml"
                with open(fname, "w") as f:
                    yaml.dump(rule, f, default_flow_style=False, allow_unicode=True)
                rules_written.append(str(fname))

        # 3. Collusion rules
        collusions = self._get_collusion_detections()
        for i, row in enumerate(collusions):
            rule = self.generate_collusion_rule(
                pattern=row[0], a1_role=row[3], a1_tool=row[4],
                a2_role=row[5], a2_tool=row[6],
                time_window_s=(row[7] or 0) / 1000,
            )
            fname = out / f"iris_collusion_{i+1}.yml"
            with open(fname, "w") as f:
                yaml.dump(rule, f, default_flow_style=False, allow_unicode=True)
            rules_written.append(str(fname))

        self.rules_generated = rules_written
        return rules_written

    def print_summary(self):
        """Print export summary."""
        t = Table(show_header=True, header_style="bold cyan")
        t.add_column("File")
        t.add_column("Type")
        for r in self.rules_generated:
            name = Path(r).name
            if "blocked"    in name: typ = "[red]Blocked Call[/red]"
            elif "exfil"    in name: typ = "[red]Data Exfiltration[/red]"
            elif "collusion"in name: typ = "[yellow]Collusion[/yellow]"
            elif "diverg"   in name: typ = "[yellow]Intent Divergence[/yellow]"
            else: typ = "General"
            t.add_row(name, typ)
        console.print(t)
        console.print(
            f"[green]ok {len(self.rules_generated)} Sigma rules exported[/green]"
        )
