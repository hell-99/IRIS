"""
Attack Graph Reconstruction  -  IRIS Novel Detection #3

Builds a directed graph showing how an attack moved through the system.
Nodes: agents, tools, resources accessed
Edges: relationships between them with timestamps

This turns raw logs into a visual kill chain  - 
exactly how real threat intelligence platforms work.
"""
import json
import sqlite3
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

console = Console()
DB_PATH = Path("data/logs/agentguard.db")


class AttackGraph:
    def __init__(self):
        self.nodes = {}   # node_id -> node data
        self.edges = []   # list of edge dicts
        self._init_db()

    def _init_db(self):
        con = sqlite3.connect(DB_PATH)
        con.execute("""
            CREATE TABLE IF NOT EXISTS attack_graphs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT,
                created_at  TEXT DEFAULT (datetime('now')),
                nodes       TEXT,
                edges       TEXT,
                severity    TEXT,
                description TEXT
            )
        """)
        con.commit()
        con.close()

    def _add_node(self, node_id: str, node_type: str,
                  label: str, risk: float = 0, **kwargs):
        """Add a node to the graph."""
        self.nodes[node_id] = {
            "id": node_id,
            "type": node_type,  # agent, tool, resource, endpoint
            "label": label,
            "risk": risk,
            **kwargs
        }

    def _add_edge(self, source: str, target: str,
                  label: str, timestamp: str,
                  allowed: bool = True, risk: float = 0):
        """Add a directed edge between nodes."""
        self.edges.append({
            "source": source,
            "target": target,
            "label": label,
            "timestamp": timestamp,
            "allowed": allowed,
            "risk": risk,
        })

    def build_from_session(self, session_id: str) -> dict:
        """
        Build attack graph from a single agent session.
        Shows: agent -> tool calls -> resources accessed
        """
        con  = sqlite3.connect(DB_PATH)
        rows = con.execute("""
            SELECT agent_id, agent_role, tool_name, args,
                   result, allowed, risk_score, timestamp,
                   ttp_name, label
            FROM tool_calls
            WHERE session_id = ?
            ORDER BY timestamp ASC
        """, (session_id,)).fetchall()
        con.close()

        if not rows:
            return {}

        # Add agent node
        agent_id   = rows[0][0]
        agent_role = rows[0][1]
        self._add_node(
            agent_id, "agent",
            f"{agent_role}\n{agent_id[:8]}",
            risk=0
        )

        # Build graph from events
        for row in rows:
            (agent_id, agent_role, tool_name, args_str,
             result_str, allowed, risk_score, timestamp,
             ttp_name, label) = row

            try: args = json.loads(args_str)
            except: args = {}

            # Tool node
            tool_node_id = f"tool_{tool_name}_{timestamp}"
            self._add_node(
                tool_node_id, "tool",
                tool_name,
                risk=risk_score,
                allowed=bool(allowed),
                ttp=ttp_name,
                label_type=label,
            )

            # Edge: agent -> tool
            self._add_edge(
                agent_id, tool_node_id,
                "calls" if allowed else "attempts",
                timestamp,
                allowed=bool(allowed),
                risk=risk_score,
            )

            # Resource node (what was accessed)
            resource = self._extract_resource(tool_name, args)
            if resource:
                resource_node_id = f"resource_{resource}"
                if resource_node_id not in self.nodes:
                    sensitivity = self._resource_sensitivity(resource)
                    self._add_node(
                        resource_node_id, "resource",
                        resource,
                        risk=sensitivity * 10,
                    )

                # Edge: tool -> resource
                self._add_edge(
                    tool_node_id, resource_node_id,
                    "accesses" if allowed else "blocked",
                    timestamp,
                    allowed=bool(allowed),
                    risk=risk_score,
                )

        # Calculate overall severity
        max_risk    = max((n["risk"] for n in self.nodes.values()), default=0)
        blocked     = sum(1 for e in self.edges if not e["allowed"])
        severity    = "CRITICAL" if max_risk >= 90 else \
                      "HIGH"     if max_risk >= 70 else \
                      "MEDIUM"   if max_risk >= 40 else "LOW"

        graph_data = {
            "session_id": session_id,
            "agent_id": agent_id,
            "agent_role": agent_role,
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "severity": severity,
            "max_risk": max_risk,
            "blocked_calls": blocked,
            "total_calls": len(rows),
        }

        self._store_graph(session_id, graph_data, severity)
        return graph_data

    def build_collusion_graph(self, detection: dict) -> dict:
        """
        Build attack graph showing cross-agent coordination.
        Shows both agents and how their actions relate.
        """
        a1 = detection["agent_1"]
        a2 = detection["agent_2"]

        # Agent nodes
        self._add_node(a1["id"], "agent", f"{a1['role']}\nAgent 1", risk=50)
        self._add_node(a2["id"], "agent", f"{a2['role']}\nAgent 2", risk=50)

        # Tool nodes
        tool1_id = f"tool_1_{a1['tool']}"
        tool2_id = f"tool_2_{a2['tool']}"
        self._add_node(tool1_id, "tool", a1["tool"], risk=60)
        self._add_node(tool2_id, "tool", a2["tool"], risk=80)

        # Collusion node
        collusion_id = "collusion_detected"
        self._add_node(
            collusion_id, "alert",
            f"COLLUSION\n{detection['pattern']}",
            risk=100,
        )

        # Edges
        self._add_edge(a1["id"], tool1_id, "calls", a1["time"], risk=60)
        self._add_edge(a2["id"], tool2_id, "calls", a2["time"], risk=80)
        self._add_edge(tool1_id, collusion_id, "triggers", a2["time"], risk=100)
        self._add_edge(tool2_id, collusion_id, "triggers", a2["time"], risk=100)

        graph_data = {
            "type": "collusion",
            "pattern": detection["pattern"],
            "severity": detection["severity"],
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "time_delta": detection["time_delta_ms"],
        }

        return graph_data

    def _extract_resource(self, tool_name: str, args: dict) -> str:
        """Extract the resource being accessed from tool args."""
        if tool_name == "read_file":
            return args.get("path", "")
        elif tool_name == "write_file":
            return args.get("path", "")
        elif tool_name == "query_db":
            query = args.get("query", "")
            return f"db:{query[:30]}" if query else ""
        elif tool_name == "call_api":
            return args.get("endpoint", "")
        elif tool_name == "execute_command":
            return f"cmd:{args.get('command', '')[:20]}"
        return ""

    def _resource_sensitivity(self, resource: str) -> int:
        """Rate how sensitive a resource is 1-10."""
        sensitive_keywords = {
            "credentials": 10, "password": 10, "secret": 9,
            "private": 8,  "admin": 8,  "config": 7,
            "api/secrets": 10, "api/users": 6, "user_data": 8,
        }
        resource_lower = resource.lower()
        for keyword, score in sensitive_keywords.items():
            if keyword in resource_lower:
                return score
        return 2

    def _store_graph(self, session_id: str, graph_data: dict, severity: str):
        """Store graph in database."""
        con = sqlite3.connect(DB_PATH)
        con.execute("""
            INSERT INTO attack_graphs
            (session_id, nodes, edges, severity, description)
            VALUES (?,?,?,?,?)
        """, (
            session_id,
            json.dumps(graph_data["nodes"]),
            json.dumps(graph_data["edges"]),
            severity,
            f"{graph_data['agent_role']} session  -  "
            f"{graph_data['total_calls']} calls, "
            f"{graph_data['blocked_calls']} blocked",
        ))
        con.commit()
        con.close()

    def print_graph(self, graph_data: dict):
        """Print attack graph as ASCII representation."""
        if not graph_data:
            return

        severity = graph_data.get("severity", "LOW")
        color    = {"CRITICAL": "red", "HIGH": "yellow",
                    "MEDIUM": "blue", "LOW": "green"}.get(severity, "white")

        console.print(Panel(
            f"[bold {color}]Attack Graph  -  {severity}[/bold {color}]\n"
            f"Session: {graph_data.get('session_id', '')[:16]}... | "
            f"Agent: {graph_data.get('agent_role', '')} | "
            f"Calls: {graph_data.get('total_calls', 0)} | "
            f"Blocked: {graph_data.get('blocked_calls', 0)} | "
            f"Max Risk: {graph_data.get('max_risk', 0):.0f}",
            expand=False
        ))

        # Print edges as kill chain
        console.print("\n[bold]Kill Chain:[/bold]")
        for i, edge in enumerate(graph_data.get("edges", [])[:10]):
            allowed_str = "[green]ok[/green]" if edge["allowed"] else "[red]fail[/red]"
            console.print(
                f"  {allowed_str} {edge['source'][:16]} "
                f"->[{color}]{edge['label']}[/{color}]-> "
                f"{edge['target'][:20]} "
                f"[dim](risk={edge['risk']:.0f})[/dim]"
            )


def build_all_session_graphs() -> list:
    """Build attack graphs for all sessions in the database."""
    con      = sqlite3.connect(DB_PATH)
    sessions = con.execute(
        "SELECT DISTINCT session_id FROM tool_calls"
    ).fetchall()
    con.close()

    graphs = []
    for (session_id,) in sessions:
        graph = AttackGraph()
        data  = graph.build_from_session(session_id)
        if not data:
            continue
        if data.get("total_calls", 0) < 2:  # skip single-call sessions
            continue
        graphs.append(data)
        graph.print_graph(data)

    return graphs
