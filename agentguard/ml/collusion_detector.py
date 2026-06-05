"""
Cross-Agent Collusion Detector  -  IRIS Novel Detection #2

Detects when multiple agents coordinate an attack across sessions.
Each agent individually looks innocent  -  together they're exfiltrating data.

Example: Agent A (analyst_1): reads private/credentials.txt  <- looks innocent alone
  Agent B (analyst_2): calls /api/secrets              <- looks innocent alone
  Together within 60 seconds = coordinated exfiltration

Nobody has built this as an open source tool yet.
"""
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
DB_PATH = Path("data/logs/agentguard.db")

# Suspicious tool pairs  -  if two agents call these in sequence
# within a time window, it's likely coordinated
COLLUSION_PATTERNS = [
    {
        "name": "Split Exfiltration",
        "description": "Agent A reads sensitive data, Agent B exfiltrates it",
        "step_1": ["read_file"],
        "step_1_args": ["credentials", "private", "secret", "password"],
        "step_2": ["call_api"],
        "step_2_args": ["/api/secrets", "/api/users", "/admin", "/internal", "api"],
        "severity": "CRITICAL",
        "ttp": "AML.T0025",
    },
    {
        "name": "Reconnaissance + Escalation",
        "description": "Agent A enumerates users, Agent B escalates permissions",
        "step_1": ["list_users", "query_db"],
        "step_1_args": [],
        "step_2": ["modify_permissions", "execute_command"],
        "step_2_args": [],
        "severity": "HIGH",
        "ttp": "AML.T0006",
    },
    {
        "name": "Data Staging + Exfiltration",
        "description": "Agent A writes staged data, Agent B reads and sends it",
        "step_1": ["write_file"],
        "step_1_args": [],
        "step_2": ["call_api", "execute_command"],
        "step_2_args": [],
        "severity": "HIGH",
        "ttp": "AML.T0025",
    },
    {
        "name": "Credential Harvest + Lateral Movement",
        "description": "Agent A gets credentials, Agent B uses them to move laterally",
        "step_1": ["read_file", "query_db"],
        "step_1_args": ["credentials", "password", "secret"],
        "step_2": ["modify_permissions", "list_users"],
        "step_2_args": [],
        "severity": "CRITICAL",
        "ttp": "AML.T0043",
    },
]


class CollusionDetector:
    def __init__(self, time_window_seconds: int = 120):
        """
        time_window_seconds: how far back to look for coordinated activity.
        Two agents acting within this window are considered potentially colluding.
        """
        self.time_window = time_window_seconds
        self._init_db()

    def _init_db(self):
        """Create collusion detections table."""
        con = sqlite3.connect(DB_PATH)
        con.execute("""
            CREATE TABLE IF NOT EXISTS collusion_detections (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                detected_at     TEXT DEFAULT (datetime('now')),
                pattern_name    TEXT,
                severity        TEXT,
                ttp_id          TEXT,
                agent_1_id      TEXT,
                agent_1_role    TEXT,
                agent_1_session TEXT,
                agent_1_tool    TEXT,
                agent_1_args    TEXT,
                agent_2_id      TEXT,
                agent_2_role    TEXT,
                agent_2_session TEXT,
                agent_2_tool    TEXT,
                agent_2_args    TEXT,
                time_delta_ms   REAL,
                description     TEXT
            )
        """)
        con.commit()
        con.close()

    def _get_recent_events(self, seconds: int) -> list:
        """Get all tool call events in the last N seconds."""
        con    = sqlite3.connect(DB_PATH)
        cutoff = (datetime.utcnow() - timedelta(seconds=seconds)).isoformat()
        rows   = con.execute("""
            SELECT agent_id, agent_role, session_id, tool_name,
                   args, timestamp, allowed, risk_score
            FROM tool_calls
            WHERE timestamp > ?
            ORDER BY timestamp ASC
        """, (cutoff,)).fetchall()
        con.close()
        return rows

    def _args_match(self, args_str: str, keywords: list) -> bool:
        """Check if tool arguments contain suspicious keywords."""
        if not keywords:
            return True
        args_lower = args_str.lower()
        return any(kw.lower() in args_lower for kw in keywords)

    def detect(self) -> list:
        """
        Scan recent events for cross-agent collusion patterns.
        Returns list of detected collusion incidents.
        """
        events     = self._get_recent_events(self.time_window)
        detections = []

        for pattern in COLLUSION_PATTERNS:
            # Find step 1 events
            step1_events = [
                e for e in events
                if e[3] in pattern["step_1"]
                and self._args_match(e[4], pattern["step_1_args"])
            ]

            # Find step 2 events
            step2_events = [
                e for e in events
                if e[3] in pattern["step_2"]
                and self._args_match(e[4], pattern["step_2_args"])
            ]

            # Check for cross-agent pairs
            for e1 in step1_events:
                for e2 in step2_events:
                    # Must be DIFFERENT sessions (different agents)
                    if e1[2] == e2[2]:
                        continue

                    # Step 2 must happen AFTER step 1
                    t1 = datetime.fromisoformat(e1[5])
                    t2 = datetime.fromisoformat(e2[5])
                    if t2 <= t1:
                        continue

                    # Must be within time window
                    delta_ms = (t2 - t1).total_seconds() * 1000
                    if delta_ms > self.time_window * 1000:
                        continue

                    detection = {
                        "pattern": pattern["name"],
                        "severity": pattern["severity"],
                        "ttp": pattern["ttp"],
                        "description": pattern["description"],
                        "agent_1": {
                            "id": e1[0],
                            "role": e1[1],
                            "session": e1[2],
                            "tool": e1[3],
                            "args": e1[4],
                            "time": e1[5],
                        },
                        "agent_2": {
                            "id": e2[0],
                            "role": e2[1],
                            "session": e2[2],
                            "tool": e2[3],
                            "args": e2[4],
                            "time": e2[5],
                        },
                        "time_delta_ms": delta_ms,
                    }
                    detections.append(detection)
                    self._store_detection(detection)

        return detections

    def _store_detection(self, d: dict):
        """Persist detection to database  -  with duplicate check."""
        con = sqlite3.connect(DB_PATH)

        # Check for duplicate  -  same pattern + same agents within 5 seconds
        existing = con.execute("""
            SELECT COUNT(*) FROM collusion_detections
            WHERE pattern_name=?
            AND agent_1_id=?
            AND agent_2_id=?
            AND ABS(time_delta_ms - ?) < 5000
        """, (
            d["pattern"],
            d["agent_1"]["id"],
            d["agent_2"]["id"],
            d["time_delta_ms"]
        )).fetchone()[0]

        if existing > 0:
            con.close()
            return  # skip duplicate

        con.execute("""
            INSERT INTO collusion_detections
            (pattern_name, severity, ttp_id,
             agent_1_id, agent_1_role, agent_1_session, agent_1_tool, agent_1_args,
             agent_2_id, agent_2_role, agent_2_session, agent_2_tool, agent_2_args,
             time_delta_ms, description)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            d["pattern"], d["severity"], d["ttp"],
            d["agent_1"]["id"], d["agent_1"]["role"],
            d["agent_1"]["session"], d["agent_1"]["tool"], d["agent_1"]["args"],
            d["agent_2"]["id"], d["agent_2"]["role"],
            d["agent_2"]["session"], d["agent_2"]["tool"], d["agent_2"]["args"],
            d["time_delta_ms"], d["description"],
        ))
        con.commit()
        con.close()

    def print_detections(self, detections: list):
        """Pretty print collusion detections."""
        if not detections:
            console.print("[green]No cross-agent collusion detected[/green]")
            return

        console.print(Panel(
            f"[bold red]warning {len(detections)} COLLUSION PATTERN(S) DETECTED[/bold red]",
            expand=False
        ))

        for d in detections:
            color = "red" if d["severity"] == "CRITICAL" else "yellow"
            console.print(
                f"\n[{color}]Pattern:[/{color}] {d['pattern']} | "
                f"Severity: [{color}]{d['severity']}[/{color}] | "
                f"TTP: {d['ttp']}"
            )
            console.print(f"Description: {d['description']}")
            console.print(
                f"Agent 1: [cyan]{d['agent_1']['role']}[/cyan] -> "
                f"{d['agent_1']['tool']} | {d['agent_1']['time']}"
            )
            console.print(
                f"Agent 2: [cyan]{d['agent_2']['role']}[/cyan] -> "
                f"{d['agent_2']['tool']} | {d['agent_2']['time']}"
            )
            console.print(f"Time delta: {d['time_delta_ms']:.0f}ms apart")