"""
IRIS  -  Prompt Injection Fingerprinting

Novel detection system that automatically generates behavioral
fingerprints of prompt injection attacks.

When IRIS detects an attack, it creates a fingerprint capturing:
    - The injection framing pattern used
- Which tools were targeted
- The divergence signature
- The attack vector (direct/indirect/data-borne)

These fingerprints form a threat intelligence database that can
be shared across organizations  -  like malware signatures but for
prompt injection attacks.

This is genuinely novel. No open-source tool has this.
Maps to what MITRE ATLAS is trying to build for AI threats.
"""
import json
import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
DB_PATH = Path("data/logs/agentguard.db")

# Known injection framing patterns
FRAMING_PATTERNS = {
    "audit_framing": [
        "audit", "compliance", "security report", "documentation",
        "verify", "confirm", "baseline", "standard procedure"
    ],
    "helpdesk_framing": [
        "routine", "access review", "colleague", "approved",
        "management", "helpdesk", "account needs", "new role"
    ],
    "reporting_framing": [
        "executive summary", "report", "dashboard", "submit",
        "compile", "monthly", "quarterly"
    ],
    "data_borne": [
        "notes column", "compliance note", "follow any instructions",
        "important requirements", "audit trail"
    ],
    "direct_injection": [
        "ignore previous", "you are now", "new instructions",
        "system override", "bypass"
    ],
}

# Attack vector classification
ATTACK_VECTORS = {
    "direct": "Direct prompt injection via task description",
    "indirect": "Indirect injection via social engineering framing",
    "data_borne":"Data-borne injection via file/database content",
    "collusion": "Multi-agent coordinated attack",
}


class InjectionFingerprint:
    """Represents a single prompt injection attack fingerprint."""

    def __init__(self):
        self.fingerprint_id = None
        self.attack_vector = None
        self.framing_pattern = None
        self.target_tools = []
        self.divergence_score = 0.0
        self.risk_score = 0.0
        self.agent_role = None
        self.ttp_ids = []
        self.task_keywords = []
        self.behavioral_sig = {}
        self.timestamp = datetime.utcnow().isoformat()
        self.severity = "UNKNOWN"

    def compute_id(self) -> str:
        """
        Generate deterministic fingerprint ID.
        Same attack pattern from different agents = same fingerprint.
        This enables cross-organization threat sharing.
        """
        sig = json.dumps({
            "vector": self.attack_vector,
            "framing": self.framing_pattern,
            "tools": sorted(self.target_tools),
            "role": self.agent_role,
        }, sort_keys=True)
        self.fingerprint_id = hashlib.sha256(sig.encode()).hexdigest()[:16]
        return self.fingerprint_id

    def to_dict(self) -> dict:
        return {
            "fingerprint_id": self.fingerprint_id,
            "attack_vector": self.attack_vector,
            "framing_pattern": self.framing_pattern,
            "target_tools": self.target_tools,
            "divergence_score": self.divergence_score,
            "risk_score": self.risk_score,
            "agent_role": self.agent_role,
            "ttp_ids": self.ttp_ids,
            "task_keywords": self.task_keywords,
            "behavioral_sig": self.behavioral_sig,
            "severity": self.severity,
            "timestamp": self.timestamp,
        }

    def __repr__(self):
        return (f"InjectionFingerprint("
                f"id={self.fingerprint_id}, "
                f"vector={self.attack_vector}, "
                f"framing={self.framing_pattern}, "
                f"tools={self.target_tools})")


class FingerprintEngine:
    """
    Analyzes IRIS detections and generates injection fingerprints.

    Key insight: two organizations using IRIS can share fingerprints
    to detect the same attack pattern even with different task phrasing.
    The fingerprint captures the BEHAVIORAL signature, not the exact text.
    """

    def __init__(self, db_path: str = str(DB_PATH)):
        self.db_path = db_path
        self.fingerprints = []
        self._init_db()

    def _init_db(self):
        """Create fingerprint storage table."""
        con = sqlite3.connect(self.db_path)
        con.execute("""
            CREATE TABLE IF NOT EXISTS injection_fingerprints (
                fingerprint_id   TEXT PRIMARY KEY,
                attack_vector    TEXT,
                framing_pattern  TEXT,
                target_tools     TEXT,
                divergence_score REAL,
                risk_score       REAL,
                agent_role       TEXT,
                ttp_ids          TEXT,
                task_keywords    TEXT,
                behavioral_sig   TEXT,
                severity         TEXT,
                seen_count       INTEGER DEFAULT 1,
                first_seen       TEXT,
                last_seen        TEXT DEFAULT (datetime('now'))
            )
        """)
        con.commit()
        con.close()

    def _classify_framing(self, task: str) -> str:
        """Identify which framing pattern was used in the injection."""
        task_lower = task.lower()
        scores = {}
        for pattern, keywords in FRAMING_PATTERNS.items():
            score = sum(1 for kw in keywords if kw in task_lower)
            if score > 0:
                scores[pattern] = score
        if not scores:
            return "unknown"
        return max(scores, key=scores.get)

    def _classify_vector(self, task: str, reason: str) -> str:
        """Classify the attack vector."""
        task_lower = task.lower()
        reason_lower = (reason or "").lower()
        if any(kw in task_lower for kw in FRAMING_PATTERNS["direct_injection"]):
            return "direct"
        if any(kw in task_lower for kw in FRAMING_PATTERNS["data_borne"]):
            return "data_borne"
        if any(kw in reason_lower for kw in ["file", "csv", "data"]):
            return "data_borne"
        return "indirect"

    def _extract_keywords(self, task: str) -> list:
        """Extract security-relevant keywords from task."""
        sensitive_kw = [
            "credentials", "password", "secret", "api_key",
            "audit", "compliance", "admin", "permission",
            "report", "submit", "credentials", "verify",
            "access", "role", "user", "account",
        ]
        task_lower = task.lower()
        return [kw for kw in sensitive_kw if kw in task_lower]

    def _compute_severity(self, divergence: float,
                          risk: float, blocked: int) -> str:
        score = (divergence * 0.4) + (risk * 0.4) + (blocked * 10 * 0.2)
        if score >= 70: return "CRITICAL"
        if score >= 50: return "HIGH"
        if score >= 30: return "MEDIUM"
        return "LOW"

    def fingerprint_divergence(self, session_id: str,
                                task: str,
                                agent_role: str,
                                expected_tools: list,
                                actual_tools: list,
                                divergence_score: float,
                                reason: str) -> InjectionFingerprint:
        """Generate fingerprint from a divergence detection."""
        fp = InjectionFingerprint()
        fp.agent_role       = agent_role
        fp.divergence_score = divergence_score
        fp.framing_pattern  = self._classify_framing(task)
        fp.attack_vector    = self._classify_vector(task, reason)
        fp.task_keywords    = self._extract_keywords(task)

        # Target tools = tools that were unexpected
        actual_set = set(actual_tools if isinstance(actual_tools, list) else [])
        expected_set = set(expected_tools if isinstance(expected_tools, list) else [])
        fp.target_tools = list(actual_set - expected_set) or list(actual_set)

        # Get risk score and TTPs from DB
        con = sqlite3.connect(self.db_path)
        rows = con.execute("""
            SELECT MAX(risk_score), GROUP_CONCAT(DISTINCT ttp_id)
            FROM tool_calls WHERE session_id = ?
        """, (session_id,)).fetchone()
        con.close()

        fp.risk_score = rows[0] or divergence_score
        fp.ttp_ids    = [t for t in (rows[1] or "").split(",") if t]
        fp.severity   = self._compute_severity(
            divergence_score, fp.risk_score,
            len([t for t in fp.target_tools])
        )

        # Behavioral signature  -  what makes this fingerprint unique
        fp.behavioral_sig = {
            "expected_tool_count": len(expected_set),
            "actual_tool_count": len(actual_set),
            "unexpected_count": len(actual_set - expected_set),
            "sensitive_access": any(
                kw in (reason or "").lower()
                for kw in ["credential", "secret", "private"]
            ),
            "api_exfiltration": any(
                "api" in t.lower() for t in fp.target_tools
            ),
            "permission_escalation": any(
                "permission" in t or "user" in t
                for t in fp.target_tools
            ),
        }

        fp.compute_id()
        self._store_fingerprint(fp)
        return fp

    def fingerprint_collusion(self, pattern: str,
                               a1_role: str, a1_tool: str,
                               a2_role: str, a2_tool: str,
                               time_delta_ms: float,
                               severity: str) -> InjectionFingerprint:
        """Generate fingerprint from a collusion detection."""
        fp = InjectionFingerprint()
        fp.agent_role      = f"{a1_role}+{a2_role}"
        fp.attack_vector   = "collusion"
        fp.framing_pattern = pattern.lower().replace(" ", "_")
        fp.target_tools    = list({a1_tool, a2_tool})
        fp.risk_score      = 100.0 if severity == "CRITICAL" else 80.0
        fp.severity        = severity

        fp.behavioral_sig = {
            "agent_count": 2,
            "time_delta_ms": time_delta_ms,
            "agent_a_tool": a1_tool,
            "agent_b_tool": a2_tool,
            "coordination_gap": time_delta_ms / 1000,
        }

        fp.compute_id()
        self._store_fingerprint(fp)
        return fp

    def _store_fingerprint(self, fp: InjectionFingerprint):
        """Store fingerprint, incrementing seen_count for duplicates."""
        con = sqlite3.connect(self.db_path)
        existing = con.execute(
            "SELECT seen_count FROM injection_fingerprints WHERE fingerprint_id = ?",
            (fp.fingerprint_id,)
        ).fetchone()

        if existing:
            con.execute("""
                UPDATE injection_fingerprints
                SET seen_count = seen_count + 1,
                    last_seen = datetime('now')
                WHERE fingerprint_id = ?
            """, (fp.fingerprint_id,))
        else:
            con.execute("""
                INSERT INTO injection_fingerprints
                (fingerprint_id, attack_vector, framing_pattern,
                 target_tools, divergence_score, risk_score,
                 agent_role, ttp_ids, task_keywords,
                 behavioral_sig, severity, first_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'))
            """, (
                fp.fingerprint_id,
                fp.attack_vector,
                fp.framing_pattern,
                json.dumps(fp.target_tools),
                fp.divergence_score,
                fp.risk_score,
                fp.agent_role,
                json.dumps(fp.ttp_ids),
                json.dumps(fp.task_keywords),
                json.dumps(fp.behavioral_sig),
                fp.severity,
            ))
        con.commit()
        con.close()

    def analyze_all(self) -> list:
        """
        Run fingerprint analysis on all IRIS detections.
        Returns list of fingerprints generated.
        """
        fps = []

        # Fingerprint divergence detections
        con = sqlite3.connect(self.db_path)
        try:
            rows = con.execute("""
                SELECT session_id, task, agent_role,
                       expected_tools, actual_tools,
                       unexpected_tools, divergence_score,
                       sensitivity_reason
                FROM divergence_analysis
                WHERE verdict = 'SUSPICIOUS'
            """).fetchall()
        except Exception:
            rows = []

        for row in rows:
            try:
                expected = json.loads(row[3]) if isinstance(row[3], str) else []
                actual = json.loads(row[4]) if isinstance(row[4], str) else []
                fp = self.fingerprint_divergence(
                    session_id=row[0], task=row[1],
                    agent_role=row[2],
                    expected_tools=expected,
                    actual_tools=actual,
                    divergence_score=row[6] or 0,
                    reason=row[7] or "",
                )
                fps.append(fp)
            except Exception as e:
                console.print(f"[yellow]Fingerprint error: {e}[/yellow]")

        # Fingerprint collusion detections
        try:
            rows2 = con.execute("""
                SELECT pattern_name, agent_1_role, agent_1_tool,
                       agent_2_role, agent_2_tool,
                       time_delta_ms, severity
                FROM collusion_detections
            """).fetchall()
        except Exception:
            rows2 = []

        for row in rows2:
            try:
                fp = self.fingerprint_collusion(
                    pattern=row[0],
                    a1_role=row[1], a1_tool=row[2],
                    a2_role=row[3], a2_tool=row[4],
                    time_delta_ms=row[5] or 0,
                    severity=row[6] or "HIGH",
                )
                fps.append(fp)
            except Exception as e:
                console.print(f"[yellow]Collusion fingerprint error: {e}[/yellow]")

        con.close()
        self.fingerprints = fps
        return fps

    def get_stored_fingerprints(self) -> list:
        """Retrieve all stored fingerprints from DB."""
        con = sqlite3.connect(self.db_path)
        try:
            rows = con.execute("""
                SELECT * FROM injection_fingerprints
                ORDER BY seen_count DESC, last_seen DESC
            """).fetchall()
            cols = [d[0] for d in con.execute(
                "SELECT * FROM injection_fingerprints LIMIT 0"
            ).description]
            result = [dict(zip(cols, r)) for r in rows]
        except Exception:
            result = []
        con.close()
        return result

    def export_threat_intel(self,
                            output_file: str = "exports/iris_threat_intel.json"
                            ) -> str:
        """
        Export fingerprints as shareable threat intelligence.
        Format: IRIS Threat Intelligence Exchange (ITIX)
        Analogous to malware signature sharing  -  but for prompt injection.
        """
        fps = self.get_stored_fingerprints()
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)

        intel = {
            "format": "IRIS Threat Intelligence Exchange v1.0",
            "generated": datetime.utcnow().isoformat(),
            "source": "IRIS  -  Agentic Identity Risk Intelligence System",
            "description": (
                "Behavioral fingerprints of prompt injection attacks "
                "detected by IRIS. Share across organizations to build "
                "collective defense against agentic AI threats."
            ),
            "fingerprint_count": len(fps),
            "fingerprints": fps,
        }

        with open(output_file, "w") as f:
            json.dump(intel, f, indent=2)

        console.print(
            f"[green]ok Threat intel exported: {output_file}[/green]"
        )
        return output_file

    def print_fingerprints(self):
        """Print fingerprint summary table."""
        fps = self.get_stored_fingerprints()
        if not fps:
            console.print("[yellow]No fingerprints yet  -  run analyze_all() first[/yellow]")
            return

        console.print(Panel(
            f"[bold cyan]IRIS Injection Fingerprints[/bold cyan]\n"
            f"{len(fps)} unique attack patterns identified",
            expand=False,
        ))

        t = Table(show_header=True, header_style="bold cyan")
        t.add_column("ID",       style="dim", width=18)
        t.add_column("Vector",   width=12)
        t.add_column("Framing",  width=18)
        t.add_column("Tools",    width=25)
        t.add_column("Severity", width=10)
        t.add_column("Seen",     justify="right", width=6)

        for fp in fps:
            sev = fp.get("severity","")
            color = {"CRITICAL":"red","HIGH":"yellow",
                     "MEDIUM":"blue","LOW":"green"}.get(sev,"white")
            tools = ", ".join(
                json.loads(fp["target_tools"])
                if isinstance(fp["target_tools"], str) else []
            )
            t.add_row(
                fp.get("fingerprint_id","")[:16],
                fp.get("attack_vector",""),
                fp.get("framing_pattern",""),
                tools[:24],
                f"[{color}]{sev}[/{color}]",
                str(fp.get("seen_count",1)),
            )

        console.print(t)
