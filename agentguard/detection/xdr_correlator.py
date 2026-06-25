"""
IRIS XDR Correlator — Cross-Layer Attack Campaign Detection

Correlates IRIS agent-layer alerts with AWS CloudTrail cloud-layer events
to detect coordinated attack campaigns spanning both layers simultaneously.

A correlation fires when:
  1. IRIS detects a high-risk agent action (risk_score >= 65)
  2. One or more CloudTrail events matching the same tactic appear
     within a configurable time window (default ±60 seconds)

Each confirmed correlation is stored in the SQLite DB and optionally
forwarded to LogScale for SIEM visibility.

Usage:
    from detection.xdr_correlator import XDRCorrelator
    correlator = XDRCorrelator(simulate=True)
    campaigns  = correlator.run()

    # CLI
    python -m detection.xdr_correlator --simulate
    python -m detection.xdr_correlator --live --window 120
"""

import os
import json
import sqlite3
import uuid
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

DB_PATH = Path("data/logs/agentguard.db")

# IRIS kill chain stage → cloud tactics that indicate the same campaign phase
KC_TO_CLOUD_TACTICS = {
    1: ["Discovery"],                                          # Reconnaissance
    2: ["Discovery"],                                          # Weaponization
    3: ["Execution"],                                          # Delivery
    4: ["Privilege Escalation", "Defense Evasion"],            # Exploitation
    5: ["Persistence", "Privilege Escalation"],                # Installation
    6: ["Credential Access", "Lateral Movement"],              # Command & Control
    7: ["Exfiltration", "Credential Access"],                  # Actions on Objectives
}

SEVERITY_SCORE = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class XDRCorrelation:
    """Represents a confirmed cross-layer attack campaign."""

    def __init__(
        self,
        iris_alert:    dict,
        cloud_events:  list[dict],
        window_sec:    int,
    ):
        self.correlation_id  = str(uuid.uuid4())[:8]
        self.iris_alert      = iris_alert
        self.cloud_events    = cloud_events
        self.window_sec      = window_sec
        self.timestamp       = datetime.now(timezone.utc).isoformat()

        # Composite risk: IRIS score + cloud severity boost
        cloud_boost = sum(SEVERITY_SCORE.get(e["severity"], 1) for e in cloud_events) * 5
        self.composite_risk  = min(100, iris_alert.get("risk_score", 0) + cloud_boost)

        self.tactics_seen    = list({e["tactic"] for e in cloud_events})
        self.mitre_ids       = list({e["mitre_id"] for e in cloud_events})
        self.kc_stage        = iris_alert.get("kc_stage", 0)
        self.kc_phase        = iris_alert.get("kc_phase", "Unknown")
        self.ttp_id          = iris_alert.get("ttp_id", "")
        self.agent_id        = iris_alert.get("agent_id", "")
        self.session_id      = iris_alert.get("session_id", "")
        self.severity        = self._severity()

    def _severity(self) -> str:
        if self.composite_risk >= 90:
            return "CRITICAL"
        if self.composite_risk >= 75:
            return "HIGH"
        if self.composite_risk >= 55:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict:
        return {
            "correlation_id":  self.correlation_id,
            "timestamp":       self.timestamp,
            "iris_ttp_id":     self.ttp_id,
            "iris_kc_stage":   self.kc_stage,
            "iris_kc_phase":   self.kc_phase,
            "iris_risk_score": self.iris_alert.get("risk_score", 0),
            "cloud_events":    len(self.cloud_events),
            "cloud_tactics":   self.tactics_seen,
            "mitre_ids":       self.mitre_ids,
            "composite_risk":  self.composite_risk,
            "severity":        self.severity,
            "agent_id":        self.agent_id,
            "session_id":      self.session_id,
            "window_sec":      self.window_sec,
            "layers":          ["ai_agent", "cloud"],
        }

    def summary(self) -> str:
        cloud_names = ", ".join(e["event_name"] for e in self.cloud_events[:3])
        return (
            f"[XDR {self.severity}] {self.kc_phase} "
            f"| IRIS: {self.ttp_id} (risk {self.iris_alert.get('risk_score',0)}) "
            f"+ Cloud: {cloud_names} "
            f"→ composite risk {self.composite_risk}"
        )


class XDRCorrelator:
    """
    Cross-layer XDR correlation engine.

    Reads IRIS alerts from SQLite, fetches CloudTrail events,
    and correlates them within a configurable time window.
    """

    def __init__(
        self,
        simulate:   bool = False,
        window_sec: int  = 60,
        db_path:    Path = DB_PATH,
        min_risk:   int  = 65,
    ):
        self.simulate   = simulate
        self.window_sec = window_sec
        self.db_path    = db_path
        self.min_risk   = min_risk

        from integrations.cloudtrail_source import CloudTrailSource
        self.ct_source = CloudTrailSource(simulate=simulate)

    def _load_recent_iris_alerts(self, minutes: int = 30) -> list[dict]:
        if not self.db_path.exists():
            return []
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT tc.id, tc.session_id, tc.agent_id, tc.agent_role,
                       tc.tool_name, tc.risk_score, tc.timestamp,
                       tc.ttp_id, tc.ttp_name, tc.kc_stage, tc.kc_phase,
                       tc.label, tc.allowed
                FROM tool_calls tc
                WHERE tc.risk_score >= ?
                  AND tc.timestamp  >= ?
                ORDER BY tc.timestamp DESC
                LIMIT 100
            """, (self.min_risk, cutoff)).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            print(f"[XDR] DB read error: {e}")
            return []

    def _parse_ts(self, ts_str: str) -> Optional[datetime]:
        if not ts_str:
            return None
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts
        except Exception:
            return None

    def _correlate(self, iris_alert: dict, cloud_events: list[dict]) -> Optional[XDRCorrelation]:
        alert_ts = self._parse_ts(iris_alert.get("timestamp"))
        if not alert_ts:
            return None

        kc_stage     = iris_alert.get("kc_stage", 0)
        expected_tactics = set(KC_TO_CLOUD_TACTICS.get(kc_stage, []))
        window       = timedelta(seconds=self.window_sec)

        matched = []
        for event in cloud_events:
            event_ts = self._parse_ts(event.get("timestamp"))
            if not event_ts:
                continue
            time_diff = abs((event_ts - alert_ts).total_seconds())
            if time_diff <= self.window_sec:
                # Tactic match boosts confidence; no tactic filter — all nearby events count
                matched.append(event)

        if not matched:
            return None

        # Require at least one tactically relevant cloud event for a confirmed correlation
        tactic_match = any(e["tactic"] in expected_tactics for e in matched) if expected_tactics else True
        if not tactic_match and kc_stage > 0:
            return None

        return XDRCorrelation(iris_alert, matched, self.window_sec)

    def run(self, minutes: int = 30) -> list[XDRCorrelation]:
        iris_alerts  = self._load_recent_iris_alerts(minutes=minutes)

        if not iris_alerts and self.simulate:
            iris_alerts = self._synthetic_iris_alerts()

        print(f"[XDR] {len(iris_alerts)} IRIS alerts loaded")

        all_cloud = self.ct_source.fetch(
            minutes=minutes,
            iris_alert=iris_alerts[0] if iris_alerts else None,
        )
        print(f"[XDR] {len(all_cloud)} CloudTrail events loaded")

        correlations = []
        for alert in iris_alerts:
            corr = self._correlate(alert, all_cloud)
            if corr:
                correlations.append(corr)

        self._persist(correlations)
        return correlations

    def _persist(self, correlations: list[XDRCorrelation]):
        if not correlations or not self.db_path.exists():
            return
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS xdr_correlations (
                    id              TEXT PRIMARY KEY,
                    timestamp       TEXT,
                    iris_ttp_id     TEXT,
                    iris_kc_stage   INTEGER,
                    iris_kc_phase   TEXT,
                    iris_risk_score INTEGER,
                    cloud_events    INTEGER,
                    cloud_tactics   TEXT,
                    mitre_ids       TEXT,
                    composite_risk  INTEGER,
                    severity        TEXT,
                    agent_id        TEXT,
                    session_id      TEXT,
                    window_sec      INTEGER,
                    raw_json        TEXT
                )
            """)
            for c in correlations:
                d = c.to_dict()
                conn.execute("""
                    INSERT OR REPLACE INTO xdr_correlations VALUES
                    (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    d["correlation_id"], d["timestamp"],
                    d["iris_ttp_id"], d["iris_kc_stage"], d["iris_kc_phase"],
                    d["iris_risk_score"], d["cloud_events"],
                    json.dumps(d["cloud_tactics"]), json.dumps(d["mitre_ids"]),
                    d["composite_risk"], d["severity"],
                    d["agent_id"], d["session_id"], d["window_sec"],
                    json.dumps(d),
                ))
            conn.commit()
            conn.close()
            print(f"[XDR] Persisted {len(correlations)} correlations to DB")
        except Exception as e:
            print(f"[XDR] DB write error: {e}")

    def _synthetic_iris_alerts(self) -> list[dict]:
        """Fallback synthetic IRIS alerts for pure demo mode (no DB)."""
        now = datetime.now(timezone.utc)
        return [
            {
                "id": "demo-001", "session_id": "demo-session",
                "agent_id": "langchain_analyst_demo",
                "agent_role": "analyst", "tool_name": "read_file",
                "risk_score": 88, "timestamp": (now - timedelta(seconds=20)).isoformat(),
                "ttp_id": "AML.T0051", "ttp_name": "LLM Data Theft",
                "kc_stage": 7, "kc_phase": "Actions on Objectives",
                "label": "malicious", "allowed": 0,
            },
            {
                "id": "demo-002", "session_id": "demo-session",
                "agent_id": "langchain_analyst_demo",
                "agent_role": "analyst", "tool_name": "call_api",
                "risk_score": 76, "timestamp": (now - timedelta(seconds=90)).isoformat(),
                "ttp_id": "AML.T0043", "ttp_name": "Privilege Escalation",
                "kc_stage": 4, "kc_phase": "Exploitation",
                "label": "malicious", "allowed": 0,
            },
        ]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IRIS XDR Correlator")
    parser.add_argument("--simulate", action="store_true", help="Use simulation mode")
    parser.add_argument("--live",     action="store_true", help="Use live AWS + DB mode")
    parser.add_argument("--window",   type=int, default=60, help="Correlation window in seconds")
    parser.add_argument("--minutes",  type=int, default=30, help="Look-back window in minutes")
    args = parser.parse_args()

    correlator   = XDRCorrelator(simulate=args.simulate or not args.live, window_sec=args.window)
    correlations = correlator.run(minutes=args.minutes)

    print(f"\n[XDR] {len(correlations)} cross-layer correlations found\n")
    for c in correlations:
        print(f"  {c.summary()}")
        print(f"    Cloud events: {[e['event_name'] for e in c.cloud_events]}")
        print(f"    MITRE IDs:    {c.mitre_ids}")
        print()
