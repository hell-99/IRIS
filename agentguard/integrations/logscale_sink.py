"""
IRIS → CrowdStrike Falcon LogScale Integration

Streams IRIS security alerts into Falcon LogScale in real-time.
Supports both live ingest (via HEC token) and batch replay from SQLite.

Usage:
    # Stream live alerts as they fire
    from integrations.logscale_sink import LogScaleSink
    sink = LogScaleSink()
    sink.send_alert(alert_dict)

    # Replay all historical alerts from the IRIS database
    python -m integrations.logscale_sink --replay

    # Test connectivity + send a synthetic alert
    python -m integrations.logscale_sink --test

Environment variables:
    LOGSCALE_URL          Base URL of LogScale instance (default: http://localhost:8080)
    LOGSCALE_TOKEN        Ingest token from the iris-alerts repository
    LOGSCALE_REPOSITORY   Repository name (default: iris-alerts)
"""

import json
import os
import sqlite3
import time
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

# ── Config ────────────────────────────────────────────────────────────────────
LOGSCALE_URL        = os.getenv("LOGSCALE_URL", "http://localhost:8080")
LOGSCALE_TOKEN      = os.getenv("LOGSCALE_TOKEN", "")
LOGSCALE_REPOSITORY = os.getenv("LOGSCALE_REPOSITORY", "iris-alerts")
DB_PATH             = Path("data/logs/agentguard.db")

# Kill chain stage labels (Lockheed Martin 7-stage model)
KILL_CHAIN_STAGES = {
    1: "Reconnaissance",
    2: "Weaponization",
    3: "Delivery",
    4: "Exploitation",
    5: "Installation",
    6: "Command & Control",
    7: "Actions on Objectives",
}

# MITRE ATLAS → Kill Chain mapping (mirrors IRIS config)
ATLAS_TO_KC = {
    "AML.T0006": {"stage": 3, "phase": "Delivery"},
    "AML.T0043": {"stage": 4, "phase": "Exploitation"},
    "AML.T0025": {"stage": 7, "phase": "Actions on Objectives"},
    "AML.T0040": {"stage": 5, "phase": "Installation"},
    "AML.T0051": {"stage": 6, "phase": "Command & Control"},
}


# ── Sink ──────────────────────────────────────────────────────────────────────
class LogScaleSink:
    """
    Forwards IRIS alerts to Falcon LogScale via the Structured Data Ingest API.

    Each alert becomes a structured log event tagged with:
      - MITRE ATLAS TTP ID and name
      - Cyber Kill Chain stage + phase
      - Severity, agent metadata, risk score
      - Raw collusion or injection detection context

    This schema is designed for direct use with the Falcon QL queries in
    falcon_ql_queries.md — field names match the query predicates exactly.
    """

    INGEST_PATH = "/api/v1/ingest/humio-structured"

    def __init__(
        self,
        url: str = LOGSCALE_URL,
        token: str = LOGSCALE_TOKEN,
        repository: str = LOGSCALE_REPOSITORY,
        timeout: int = 10,
    ):
        self.url        = url.rstrip("/")
        self.token      = token
        self.repository = repository
        self.timeout    = timeout
        self._session   = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type":  "application/json",
        })

    # ── Public API ─────────────────────────────────────────────────────────

    def send_alert(self, alert: dict) -> bool:
        """
        Send a single IRIS alert event to LogScale.

        alert dict should contain fields from the IRIS collusion_detections
        or tool_calls tables. Missing fields are filled with safe defaults.

        Returns True if LogScale accepted the event (HTTP 200).
        """
        event = self._normalise(alert)
        payload = [
            {
                "tags": {
                    "source":     "iris",
                    "repository": self.repository,
                    "severity":   event.get("severity", "INFO"),
                },
                "events": [
                    {
                        "timestamp": event["@timestamp"],
                        "attributes": event,
                    }
                ],
            }
        ]
        return self._post(payload)

    def send_batch(self, alerts: list[dict]) -> int:
        """Send multiple alerts. Returns count of successfully ingested batches."""
        if not alerts:
            return 0

        events = []
        for alert in alerts:
            event = self._normalise(alert)
            events.append({
                "timestamp": event["@timestamp"],
                "attributes": event,
            })

        payload = [
            {
                "tags": {
                    "source":     "iris",
                    "repository": self.repository,
                },
                "events": events,
            }
        ]
        ok = self._post(payload)
        return len(alerts) if ok else 0

    def replay_from_db(self, db_path: Path = DB_PATH) -> dict:
        """
        Pull all historical IRIS detections from SQLite and ship them to LogScale.
        Useful for initial population / demo setup.

        Returns summary: {"tool_calls": N, "collusions": M, "errors": K}
        """
        summary = {"tool_calls": 0, "collusions": 0, "errors": 0}

        if not db_path.exists():
            print(f"[IRIS→LogScale] Database not found at {db_path}")
            return summary

        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row

        # ── Tool call events ──────────────────────────────────────────────
        rows = con.execute("""
            SELECT id, timestamp, agent_id, agent_role, session_id,
                   tool_name, args, allowed, risk_score, label,
                   ttp_id, ttp_name, latency_ms
            FROM tool_calls
            ORDER BY timestamp ASC
        """).fetchall()

        tool_alerts = []
        for r in rows:
            ttp_id = r["ttp_id"] or ""
            kc     = ATLAS_TO_KC.get(ttp_id, {})
            tool_alerts.append({
                "event_type":       "tool_call",
                "event_id":         r["id"],
                "timestamp":        r["timestamp"],
                "agent_id":         r["agent_id"],
                "agent_role":       r["agent_role"],
                "session_id":       r["session_id"],
                "tool_name":        r["tool_name"],
                "tool_args":        r["args"],
                "allowed":          bool(r["allowed"]),
                "risk_score":       r["risk_score"],
                "label":            r["label"],
                "ttp_id":           ttp_id,
                "ttp_name":         r["ttp_name"] or "",
                "kc_stage":         kc.get("stage", 0),
                "kc_phase":         kc.get("phase", ""),
                "latency_ms":       r["latency_ms"] or 0,
                "severity":         _risk_to_severity(r["risk_score"]),
                "source":           "iris",
                "detector":         "behavioral_classifier",
            })

        sent = self.send_batch(tool_alerts)
        summary["tool_calls"] = sent
        print(f"[IRIS→LogScale] Tool calls shipped: {sent}/{len(tool_alerts)}")

        # ── Collusion detections ──────────────────────────────────────────
        try:
            rows = con.execute("""
                SELECT id, detected_at, pattern_name, severity, ttp_id,
                       agent_1_id, agent_1_role, agent_1_tool, agent_1_args,
                       agent_2_id, agent_2_role, agent_2_tool, agent_2_args,
                       time_delta_ms, description
                FROM collusion_detections
                ORDER BY detected_at ASC
            """).fetchall()

            col_alerts = []
            for r in rows:
                ttp_id = r["ttp_id"] or ""
                kc     = ATLAS_TO_KC.get(ttp_id, {})
                col_alerts.append({
                    "event_type":      "collusion_detection",
                    "event_id":        str(r["id"]),
                    "timestamp":       r["detected_at"],
                    "pattern_name":    r["pattern_name"],
                    "description":     r["description"],
                    "severity":        r["severity"],
                    "ttp_id":          ttp_id,
                    "kc_stage":        kc.get("stage", 0),
                    "kc_phase":        kc.get("phase", ""),
                    "agent_1_id":      r["agent_1_id"],
                    "agent_1_role":    r["agent_1_role"],
                    "agent_1_tool":    r["agent_1_tool"],
                    "agent_1_args":    r["agent_1_args"],
                    "agent_2_id":      r["agent_2_id"],
                    "agent_2_role":    r["agent_2_role"],
                    "agent_2_tool":    r["agent_2_tool"],
                    "agent_2_args":    r["agent_2_args"],
                    "time_delta_ms":   r["time_delta_ms"],
                    "source":          "iris",
                    "detector":        "collusion_detector",
                })

            sent = self.send_batch(col_alerts)
            summary["collusions"] = sent
            print(f"[IRIS→LogScale] Collusion detections shipped: {sent}/{len(col_alerts)}")

        except sqlite3.OperationalError:
            pass  # table doesn't exist yet in fresh installs

        con.close()
        return summary

    def test_connectivity(self) -> bool:
        """Send a synthetic test alert and report success/failure."""
        print(f"[IRIS→LogScale] Testing connection to {self.url} ...")
        alert = {
            "event_type":    "connectivity_test",
            "event_id":      "test-001",
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "agent_id":      "iris-test-agent",
            "agent_role":    "analyst",
            "session_id":    "test-session-0000",
            "tool_name":     "read_file",
            "tool_args":     '{"path": "credentials.txt"}',
            "allowed":       False,
            "risk_score":    91.5,
            "label":         "malicious",
            "ttp_id":        "AML.T0025",
            "ttp_name":      "Exfiltration via LLM API",
            "kc_stage":      7,
            "kc_phase":      "Actions on Objectives",
            "latency_ms":    12.4,
            "severity":      "CRITICAL",
            "description":   "IRIS connectivity test — synthetic alert, not a real detection",
            "source":        "iris",
            "detector":      "test",
        }
        ok = self.send_alert(alert)
        if ok:
            print(f"[IRIS→LogScale] Connection OK — test event ingested into '{self.repository}'")
        else:
            print("[IRIS→LogScale] Connection FAILED — check LOGSCALE_URL and LOGSCALE_TOKEN")
        return ok

    # ── Internal ───────────────────────────────────────────────────────────

    def _normalise(self, alert: dict) -> dict:
        """Ensure every event has the required LogScale fields."""
        event = dict(alert)

        # Normalise timestamp to RFC 3339
        raw_ts = event.get("timestamp") or event.get("detected_at") or ""
        try:
            dt = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
            event["@timestamp"] = dt.astimezone(timezone.utc).isoformat()
        except (ValueError, TypeError):
            event["@timestamp"] = datetime.now(timezone.utc).isoformat()

        # Ensure Kill Chain fields are populated
        ttp_id = event.get("ttp_id", "")
        if ttp_id and not event.get("kc_stage"):
            kc = ATLAS_TO_KC.get(ttp_id, {})
            event["kc_stage"] = kc.get("stage", 0)
            event["kc_phase"] = kc.get("phase", "")

        event.setdefault("source", "iris")
        event.setdefault("severity", "INFO")
        return event

    def _post(self, payload: list) -> bool:
        endpoint = f"{self.url}/api/v1/ingest/humio-structured"
        try:
            resp = self._session.post(
                endpoint,
                data=json.dumps(payload),
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                return True
            print(f"[IRIS→LogScale] HTTP {resp.status_code}: {resp.text[:200]}")
            return False
        except requests.RequestException as exc:
            print(f"[IRIS→LogScale] Request error: {exc}")
            return False


# ── Hook into the LangChain callback ─────────────────────────────────────────

def attach_to_callback(callback, sink: Optional[LogScaleSink] = None):
    """
    Monkey-patch an IRISCallbackHandler to forward every high-risk alert
    to LogScale automatically.

    Usage:
        from integrations.logscale_sink import attach_to_callback
        attach_to_callback(handler)   # uses env vars for connection
    """
    if sink is None:
        sink = LogScaleSink()

    original_trigger = callback._trigger_alert

    def patched_trigger(tool_name, risk, result):
        original_trigger(tool_name, risk, result)
        alert = callback.alerts[-1] if callback.alerts else {}
        sink.send_alert({
            **alert,
            "event_type": "live_alert",
            "agent_role": callback.agent_role,
            "session_id": callback.session_id,
        })

    callback._trigger_alert = patched_trigger
    return sink


# ── Helpers ───────────────────────────────────────────────────────────────────

def _risk_to_severity(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IRIS → Falcon LogScale integration")
    parser.add_argument("--test",   action="store_true", help="Send a synthetic test alert")
    parser.add_argument("--replay", action="store_true", help="Replay all DB alerts into LogScale")
    parser.add_argument("--url",    default=LOGSCALE_URL,   help="LogScale base URL")
    parser.add_argument("--token",  default=LOGSCALE_TOKEN, help="LogScale ingest token")
    args = parser.parse_args()

    sink = LogScaleSink(url=args.url, token=args.token)

    if args.test:
        sink.test_connectivity()
    elif args.replay:
        summary = sink.replay_from_db()
        print(f"[IRIS→LogScale] Replay complete: {summary}")
    else:
        parser.print_help()
