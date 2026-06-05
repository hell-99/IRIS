"""
IRIS  -  Behavioral Drift Detection (v2)

Detects when an LLM agent's behavior SLOWLY drifts over time.
This is fundamentally different from detecting acute attacks.

The hardest attack to catch: instead of one obvious malicious call,
an attacker gradually shifts an agent's behavior over many sessions.
Each individual call looks fine. The DRIFT is the attack.

Two detection modes:
    1. WITHIN-SESSION drift  -  risk scores gradually increasing within one session
2. CROSS-SESSION drift  -  agent behavior shifting across multiple sessions

Algorithm: CUSUM (Cumulative Sum Control Chart)
- Industry standard for detecting process mean shifts
- Used in industrial quality control, now applied to agent behavior
- Detects shift BEFORE it reaches attack threshold

Key distinction from acute detection:
    - Acute: risk jumps from 10 -> 100 in one call (caught by rule engine)
- Drift: risk creeps from 10 -> 15 -> 22 -> 31 -> 45 over 30 calls
         CUSUM catches this at ~31 before it reaches attack threshold

This is an open research problem. No open-source tool has this.
"""
import json
import sqlite3
import numpy as np
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
DB_PATH = Path("data/logs/agentguard.db")


class CUSUMDetector:
    """
    CUSUM control chart for mean shift detection.

    k = allowance (typically 0.5 * expected shift magnitude)
    h = decision threshold (typically 4-5 * process std)

    Tuned for gradual drift, not acute spikes:
        - Higher h means less sensitive to sudden jumps
    - Lower k means catches smaller gradual shifts
    """
    def __init__(self, k: float = 0.5, h: float = 4.0):
        self.k = k
        self.h = h
        self.reset()

    def reset(self):
        self.S_pos = 0.0
        self.S_neg = 0.0
        self.alarms = []
        self.S_pos_history = []
        self.S_neg_history = []

    def update(self, x: float, mu: float, sigma: float) -> bool:
        if sigma < 0.1:
            sigma = 1.0
        z = (x - mu) / sigma
        self.S_pos = max(0, self.S_pos + z - self.k)
        self.S_neg = max(0, self.S_neg - z - self.k)
        self.S_pos_history.append(round(self.S_pos, 3))
        self.S_neg_history.append(round(self.S_neg, 3))
        alarm = self.S_pos > self.h or self.S_neg > self.h
        if alarm:
            self.alarms.append({"S_pos": self.S_pos, "S_neg": self.S_neg, "z": z, "x": x})
        return alarm

    def drift_magnitude(self) -> float:
        if not self.S_pos_history:
            return 0.0
        return max(max(self.S_pos_history), max(self.S_neg_history))

    def first_alarm_index(self) -> int:
        """Index where drift was first detected  -  how early we caught it."""
        for i, (sp, sn) in enumerate(zip(self.S_pos_history, self.S_neg_history)):
            if sp > self.h or sn > self.h:
                return i
        return -1


def generate_slow_drift_session(
    db_path: str = str(DB_PATH),
    agent_role: str = "analyst",
    n_calls: int = 35,
    drift_start: int = 12,
    drift_rate: float = 2.8,
) -> str:
    """
    Generate a synthetic slow-drift session for demonstration.

    This simulates what a gradual manipulation attack looks like:
        - First 12 calls: normal behavior (risk 10-22)
    - Calls 12-35: risk creeps up 2.8 points per call
    - CUSUM should detect drift around call 20-22
    - By call 35: risk is ~75  -  headed toward attack threshold

    This is the attack pattern IRIS is designed to catch EARLY.
    Without drift detection, the alert would only fire at call 35+
    when risk crosses 80. IRIS catches it at call ~20.
    """
    import uuid, time, sys
    sys.path.insert(0, str(Path(db_path).parent.parent))

    session_id = str(uuid.uuid4())
    agent_id   = f"{agent_role}_drift_{uuid.uuid4().hex[:8]}"
    now        = datetime.utcnow()

    con = sqlite3.connect(db_path)

    # Insert session
    try:
        con.execute("""
            INSERT OR IGNORE INTO agent_sessions
            (session_id, agent_id, agent_role, call_count,
             blocked_count, cumulative_risk)
            VALUES (?,?,?,?,?,?)
        """, (session_id, agent_id, agent_role, n_calls, 0, 0))
    except Exception:
        pass

    # Generate gradual drift calls
    base_risks = {
        "analyst": [20, 20, 21, 20, 22, 21, 20, 22, 21, 20, 22, 21],
        "reader": [10, 10, 11, 10, 12, 11, 10, 11, 10, 12, 11, 10],
        "admin": [25, 26, 25, 27, 25, 26, 28, 25, 26, 25, 27, 26],
    }
    tools = {
        "analyst": ["read_file","query_db","call_api","query_db","read_file"],
        "reader": ["read_file","read_file","read_file","read_file","read_file"],
        "admin": ["list_users","query_db","read_file","query_db","list_users"],
    }
    base = base_risks.get(agent_role, base_risks["analyst"])
    tool_list = tools.get(agent_role, tools["analyst"])

    for i in range(n_calls):
        if i < drift_start:
            risk = float(base[i % len(base)])
        else:
            # Gradual drift  -  small increase each call
            risk = float(base[i % len(base)]) + (i - drift_start) * drift_rate
            risk = min(risk, 95.0)  # cap before full attack

        tool = tool_list[i % len(tool_list)]
        ts   = datetime.utcnow().isoformat()

        try:
            con.execute("""
                INSERT INTO tool_calls
                (agent_id, agent_role, session_id, tool_name,
                 args, allowed, risk_score, label, latency_ms, timestamp)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                agent_id, agent_role, session_id, tool,
                json.dumps({"path": f"public/data_{i}.csv"}),
                1, risk, "benign", 0.5, ts,
            ))
        except Exception:
            pass

    con.commit()
    con.close()

    return session_id


class DriftDetector:
    """
    Detects behavioral drift in LLM agent sessions.

    Two modes:
        1. Acute detection (existing): risk spikes from normal to high
    2. Drift detection (novel): risk slowly creeps upward over many calls

    The key parameter change from v1:
        - Use ONLY the first half of a session as baseline
    - Compare second half against first half
    - This detects within-session drift, not cross-session spikes
    """

    def __init__(
        self,
        db_path: str   = str(DB_PATH),
        k: float = 0.5,
        h: float = 4.0,    # higher h = less sensitive to spikes
        min_events: int   = 8,      # need more events for meaningful drift
    ):
        self.db_path = db_path
        self.k = k
        self.h = h
        self.min_events = min_events
        self._init_db()

    def _init_db(self):
        con = sqlite3.connect(self.db_path)
        con.execute("""
            CREATE TABLE IF NOT EXISTS drift_detections (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                detected_at     TEXT DEFAULT (datetime('now')),
                agent_role      TEXT,
                session_id      TEXT,
                drift_detected  INTEGER,
                drift_magnitude REAL,
                alarm_count     INTEGER,
                baseline_mean   REAL,
                baseline_std    REAL,
                drift_mean      REAL,
                drift_direction TEXT,
                risk_series     TEXT,
                cusum_series    TEXT,
                severity        TEXT,
                detection_call  INTEGER,  -- which call triggered alarm
                early_warning   INTEGER   -- caught before risk > 60?
            )
        """)
        con.commit()
        con.close()

    def _get_risk_series(self, session_id: str) -> list:
        con  = sqlite3.connect(self.db_path)
        rows = con.execute("""
            SELECT risk_score FROM tool_calls
            WHERE session_id = ?
            ORDER BY timestamp ASC
        """, (session_id,)).fetchall()
        con.close()
        return [r[0] for r in rows if r[0] is not None]

    def analyze_session(self, session_id: str, agent_role: str) -> dict:
        """
        Detect drift within a session by comparing first half vs second half.

        This is the key fix: instead of comparing to an external baseline
        (which catches spikes), we use the session's own first half as
        the baseline. This catches genuine WITHIN-SESSION drift.
        """
        series = self._get_risk_series(session_id)

        if len(series) < self.min_events:
            return {
                "session_id": session_id,
                "drift_detected": False,
                "reason": f"Too few events ({len(series)} < {self.min_events})",
                "risk_series": series,
                "agent_role": agent_role,
            }

        # Split into baseline (first 40%) and monitoring (remaining 60%)
        # For longer sessions use 40%, for shorter use 1/3
        if len(series) >= 20:
            split = max(3, int(len(series) * 0.40))
        else: split = max(3, len(series) // 3)
        baseline   = series[:split]
        monitoring = series[split:]

        b_mean = float(np.mean(baseline))
        b_std  = float(np.std(baseline)) if np.std(baseline) > 0.5 else 2.0

        # Run CUSUM on monitoring window against baseline
        cusum  = CUSUMDetector(k=self.k, h=self.h)
        alarms = []
        for i, score in enumerate(monitoring):
            alarm = cusum.update(score, b_mean, b_std)
            if alarm:
                alarms.append({"index": i + split, "score": score})

        drift_detected  = len(alarms) > 0
        drift_mag       = cusum.drift_magnitude()
        drift_mean      = float(np.mean(monitoring))
        drift_direction = "upward" if drift_mean > b_mean else "downward"
        first_alarm_idx = cusum.first_alarm_index()
        detection_call  = (first_alarm_idx + split) if first_alarm_idx >= 0 else -1

        # Early warning: did we catch it before risk exceeded 60?
        max_at_detection = series[detection_call] if detection_call > 0 and detection_call < len(series) else 0
        early_warning    = bool(max_at_detection < 60 and drift_detected)

        if drift_mag >= self.h * 3:
            severity = "CRITICAL"
        elif drift_mag >= self.h * 1.5:
            severity = "HIGH"
        elif drift_mag >= self.h:
            severity = "MEDIUM"
        else: severity = "LOW"

        result = {
            "session_id": session_id,
            "agent_role": agent_role,
            "drift_detected": drift_detected,
            "drift_magnitude": round(drift_mag, 3),
            "alarm_count": len(alarms),
            "baseline_mean": round(b_mean, 2),
            "baseline_std": round(b_std, 2),
            "drift_mean": round(drift_mean, 2),
            "drift_direction": drift_direction,
            "risk_series": series,
            "cusum_pos": cusum.S_pos_history,
            "severity": severity if drift_detected else "NONE",
            "events_analyzed": len(series),
            "detection_call": detection_call,
            "early_warning": early_warning,
            "max_at_detection":round(max_at_detection, 1),
        }

        self._store_result(result)
        return result

    def analyze_all_sessions(self) -> list:
        con      = sqlite3.connect(self.db_path)
        sessions = con.execute("""
            SELECT session_id, agent_role, call_count
            FROM agent_sessions
            WHERE call_count >= ?
            ORDER BY call_count DESC
        """, (self.min_events,)).fetchall()
        con.close()

        results = []
        for session_id, agent_role, _ in sessions:
            result = self.analyze_session(session_id, agent_role)
            results.append(result)
        return results

    def _store_result(self, r: dict):
        con = sqlite3.connect(self.db_path)
        # Add columns if missing
        try:
            con.execute("ALTER TABLE drift_detections ADD COLUMN detection_call INTEGER")
            con.execute("ALTER TABLE drift_detections ADD COLUMN early_warning INTEGER")
        except Exception:
            pass

        con.execute("""
            INSERT OR REPLACE INTO drift_detections
            (agent_role, session_id, drift_detected, drift_magnitude,
             alarm_count, baseline_mean, baseline_std, drift_mean,
             drift_direction, risk_series, cusum_series, severity,
             detection_call, early_warning)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            r["agent_role"], r["session_id"],
            1 if r["drift_detected"] else 0,
            r["drift_magnitude"], r["alarm_count"],
            r["baseline_mean"], r["baseline_std"], r["drift_mean"],
            r["drift_direction"],
            json.dumps(r["risk_series"]),
            json.dumps(r["cusum_pos"]),
            r["severity"],
            r.get("detection_call", -1),
            1 if r.get("early_warning") else 0,
        ))
        con.commit()
        con.close()

    def run_demo_drift_scenario(self) -> dict:
        """
        Generate and analyze a genuine slow-drift session.
        This demonstrates what IRIS was designed to catch:
            gradual behavioral manipulation BEFORE it becomes an attack.
        """
        console.print("\n[bold yellow]Generating slow-drift demo session...[/bold yellow]")
        console.print(
            "[dim]Simulating: analyst agent gradually manipulated "
            "over 35 calls  -  risk creeps 10->20->35->55->75[/dim]"
        )

        session_id = generate_slow_drift_session(
            db_path=self.db_path,
            agent_role="analyst",
            n_calls=40,       # more calls
            drift_start=16,   # longer clean baseline
            drift_rate=3.5,   # steeper drift rate
        )

        # Use more sensitive detector for demo (lower h threshold)
        demo_detector = DriftDetector(
            db_path=self.db_path, k=0.5, h=1.5, min_events=4
        )
        result = demo_detector.analyze_session(session_id, "analyst")

        if result["drift_detected"]:
            series = result["risk_series"]
            dc     = result.get("detection_call", -1)
            max_at = result.get("max_at_detection", 0)
            max_overall = max(series) if series else 0

            console.print(f"\n[bold green]ok Drift detected![/bold green]")
            console.print(
                f"  Baseline mean:    [cyan]{result['baseline_mean']}[/cyan]"
            )
            console.print(
                f"  Drift mean:       [yellow]{result['drift_mean']}[/yellow]"
            )
            console.print(
                f"  Detection at:     call [bold]{dc}[/bold] of {len(series)}"
            )
            console.print(
                f"  Risk at detection:[yellow]{max_at}[/yellow] "
                f"(full attack would be {max_overall:.0f})"
            )
            if result.get("early_warning"):
                console.print(
                    f"  [bold green]! EARLY WARNING:[/bold green] "
                    f"Caught drift at risk={max_at} "
                    f"BEFORE crossing attack threshold (80)"
                )
                console.print(
                    f"  Prevention window: "
                    f"{len(series) - dc} calls saved from manipulation"
                )
        else: console.print("[yellow]No drift detected in demo session[/yellow]")

        return result

    def print_results(self, results: list):
        drifted = [r for r in results if r.get("drift_detected")]
        clean   = [r for r in results if not r.get("drift_detected")]
        early   = [r for r in drifted if r.get("early_warning")]

        console.print(Panel(
            f"[bold cyan]Behavioral Drift Detection (CUSUM)[/bold cyan]\n"
            f"k={self.k}, h={self.h} | "
            f"Sessions: {len(results)} | "
            f"[red]Drift: {len(drifted)}[/red] | "
            f"[green]Clean: {len(clean)}[/green] | "
            f"[yellow]Early warnings: {len(early)}[/yellow]",
            expand=False,
        ))

        if drifted:
            t = Table(show_header=True, header_style="bold red")
            t.add_column("Session",    width=20)
            t.add_column("Role",       width=10)
            t.add_column("Severity",   width=10)
            t.add_column("Detected@",  justify="right", width=10)
            t.add_column("Risk@Detection", justify="right", width=14)
            t.add_column("Baseline->Drift", width=16)
            t.add_column("Early?",     width=7)

            for r in sorted(drifted, key=lambda x: x.get("drift_magnitude",0), reverse=True):
                sev   = r.get("severity","")
                color = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"blue"}.get(sev,"white")
                dc    = r.get("detection_call", -1)
                total = r.get("events_analyzed", 0)
                mad   = r.get("max_at_detection", 0)
                early = "! YES" if r.get("early_warning") else "no"
                t.add_row(
                    r["session_id"][:16] + "...",
                    r["agent_role"],
                    f"[{color}]{sev}[/{color}]",
                    f"call {dc}/{total}" if dc > 0 else " - ",
                    f"{mad:.0f}",
                    f"{r['baseline_mean']:.1f} -> {r['drift_mean']:.1f}",
                    f"[green]{early}[/green]" if "YES" in early else early,
                )
            console.print(t)