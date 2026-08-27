"""
Interceptor  -  wraps every tool call before execution.
Logs structured events to SQLite, enforces permission policy,
and emits real-time risk score updates.
"""
import hashlib
import json
import sqlite3
import time
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from config import AGENT_ROLES, MITRE_ATLAS_TTPS, RISK_THRESHOLD
from agents.tools import TOOL_REGISTRY, TOOL_SENSITIVITY
from security.tool_sandbox import get_sandbox, SandboxViolation

DB_PATH = Path("data/logs/agentguard.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Database setup
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS tool_calls (
            id           TEXT PRIMARY KEY,
            timestamp    TEXT NOT NULL,
            agent_id     TEXT NOT NULL,
            agent_role   TEXT NOT NULL,
            session_id   TEXT NOT NULL,
            tool_name    TEXT NOT NULL,
            args         TEXT NOT NULL,
            result       TEXT,
            allowed      INTEGER NOT NULL,
            risk_score   REAL NOT NULL,
            label        TEXT NOT NULL,
            ttp_id       TEXT,
            ttp_name     TEXT,
            ledger_hash  TEXT NOT NULL,
            latency_ms   REAL
        );
        CREATE TABLE IF NOT EXISTS agent_sessions (
            session_id       TEXT PRIMARY KEY,
            agent_id         TEXT NOT NULL,
            agent_role       TEXT NOT NULL,
            started_at       TEXT NOT NULL,
            last_seen        TEXT NOT NULL,
            cumulative_risk  REAL DEFAULT 0,
            call_count       INTEGER DEFAULT 0,
            blocked_count    INTEGER DEFAULT 0,
            current_status   TEXT DEFAULT 'normal'
        );
        CREATE TABLE IF NOT EXISTS ledger (
            seq         INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id    TEXT NOT NULL,
            prev_hash   TEXT NOT NULL,
            curr_hash   TEXT NOT NULL,
            timestamp   TEXT NOT NULL
        );
    """)
    con.commit()
    con.close()

init_db()

# SHA-256 audit ledger
def _get_prev_hash() -> str:
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT curr_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
    con.close()
    return row[0] if row else "0" * 64

def _append_ledger(event_id: str, event_data: dict) -> str:
    prev_hash = _get_prev_hash()
    payload   = json.dumps(event_data, sort_keys=True, default=str)
    curr_hash = hashlib.sha256(f"{prev_hash}{payload}".encode()).hexdigest()
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT INTO ledger (event_id, prev_hash, curr_hash, timestamp) VALUES (?,?,?,?)",
        (event_id, prev_hash, curr_hash, datetime.utcnow().isoformat())
    )
    con.commit()
    con.close()
    return curr_hash

# Risk scoring
def _compute_risk(agent_role: str, tool_name: str, allowed: bool,
                  session_call_count: int, session_blocked: int) -> tuple[float, str]:
    role     = AGENT_ROLES.get(agent_role)
    base     = TOOL_SENSITIVITY.get(tool_name, 3)
    score    = float(base * 5)                        # 0-50 base

    if not allowed:
        score += 40                                   # big penalty for violations
    if tool_name not in (role.allowed_tools if role else []):
        score += 30
    score += min(session_blocked * 10, 30)            # escalating penalty per block
    score += min(session_call_count * 0.5, 10)        # volume heuristic
    score  = min(score, 100.0)

    # MITRE ATLAS TTP mapping
    ttp = None
    if not allowed and tool_name in ("execute_command", "modify_permissions"):
        ttp = "privilege_escalation"
    elif not allowed and tool_name == "send_email":
        ttp = "privilege_escalation"  # AML.T0006 LLM Prompt Injection: unauthorized outbound email is a classic injection payoff
    elif not allowed and tool_name in ("read_file", "query_db") and "private" in str(tool_name):
        ttp = "data_exfiltration"
    elif not allowed:
        ttp = "permission_violation"
    elif tool_name == "call_api" and agent_role == "reader":
        ttp = "lateral_movement"

    return score, ttp

# Permission check
def _is_allowed(agent_role: str, tool_name: str) -> bool:
    role = AGENT_ROLES.get(agent_role)
    if not role:
        return False
    return tool_name in role.allowed_tools

# Session management
def _upsert_session(session_id: str, agent_id: str, agent_role: str,
                    risk_delta: float, blocked: bool):
    now = datetime.utcnow().isoformat()
    con = sqlite3.connect(DB_PATH)
    row = con.execute(
        "SELECT cumulative_risk, call_count, blocked_count FROM agent_sessions WHERE session_id=?",
        (session_id,)
    ).fetchone()
    if row:
        new_risk    = min(row[0] + risk_delta * 0.3, 100.0)
        new_calls   = row[1] + 1
        new_blocked = row[2] + (1 if blocked else 0)
        status      = "critical" if new_risk > 80 else "warning" if new_risk > RISK_THRESHOLD else "normal"
        con.execute("""
            UPDATE agent_sessions
            SET last_seen=?, cumulative_risk=?, call_count=?, blocked_count=?, current_status=?
            WHERE session_id=?
        """, (now, new_risk, new_calls, new_blocked, status, session_id))
    else:
        con.execute("""
            INSERT INTO agent_sessions
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (session_id, agent_id, agent_role, now, now, risk_delta * 0.3, 1, 1 if blocked else 0, "normal"))
    con.commit()
    con.close()

# Core intercept function
def intercept(agent_id: str, agent_role: str, session_id: str,
              tool_name: str, tool_args: dict,
              label: str = "benign") -> dict[str, Any]:
    """
    Central interception point for every tool call.
    Returns the tool result plus metadata.
    """
    t_start  = time.time()
    event_id = str(uuid.uuid4())
    now      = datetime.utcnow().isoformat()

    # Check permission
    allowed = _is_allowed(agent_role, tool_name)

    # Get session context for risk scoring
    con = sqlite3.connect(DB_PATH)
    sess = con.execute(
        "SELECT call_count, blocked_count FROM agent_sessions WHERE session_id=?",
        (session_id,)
    ).fetchone()
    con.close()
    call_count   = sess[0] if sess else 0
    blocked_count = sess[1] if sess else 0

    # Compute risk
    risk_score, ttp = _compute_risk(agent_role, tool_name, allowed, call_count, blocked_count)

    # Execute tool (or block) — allowed calls run inside the subprocess sandbox
    sandbox_meta = None
    if allowed:
        tool_fn = TOOL_REGISTRY.get(tool_name)
        if tool_fn:
            try:
                result = get_sandbox().run(tool_name, tool_fn, tool_args)
                sandbox_meta = result.pop("sandbox", None) if isinstance(result, dict) else None
            except SandboxViolation as sv:
                result = {"error": f"Sandbox violation: {sv.reason}", "sandboxed": True}
                allowed = False
        else:
            result = {"error": f"Unknown tool: {tool_name}"}
    else:
        result = {"blocked": True, "reason": f"Agent '{agent_role}' not permitted to call '{tool_name}'"}

    latency_ms = (time.time() - t_start) * 1000

    # TTP details
    ttp_info = MITRE_ATLAS_TTPS.get(ttp, {}) if ttp else {}

    # Build event
    event = {
        "id": event_id,
        "timestamp": now,
        "agent_id": agent_id,
        "agent_role": agent_role,
        "session_id": session_id,
        "tool_name": tool_name,
        "args": json.dumps(tool_args),
        "result": json.dumps(result, default=str),
        "allowed": int(allowed),
        "risk_score": risk_score,
        "label": label,
        "ttp_id": ttp_info.get("id"),
        "ttp_name": ttp_info.get("name"),
        "latency_ms": latency_ms,
        "sandbox_enforced": int(sandbox_meta is not None),
    }

    # Append to tamper-evident ledger
    ledger_hash = _append_ledger(event_id, event)
    event["ledger_hash"] = ledger_hash

    # Persist event
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        INSERT INTO tool_calls VALUES
        (:id,:timestamp,:agent_id,:agent_role,:session_id,:tool_name,:args,
         :result,:allowed,:risk_score,:label,:ttp_id,:ttp_name,:ledger_hash,:latency_ms)
    """, event)
    con.commit()
    con.close()

    # Update session
    _upsert_session(session_id, agent_id, agent_role, risk_score, not allowed)

    return {
        "event_id": event_id,
        "allowed": allowed,
        "result": result,
        "risk_score": risk_score,
        "ttp": ttp_info or None,
        "blocked": not allowed,
        "latency_ms": latency_ms,
        "ledger_hash": ledger_hash,
    }
