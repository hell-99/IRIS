"""
Direct SQLite access layer for Streamlit Community Cloud deployment.

When DIRECT_DB=true, the dashboard skips FastAPI entirely and queries
the SQLite database directly. The demo_data/agentguard.db file is
committed to the repo and serves as the seed dataset.

Every function here returns the same dict structure that the corresponding
FastAPI endpoint returns, so app.py requires minimal changes.
"""
import json
import os
import pathlib
import sqlite3
from datetime import datetime

_HERE = pathlib.Path(__file__).parent  # agentguard/dashboard/


def _db_path():
    env = os.getenv("DB_PATH")
    if env:
        return env
    # Default: agentguard/demo_data/agentguard.db regardless of CWD
    return str(_HERE.parent / "demo_data" / "agentguard.db")


def _connect():
    path = _db_path()
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    return con


def _row_to_dict(row):
    return dict(row)


def _risk_to_threat(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


def get_metrics():
    con = _connect()
    try:
        total = con.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
        blocked = con.execute("SELECT COUNT(*) FROM tool_calls WHERE allowed=0").fetchone()[0]
        sessions = con.execute("SELECT COUNT(*) FROM agent_sessions").fetchone()[0]
        malicious = con.execute("SELECT COUNT(*) FROM tool_calls WHERE label='malicious'").fetchone()[0]
        benign = con.execute("SELECT COUNT(*) FROM tool_calls WHERE label='benign'").fetchone()[0]
        avg_latency = con.execute("SELECT AVG(latency_ms) FROM tool_calls").fetchone()[0] or 0
        max_latency = con.execute("SELECT MAX(latency_ms) FROM tool_calls").fetchone()[0] or 0

        try:
            suspicious_div = con.execute(
                "SELECT COUNT(*) FROM divergence_analysis WHERE verdict='SUSPICIOUS'"
            ).fetchone()[0]
            total_div = con.execute("SELECT COUNT(*) FROM divergence_analysis").fetchone()[0]
        except Exception:
            suspicious_div = 0
            total_div = 0

        try: collusion_count = con.execute("SELECT COUNT(*) FROM collusion_detections").fetchone()[0]
        except Exception:
            collusion_count = 0

        try:
            ttps = con.execute("""
                SELECT ttp_name, COUNT(*) as count
                FROM tool_calls
                WHERE ttp_name IS NOT NULL AND ttp_name != ' - '
                GROUP BY ttp_name
                ORDER BY count DESC
            """).fetchall()
        except Exception:
            ttps = []

        block_rate = (blocked / total * 100) if total > 0 else 0
        detection_rate = (suspicious_div / total_div * 100) if total_div > 0 else 0

        return {
            "total_events": total,
            "blocked_events": blocked,
            "block_rate_pct": round(block_rate, 2),
            "malicious_events": malicious,
            "benign_events": benign,
            "active_sessions": sessions,
            "divergence_analyses": total_div,
            "suspicious_divergences": suspicious_div,
            "detection_rate_pct": round(detection_rate, 2),
            "collusion_detections": collusion_count,
            "avg_detection_latency_ms": round(avg_latency, 3),
            "max_detection_latency_ms": round(max_latency, 3),
            "ttp_breakdown": {t[0]: t[1] for t in ttps},
            "timestamp": datetime.utcnow().isoformat(),
        }
    finally: con.close()


def get_sessions(status=None, role=None, limit=50):
    con = _connect()
    try:
        query = "SELECT * FROM agent_sessions WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if role:
            query += " AND agent_role = ?"
            params.append(role)
        query += " ORDER BY cumulative_risk DESC LIMIT ?"
        params.append(limit)

        rows = [_row_to_dict(r) for r in con.execute(query, params).fetchall()]
        return {"sessions": rows, "count": len(rows), "filters": {"status": status, "role": role}}
    finally: con.close()


def get_session_detail(session_id):
    con = _connect()
    try:
        session = con.execute("SELECT * FROM agent_sessions WHERE session_id = ?", (session_id,)).fetchone()
        if not session:
            return None
        session_dict = _row_to_dict(session)

        calls = [_row_to_dict(r) for r in con.execute("""
            SELECT tool_name, args, allowed, risk_score,
                   label, ttp_name, ttp_id, latency_ms, timestamp
            FROM tool_calls WHERE session_id = ?
            ORDER BY timestamp ASC
        """, (session_id,)).fetchall()]

        return {"session": session_dict, "tool_calls": calls, "call_count": len(calls)}
    finally: con.close()


def get_detections(verdict=None, limit=50):
    con = _connect()
    try:
        query = "SELECT * FROM divergence_analysis WHERE 1=1"
        params = []
        if verdict:
            query += " AND verdict = ?"
            params.append(verdict)
        query += " ORDER BY divergence_score DESC LIMIT ?"
        params.append(limit)

        try: rows = [_row_to_dict(r) for r in con.execute(query, params).fetchall()]
        except Exception:
            rows = []

        for r in rows:
            for field in ("expected_tools", "actual_tools", "unexpected_tools"):
                if field in r and isinstance(r[field], str):
                    try: r[field] = json.loads(r[field])
                    except Exception:
                        pass

        return {
            "detections": rows,
            "count": len(rows),
            "suspicious": sum(1 for r in rows if r.get("verdict") == "SUSPICIOUS"),
        }
    finally: con.close()


def get_collusion(severity=None, limit=50):
    con = _connect()
    try:
        query = "SELECT * FROM collusion_detections WHERE 1=1"
        params = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)

        try: rows = [_row_to_dict(r) for r in con.execute(query, params).fetchall()]
        except Exception:
            rows = []

        return {
            "detections": rows,
            "count": len(rows),
            "critical": sum(1 for r in rows if r.get("severity") == "CRITICAL"),
            "high": sum(1 for r in rows if r.get("severity") == "HIGH"),
        }
    finally: con.close()


def get_graphs(limit=20):
    con = _connect()
    try:
        rows = [_row_to_dict(r) for r in con.execute("""
            SELECT
                s.session_id, s.agent_id, s.agent_role,
                s.cumulative_risk, s.call_count, s.blocked_count,
                COUNT(t.id) as total_calls,
                SUM(CASE WHEN t.allowed=0 THEN 1 ELSE 0 END) as blocked,
                MAX(t.risk_score) as max_risk
            FROM agent_sessions s
            LEFT JOIN tool_calls t ON s.session_id = t.session_id
            GROUP BY s.session_id
            ORDER BY max_risk DESC
            LIMIT ?
        """, (limit,)).fetchall()]

        for r in rows:
            r["threat_level"] = _risk_to_threat(r.get("max_risk") or 0)

        return {"graphs": rows, "count": len(rows)}
    finally: con.close()


def get_graph_detail(session_id):
    con = _connect()
    try:
        calls = [_row_to_dict(r) for r in con.execute("""
            SELECT
                t.agent_id, t.agent_role, t.tool_name,
                t.args, t.allowed, t.risk_score,
                t.ttp_name, t.ttp_id, t.label, t.timestamp
            FROM tool_calls t
            WHERE t.session_id = ?
            ORDER BY t.timestamp ASC
        """, (session_id,)).fetchall()]

        if not calls:
            return None

        nodes = []
        edges = []
        seen = set()

        agent_node = f"agent_{calls[0]['agent_id'][:8]}"
        nodes.append({"id": agent_node, "type": "agent", "label": f"{calls[0]['agent_role']} agent", "risk": 0})

        for call in calls:
            tool_node = f"tool_{call['tool_name']}_{str(call['timestamp'])[:19]}"
            resource_node = f"resource_{str(call['args'])[:20]}"

            if tool_node not in seen:
                nodes.append({
                    "id": tool_node, "type": "tool", "label": call["tool_name"],
                    "allowed": bool(call["allowed"]), "risk": call["risk_score"],
                    "ttp": call.get("ttp_name"),
                })
                seen.add(tool_node)

            edges.append({
                "from": agent_node, "to": tool_node,
                "action": "calls" if call["allowed"] else "attempts",
                "blocked": not bool(call["allowed"]), "risk": call["risk_score"],
            })

            if resource_node not in seen and call["args"]:
                nodes.append({
                    "id": resource_node, "type": "resource",
                    "label": str(call["args"])[:30], "risk": call["risk_score"],
                })
                seen.add(resource_node)
                edges.append({
                    "from": tool_node, "to": resource_node,
                    "action": "blocked" if not call["allowed"] else "accesses",
                    "risk": call["risk_score"],
                })

        max_risk = max((c["risk_score"] for c in calls), default=0)
        return {
            "session_id": session_id,
            "agent_role": calls[0]["agent_role"],
            "threat_level": _risk_to_threat(max_risk),
            "max_risk": max_risk,
            "total_calls": len(calls),
            "blocked_calls": sum(1 for c in calls if not c["allowed"]),
            "nodes": nodes,
            "edges": edges,
            "kill_chain": calls,
        }
    finally: con.close()


def get_events(limit=100, blocked_only=False, role=None):
    con = _connect()
    try:
        query = """
            SELECT agent_id, agent_role, session_id, tool_name,
                   args, allowed, risk_score, label,
                   ttp_name, ttp_id, latency_ms, timestamp
            FROM tool_calls WHERE 1=1
        """
        params = []
        if blocked_only:
            query += " AND allowed = 0"
        if role:
            query += " AND agent_role = ?"
            params.append(role)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = [_row_to_dict(r) for r in con.execute(query, params).fetchall()]
        return {"events": rows, "count": len(rows)}
    finally: con.close()
