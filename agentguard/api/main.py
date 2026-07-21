"""
IRIS: Day 4: FastAPI Risk Score API

Exposes all IRIS detection data as a real REST API.
Any dashboard, SIEM, or monitoring tool can consume this.

Endpoints: GET  /                           -  health check
    GET  /api/status                 -  system overview
    GET  /api/risk/{agent_id}        -  live risk score for an agent
    GET  /api/sessions               -  all active sessions
    GET  /api/sessions/{session_id}  -  single session detail
    GET  /api/detections             -  all divergence analyses
    GET  /api/collusion              -  all collusion detections
    GET  /api/graphs                 -  all attack graph summaries
    GET  /api/graphs/{session_id}    -  full attack graph for a session
    GET  /api/events                 -  recent tool call events
    GET  /api/metrics                -  detection metrics summary
    WS   /ws/live                    -  real-time event streaming
"""
import sys
import os
import json
import sqlite3
import asyncio
import pathlib
import time
from datetime import datetime
from typing import Optional

_root=pathlib.Path(__file__).parent.parent
sys.path.insert(0,str(_root))

from dotenv import load_dotenv
load_dotenv(_root / ".env")

from fastapi import FastAPI, HTTPException,WebSocket, WebSocketDisconnect, Query, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from config import DB_PATH,RISK_THRESHOLD

app = FastAPI(
    title="IRIS: Agentic Identity Risk Intelligence System",
    description=(
        "Real-time security monitoring API for LLM agent systems. "
        "Detects prompt injection, privilege escalation, data exfiltration, "
        "and cross agent collusion using behavioral ML + intent action divergence."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Prometheus metrics ──────────────────────────────────────────────────────
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response

Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

iris_tool_calls_total = Gauge("iris_tool_calls_total", "Total tool calls processed")
iris_tool_calls_blocked = Gauge("iris_tool_calls_blocked", "Tool calls blocked by policy")
iris_sessions_total = Gauge("iris_sessions_total", "Total agent sessions")
iris_detections_suspicious = Gauge("iris_detections_suspicious", "Suspicious intent-action divergences detected")
iris_avg_latency_ms = Gauge("iris_avg_latency_ms", "Average tool-call interception latency in milliseconds")
iris_yara_scan_latency_ms = Histogram(
    "iris_yara_scan_latency_ms",
    "Real per-request YARA scan duration in milliseconds (time.perf_counter around rules.match)",
    buckets=(0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000),
)


# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active:list[WebSocket]=[]

    async def connect(self, ws:WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws:WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self,data:dict):
        dead=[]
        for ws in self.active:
            try: await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager =ConnectionManager()


# DB helper 
def get_db(db_path:str = None):
    """Getting database connection. It uses user-specific DB if path provided."""
    path=db_path or DB_PATH
    db =pathlib.Path(path)
    if not db.exists():
        # For new users, it create an empty database
        db.parent.mkdir(parents=True,exist_ok=True)
        con=sqlite3.connect(str(path))
        con.execute("""
            CREATE TABLE IF NOT EXISTS tool_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT, agent_role TEXT, session_id TEXT,
                tool_name TEXT, args TEXT, allowed INTEGER,
                risk_score REAL, label TEXT, latency_ms REAL,
                timestamp TEXT DEFAULT (datetime('now'))
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS agent_sessions (
                session_id TEXT PRIMARY KEY,
                agent_id TEXT, agent_role TEXT,
                call_count INTEGER DEFAULT 0,
                blocked_count INTEGER DEFAULT 0,
                cumulative_risk REAL DEFAULT 0
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS divergence_analysis (
                session_id TEXT, task TEXT, agent_role TEXT,
                expected_tools TEXT, actual_tools TEXT,
                divergence_score REAL, verdict TEXT,
                timestamp TEXT DEFAULT (datetime('now'))
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS collusion_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT, severity TEXT,
                agent1_role TEXT, agent2_role TEXT,
                detected_at TEXT DEFAULT (datetime('now'))
            )
        """)
        con.commit()
        return con
    return sqlite3.connect(str(path))


def get_db_for_request(authorization: str = Header(None)):
    """FastAPI dependency: it returns DB connection for current user."""
    if authorization:
        token = authorization.replace("Bearer ", "").strip()
        payload = verify_token(token)
        if payload:
            user_id= payload.get("user_id")
            db_path= get_db_path_for_user(user_id)
            return get_db(db_path)
    return get_db()


def row_to_dict(cursor, row):
    return {col[0]:val for col,val in zip(cursor.description, row)}


@app.get("/metrics/iris", include_in_schema=False)
def iris_metrics(db=Depends(get_db_for_request)):
    """Domain-specific security metrics, same queries as /api/metrics, in Prometheus text format."""
    con = db
    iris_tool_calls_total.set(con.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0])
    iris_tool_calls_blocked.set(con.execute("SELECT COUNT(*) FROM tool_calls WHERE allowed=0").fetchone()[0])
    iris_sessions_total.set(con.execute("SELECT COUNT(*) FROM agent_sessions").fetchone()[0])
    try:
        iris_detections_suspicious.set(
            con.execute("SELECT COUNT(*) FROM divergence_analysis WHERE verdict='SUSPICIOUS'").fetchone()[0]
        )
    except Exception:
        pass
    iris_avg_latency_ms.set(con.execute("SELECT AVG(latency_ms) FROM tool_calls").fetchone()[0] or 0)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# Root/health
@app.get("/",tags=["Health"])
def root():
    return {
        "name":"IRIS  -  Agentic Identity Risk Intelligence System",
        "version":"1.0.0",
        "status":"operational",
        "docs": "/docs",
    }


@app.get("/api/status", tags=["Health"])
def status(db=Depends(get_db_for_request)):
    """System overview:total events, active threats, model info."""
    try:
        con=db
        total= con.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
        blocked=con.execute("SELECT COUNT(*) FROM tool_calls WHERE allowed=0").fetchone()[0]
        sessions=con.execute("SELECT COUNT(*) FROM agent_sessions").fetchone()[0]

        try:
            critical = con.execute("""
                SELECT COUNT(*) FROM agent_sessions WHERE status='critical'
            """).fetchone()[0]
        except Exception:
            critical = 0

        try:
            collusion = con.execute(
                "SELECT COUNT(*) FROM collusion_detections"
            ).fetchone()[0]
        except Exception:
            collusion = 0

        try:
            divergence = con.execute(
                "SELECT COUNT(*) FROM divergence_analysis WHERE verdict='SUSPICIOUS'"
            ).fetchone()[0]
        except Exception:
            divergence = 0

        con.close()
        return {
            "total_tool_calls":total,
            "blocked_calls":blocked,
            "active_sessions":sessions,
            "critical_sessions":critical,
            "collusion_detections":collusion,
            "suspicious_divergences": divergence,
            "risk_threshold": RISK_THRESHOLD,
            "timestamp":datetime.utcnow().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500,detail=str(e))


# gives risk score for a specific agent
@app.get("/api/risk/{agent_id}",tags=["Risk"])
def get_agent_risk(agent_id: str,db=Depends(get_db_for_request)):
    """
    Live risk score for a specific agent.
    It returns current status,cumulative risk,blocked calls, and recent TTPs.
    """
    try:
        con = db

        session = con.execute("""
            SELECT session_id, agent_role, cumulative_risk,
                   call_count, blocked_count, status
            FROM agent_sessions
            WHERE agent_id = ?
            ORDER BY rowid DESC LIMIT 1
        """, (agent_id,)).fetchone()

        if not session:
            con.close()
            raise HTTPException(
                status_code= 404,
                detail=f"Agent '{agent_id}' not found"
            )

        session_id = session[0]

        recent= con.execute("""
            SELECT tool_name, allowed,risk_score, ttp_name, timestamp
            FROM tool_calls
            WHERE agent_id=?
            ORDER BY timestamp DESC LIMIT 10
        """, (agent_id,)).fetchall()

        # Get TTPs triggered
        ttps=con.execute("""
            SELECT DISTINCT ttp_name FROM tool_calls
            WHERE agent_id =? AND ttp_name IS NOT NULL AND ttp_name != ' - '
        """, (agent_id,)).fetchall()

        con.close()

        risk_score=session[2] or 0
        status_val= session[5] or "normal"

        return {
            "agent_id":agent_id,
            "session_id":session_id,
            "agent_role":session[1],
            "risk_score":round(risk_score, 2),
            "status":status_val,
            "call_count":session[3],
            "blocked_count":session[4],
            "threat_level":_risk_to_threat(risk_score),
            "ttps_triggered":[t[0] for t in ttps if t[0]],
            "recent_calls":[
                {
                    "tool":r[0],
                    "allowed":bool(r[1]),
                    "risk":r[2],
                    "ttp":r[3],
                    "timestamp":r[4],
                }
                for r in recent
            ],
            "timestamp":datetime.utcnow().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# All sessions
@app.get("/api/sessions", tags=["Sessions"])
def get_sessions(
    status:Optional[str] = Query(None,description="Filter: normal/warning/critical"),
    role:Optional[str] = Query(None,description="Filter:admin/analyst/reader"),
    limit:int= Query(50,description="Max results"),
    db=Depends(get_db_for_request),
):
    """All active agent sessions with risk profiles."""
    try:
        con=db
        query="SELECT * FROM agent_sessions WHERE 1=1"
        params = []

        if status:
            query +="AND status = ?"
            params.append(status)
        if role:
            query +="AND agent_role = ?"
            params.append(role)

        query +="ORDER BY cumulative_risk DESC LIMIT ?"
        params.append(limit)

        cur=con.execute(query, params)
        rows=[row_to_dict(cur, r) for r in cur.fetchall()]
        con.close()

        return {
            "sessions":rows,
            "count":len(rows),
            "filters":{"status": status, "role": role},
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sessions/{session_id}",tags=["Sessions"])
def get_session_detail(session_id:str, db=Depends(get_db_for_request)):
    """Full detail for a single session including all tool calls."""
    try:
        con = db
        session = con.execute("""
            SELECT * FROM agent_sessions WHERE session_id = ?
        """, (session_id,)).fetchone()

        if not session:
            con.close()
            raise HTTPException(status_code=404, detail="Session not found")

        cur = con.execute("""
            SELECT * FROM agent_sessions WHERE session_id = ?
        """, (session_id,))
        session_dict = row_to_dict(cur, session)

        # All tool calls for this session
        cur2  = con.execute("""
            SELECT tool_name, args, allowed, risk_score,
                   label, ttp_name, ttp_id, latency_ms, timestamp
            FROM tool_calls WHERE session_id = ?
            ORDER BY timestamp ASC
        """, (session_id,))
        calls=[row_to_dict(cur2, r) for r in cur2.fetchall()]

        con.close()
        return {
            "session": session_dict,
            "tool_calls": calls,
            "call_count": len(calls),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Divergence analyses
@app.get("/api/detections", tags=["Detections"])
def get_detections(
    verdict: Optional[str] = Query(None, description="Filter: SUSPICIOUS/NORMAL"),
    limit:int= Query(50),
    db=Depends(get_db_for_request),
):
    """All intent action divergence analyses."""
    try:
        con = db
        try:
            query  = "SELECT * FROM divergence_analysis WHERE 1=1"
            params = []
            if verdict:
                query += " AND verdict = ?"
                params.append(verdict)
            query += " ORDER BY divergence_score DESC LIMIT ?"
            params.append(limit)

            cur = con.execute(query, params)
            rows=[row_to_dict(cur, r) for r in cur.fetchall()]
        except Exception:
            rows = []
        con.close()

        for r in rows:
            for field in ["expected_tools", "actual_tools", "unexpected_tools"]:
                if field in r and isinstance(r[field], str):
                    try: r[field] = json.loads(r[field])
                    except Exception:
                        pass

        return {
            "detections":rows,
            "count":len(rows),
            "suspicious": sum(1 for r in rows if r.get("verdict")== "SUSPICIOUS"),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Collusion detections :(
@app.get("/api/collusion", tags=["Detections"])
def get_collusion(
    severity: Optional[str]= Query(None, description="Filter:CRITICAL/HIGH/MEDIUM"),
    limit:int= Query(50),
    db=Depends(get_db_for_request),
):
    """All cross-agent collusion detections."""
    try:
        con = db
        try:
            query= "SELECT * FROM collusion_detections WHERE 1=1"
            params=[]
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            query += " ORDER BY detected_at DESC LIMIT ?"
            params.append(limit)

            cur=con.execute(query, params)
            rows=[row_to_dict(cur, r) for r in cur.fetchall()]
        except Exception:
            rows = []
        con.close()

        return {
            "detections": rows,
            "count":len(rows),
            "critical":sum(1 for r in rows if r.get("severity")=="CRITICAL"),
            "high":sum(1 for r in rows if r.get("severity")=="HIGH"),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Attack graphs :)
@app.get("/api/graphs", tags=["Attack Graphs"])
def get_graphs(limit:int = Query(20), db=Depends(get_db_for_request)):
    """Summary of all attack graphs built."""
    try:
        con = db

        cur = con.execute("""
            SELECT
                s.session_id,
                s.agent_id,
                s.agent_role,
                s.cumulative_risk,
                s.call_count,
                s.blocked_count,
                COUNT(t.id) as total_calls,
                SUM(CASE WHEN t.allowed=0 THEN 1 ELSE 0 END) as blocked,
                MAX(t.risk_score) as max_risk
            FROM agent_sessions s
            LEFT JOIN tool_calls t ON s.session_id = t.session_id
            GROUP BY s.session_id
            ORDER BY max_risk DESC
            LIMIT ?
        """, (limit,))

        rows = [row_to_dict(cur, r) for r in cur.fetchall()]
        con.close()

        for r in rows:
            r["threat_level"] = _risk_to_threat(r.get("max_risk") or 0)

        return {"graphs":rows, "count":len(rows)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500,detail=str(e))


@app.get("/api/graphs/{session_id}",tags=["Attack Graphs"])
def get_graph_detail(session_id: str, db=Depends(get_db_for_request)):
    """Full attack graph kill chain for a specific session."""
    try:
        con = db
        cur = con.execute("""
            SELECT
                t.agent_id, t.agent_role, t.tool_name,
                t.args, t.allowed, t.risk_score,
                t.ttp_name, t.ttp_id, t.label, t.timestamp
            FROM tool_calls t
            WHERE t.session_id = ?
            ORDER BY t.timestamp ASC
        """, (session_id,))

        calls = [row_to_dict(cur, r) for r in cur.fetchall()]
        if not calls:
            con.close()
            raise HTTPException(status_code=404, detail="Session not found")

        nodes = []
        edges = []
        seen= set()

        agent_node = f"agent_{calls[0]['agent_id'][:8]}"
        nodes.append({
            "id":agent_node,
            "type":"agent",
            "label":f"{calls[0]['agent_role']} agent",
            "risk":0,
        })

        for call in calls:
            tool_node= f"tool_{call['tool_name']}_{call['timestamp'][:19]}"
            resource_node=f"resource_{str(call['args'])[:20]}"

            if tool_node not in seen:
                nodes.append({
                    "id":tool_node,
                    "type":"tool",
                    "label":call["tool_name"],
                    "allowed":bool(call["allowed"]),
                    "risk":call["risk_score"],
                    "ttp":call.get("ttp_name"),
                })
                seen.add(tool_node)

            edges.append({
                "from":agent_node,
                "to":tool_node,
                "action":"calls" if call["allowed"] else "attempts",
                "blocked":not bool(call["allowed"]),
                "risk":call["risk_score"],
            })

            if resource_node not in seen and call["args"]:
                nodes.append({
                    "id":resource_node,
                    "type":"resource",
                    "label":str(call["args"])[:30],
                    "risk":call["risk_score"],
                })
                seen.add(resource_node)

                edges.append({
                    "from":tool_node,
                    "to":resource_node,
                    "action":"blocked" if not call["allowed"] else "accesses",
                    "risk":call["risk_score"],
                })

        con.close()

        max_risk= max((c["risk_score"] for c in calls), default=0)
        threat_level=_risk_to_threat(max_risk)

        return {
            "session_id":session_id,
            "agent_role":calls[0]["agent_role"],
            "threat_level": threat_level,
            "max_risk":max_risk,
            "total_calls":len(calls),
            "blocked_calls":sum(1 for c in calls if not c["allowed"]),
            "nodes":nodes,
            "edges":edges,
            "kill_chain":calls,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Recent events
@app.get("/api/events", tags=["Events"])
def get_events(
    limit:int= Query(100),
    blocked_only: bool = Query(False),
    role:Optional[str] = Query(None),
    db=Depends(get_db_for_request),
):
    """Recent tool call events: the raw event stream."""
    try:
        con=get_db()
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

        query +=" ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cur=con.execute(query, params)
        rows=[row_to_dict(cur, r) for r in cur.fetchall()]
        con.close()

        return {
            "events": rows,
            "count":len(rows),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Detection metrics
@app.get("/api/metrics", tags=["Metrics"])
def get_metrics(db=Depends(get_db_for_request)):
    """
    Detection performance metrics.
    These are the numbers that go on your resume.
    """
    try:
        con = db
        total = con.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
        blocked = con.execute("SELECT COUNT(*) FROM tool_calls WHERE allowed=0").fetchone()[0]
        sessions = con.execute("SELECT COUNT(*) FROM agent_sessions").fetchone()[0]

        malicious = con.execute(
            "SELECT COUNT(*) FROM tool_calls WHERE label='malicious'"
        ).fetchone()[0]
        benign = con.execute(
            "SELECT COUNT(*) FROM tool_calls WHERE label='benign'"
        ).fetchone()[0]

        avg_latency = con.execute(
            "SELECT AVG(latency_ms) FROM tool_calls"
        ).fetchone()[0] or 0

        max_latency = con.execute(
            "SELECT MAX(latency_ms) FROM tool_calls"
        ).fetchone()[0] or 0

        try:
            suspicious_div = con.execute(
                "SELECT COUNT(*) FROM divergence_analysis WHERE verdict='SUSPICIOUS'"
            ).fetchone()[0]
            total_div = con.execute(
                "SELECT COUNT(*) FROM divergence_analysis"
            ).fetchone()[0]
        except Exception:
            suspicious_div = 0
            total_div= 0
        try:
            collusion_count = con.execute(
                "SELECT COUNT(*) FROM collusion_detections"
            ).fetchone()[0]
        except Exception:
            collusion_count = 0

        # TTP breakdown
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

        con.close()

        block_rate = (blocked / total * 100) if total > 0 else 0
        detection_rate = (suspicious_div / total_div * 100) if total_div > 0 else 0

        return {
            "total_events":total,
            "blocked_events":blocked,
            "block_rate_pct":round(block_rate, 2),
            "malicious_events":malicious,
            "benign_events":benign,
            "active_sessions":sessions,
            "divergence_analyses":total_div,
            "suspicious_divergences":suspicious_div,
            "detection_rate_pct":round(detection_rate, 2),
            "collusion_detections":collusion_count,
            "avg_detection_latency_ms":round(avg_latency, 3),
            "max_detection_latency_ms":round(max_latency, 3),
            "ttp_breakdown": {t[0]: t[1] for t in ttps},
            "timestamp": datetime.utcnow().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# WebSocket live stream 
@app.websocket("/ws/live")
async def websocket_live(ws:WebSocket):
    """
    Real-time event stream.
    Sends new tool call events as they are logged to the DB.
    Connect with: ws://localhost:8000/ws/live
    """
    await manager.connect(ws)
    last_id = 0

    try:
        # Send initial state
        await ws.send_json({
            "type":"connected",
            "message": "IRIS live stream connected",
            "timestamp": datetime.utcnow().isoformat(),
        })

        while True:
            try:
                con = sqlite3.connect(DB_PATH)
                cur = con.execute("""
                    SELECT id, agent_id, agent_role, tool_name,
                           allowed, risk_score, ttp_name, label, timestamp
                    FROM tool_calls
                    WHERE id > ?
                    ORDER BY id ASC
                    LIMIT 10
                """, (last_id,))
                rows = cur.fetchall()
                con.close()

                for row in rows:
                    last_id = row[0]
                    event   = {
                        "type":"tool_call",
                        "id":row[0],
                        "agent_id":row[1],
                        "role":row[2],
                        "tool":row[3],
                        "allowed":bool(row[4]),
                        "risk":row[5],
                        "ttp":row[6],
                        "label":row[7],
                        "timestamp":row[8],
                        "threat":_risk_to_threat(row[5] or 0),
                    }
                    await ws.send_json(event)

            except Exception:
                pass

            await asyncio.sleep(0.5)

    except WebSocketDisconnect:
        manager.disconnect(ws)


# Helper
def _risk_to_threat(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


# AUTH SYSTEM: Added for multi-tenant SaaS

from fastapi import Depends, Header
from auth.models import init_auth_db, create_user, verify_user, get_user, get_db_path_for_user
from auth.jwt import create_token, verify_token, get_user_id_from_token

init_auth_db()


#Auth request/response models
class RegisterRequest(BaseModel):
    email:str
    name:str
    password:str

class LoginRequest(BaseModel):
    email: str
    password:str

class AuthResponse(BaseModel):
    token:str
    user_id: str
    email:str
    name:str
    is_demo:bool
    plan:str


# Auth dependency
def get_current_user(authorization:str = Header(None)) -> dict:
    """Extract and verify user from Authorization header."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")

    # Accept "Bearer <token>" or just "<token>"
    token = authorization.replace("Bearer ", "").strip()
    payload = verify_token(token)

    if not payload:
        raise HTTPException(status_code=401,detail="Invalid or expired token")

    user = get_user(payload["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


def get_user_db(user:dict = Depends(get_current_user)) -> str:
    """Get the database path for the current user."""
    return get_db_path_for_user(user["user_id"])


# Auth endpoints
@app.post("/auth/register",response_model=AuthResponse,tags=["Authentication"])
def register(req: RegisterRequest):
    """Registering a new user account."""
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if "@" not in req.email:
        raise HTTPException(status_code=400, detail="Invalid email address")

    try:
        user = create_user(req.email, req.name, req.password)
        token = create_token(user["user_id"], user["email"])
        return AuthResponse(
            token=token,
            user_id=user["user_id"],
            email=user["email"],
            name=user["name"],
            is_demo=False,
            plan="free",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/auth/login", response_model=AuthResponse, tags=["Authentication"])
def login(req: LoginRequest):
    """Login with email and password."""
    user = verify_user(req.email, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_token(user["user_id"], user["email"])
    return AuthResponse(
        token=token,
        user_id=user["user_id"],
        email=user["email"],
        name=user["name"],
        is_demo=user["is_demo"],
        plan=user["plan"],
    )

@app.get("/auth/me", tags=["Authentication"])
def me(user: dict = Depends(get_current_user)):
    """Getting current user info."""
    return user


# User-scoped metrics endpoint
@app.get("/api/user/metrics", tags=["User Data"])
def user_metrics(
    user:dict = Depends(get_current_user),
    db_path:str= Depends(get_user_db),
):
    """Getting detection metrics for the current user."""
    try:
        con = sqlite3.connect(db_path)
        total = con.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
        blocked = con.execute("SELECT COUNT(*) FROM tool_calls WHERE allowed=0").fetchone()[0]
        malicious = con.execute("SELECT COUNT(*) FROM tool_calls WHERE label='malicious'").fetchone()[0]
        sessions = con.execute("SELECT COUNT(*) FROM agent_sessions").fetchone()[0]

        try:
            divergence = con.execute(
                "SELECT COUNT(*) FROM divergence_analysis WHERE verdict='SUSPICIOUS'"
            ).fetchone()[0]
        except Exception:
            divergence = 0

        try:
            collusion = con.execute(
                "SELECT COUNT(*) FROM collusion_detections"
            ).fetchone()[0]
        except Exception:
            collusion = 0

        lat = con.execute("SELECT AVG(latency_ms) FROM tool_calls").fetchone()[0] or 0
        con.close()

        detection_rate = round(
            (malicious / total * 100) if total > 0 else 0, 1
        )

        return {
            "user_id": user["user_id"],
            "user_name":user["name"],
            "total_calls": total,
            "blocked_calls": blocked,
            "malicious_calls":malicious,
            "sessions":sessions,
            "divergence":divergence,
            "collusion": collusion,
            "detection_rate": detection_rate,
            "avg_latency_ms": round(lat, 3),
            "is_demo":user["is_demo"],
        }
    except Exception as e:
        return {
            "user_id":user["user_id"],
            "user_name":user["name"],
            "total_calls":0,
            "error":str(e),
            "is_demo":user["is_demo"],
        }


@app.get("/api/user/sessions", tags=["User Data"])
def user_sessions(
    user:dict = Depends(get_current_user),
    db_path:str= Depends(get_user_db),
):
    """Get all agent sessions for the current user."""
    try:
        con= sqlite3.connect(db_path)
        rows= con.execute("""
            SELECT session_id, agent_id, agent_role,
                   call_count, blocked_count, cumulative_risk
            FROM agent_sessions
            ORDER BY session_id DESC
            LIMIT 50
        """).fetchall()
        con.close()
        return [
            {
                "session_id": r[0],
                "agent_id":r[1],
                "agent_role":r[2],
                "call_count":r[3],
                "blocked_count":r[4],
                "cumulative_risk":r[5],
            }
            for r in rows
        ]
    except Exception as e:
        return []

# ── Okta M2M Agent Identity ──────────────────────────────────────────────────
#
# Agents authenticate with Okta (client credentials flow) and call this
# endpoint instead of the demo intercept. IRIS validates the RS256 token via
# Okta's JWKS endpoint and derives the agent role from the token's scopes —
# the caller cannot supply or override the role.
#
# Requires env vars:  OKTA_ENABLED=true  OKTA_DOMAIN=...  OKTA_AUDIENCE=...

from security.okta_validator import validate_agent_token, OktaValidationError, OKTA_ENABLED
from interceptor.core import intercept as _intercept


class AgentInterceptRequest(BaseModel):
    tool_name:  str
    tool_args:  dict
    session_id: str
    label:      str = "benign"


@app.post("/api/agent/intercept", tags=["Agent Identity"])
def agent_intercept(
    req:           AgentInterceptRequest,
    authorization: str = Header(None),
):
    """
    Okta-authenticated tool interception endpoint.

    The agent presents its Okta access token (client credentials grant).
    IRIS validates the token cryptographically and extracts the agent role
    from the granted scopes — the caller cannot supply or forge the role.

    Token scopes → IRIS roles:
      iris.admin   → admin   (all tools)
      iris.analyst → analyst (read_file, query_db, call_api)
      iris.reader  → reader  (read_file only)

    When OKTA_ENABLED=false this endpoint returns 503 (use /api/intercept for demo mode).
    """
    if not OKTA_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="Okta agent identity is not enabled. Set OKTA_ENABLED=true and configure OKTA_DOMAIN.",
        )

    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization: Bearer <okta_token> required")

    try:
        agent_id, agent_role, token_payload = validate_agent_token(authorization)
    except OktaValidationError as e:
        raise HTTPException(status_code=401, detail=f"Okta token invalid: {e}")

    result = _intercept(
        agent_id   = agent_id,
        agent_role = agent_role,
        session_id = req.session_id,
        tool_name  = req.tool_name,
        tool_args  = req.tool_args,
        label      = req.label,
    )

    return {
        **result,
        "identity": {
            "source":     "okta",
            "agent_id":   agent_id,
            "agent_role": agent_role,
            "client_id":  token_payload.get("sub"),
            "scopes":     token_payload.get("scp", ""),
            "issuer":     token_payload.get("iss"),
        },
    }


@app.get("/api/agent/identity/status", tags=["Agent Identity"])
def agent_identity_status():
    """Returns whether Okta agent identity enforcement is active."""
    import os
    return {
        "okta_enabled":  OKTA_ENABLED,
        "okta_domain":   os.getenv("OKTA_DOMAIN", "not configured"),
        "okta_audience": os.getenv("OKTA_AUDIENCE", "api://default"),
        "scope_mapping": {
            "iris.admin":   "admin",
            "iris.analyst": "analyst",
            "iris.reader":  "reader",
        },
    }


@app.get("/api/user/events", tags=["User Data"])
def user_events(
    user:dict = Depends(get_current_user),
    db_path:str= Depends(get_user_db),
    limit:int = 50,
):
    """Getting recent tool call events for the current user."""
    try:
        con = sqlite3.connect(db_path)
        rows = con.execute("""
            SELECT agent_role, tool_name, allowed,
                   risk_score, label, timestamp
            FROM tool_calls
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()
        con.close()
        return [
            {
                "agent_role": r[0],
                "tool_name":r[1],
                "allowed":bool(r[2]),
                "risk_score":r[3],
                "label":r[4],
                "timestamp":r[5],
            }
            for r in rows
        ]
    except Exception:
        return []


# ── YARA Malware Scanning ─────────────────────────────────────────────────────

import hashlib
import tempfile
from fastapi import UploadFile, File

YARA_RULES_DIR = pathlib.Path(__file__).parent.parent.parent / "malware-analysis-lab" / "rules"
_compiled_rules = None


def _load_yara_rules():
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules
    try:
        import yara
        rule_files = list(YARA_RULES_DIR.glob("*.yar")) + list(YARA_RULES_DIR.glob("*.yara"))
        if not rule_files:
            return None
        filepaths = {f.stem: str(f) for f in rule_files}
        _compiled_rules = yara.compile(filepaths=filepaths)
        return _compiled_rules
    except ImportError:
        return None


@app.post("/api/scan/file", tags=["Malware Detection"])
async def scan_file(file: UploadFile = File(...)):
    """
    YARA-based malware scan for uploaded files.
    Runs compiled rules from malware-analysis-lab/rules/ against the uploaded binary.
    Returns matches with MITRE ATT&CK technique tags.
    """
    content = await file.read()
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content, usedforsecurity=False).hexdigest()

    rules = _load_yara_rules()
    if rules is None:
        return {
            "filename": file.filename,
            "sha256": sha256,
            "md5": md5,
            "size_bytes": len(content),
            "scanned": False,
            "error": "YARA rules not available (install yara-python or check rules directory)",
            "matches": [],
        }

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    scan_start = time.perf_counter()
    try:
        matches = rules.match(tmp_path)
    finally:
        pathlib.Path(tmp_path).unlink(missing_ok=True)
    scan_time_ms = (time.perf_counter() - scan_start) * 1000
    iris_yara_scan_latency_ms.observe(scan_time_ms)

    match_results = []
    for m in matches:
        mitre = m.meta.get("mitre_attack", "")
        match_results.append({
            "rule": m.rule,
            "namespace": m.namespace,
            "description": m.meta.get("description", ""),
            "mitre_attack": mitre,
            "mitre_url": f"https://attack.mitre.org/techniques/{mitre.replace('.', '/')}/" if mitre else "",
            "tags": list(m.tags),
            "strings_matched": [
                {"offset": hex(s.instances[0].offset), "identifier": s.identifier, "data": s.instances[0].matched_data[:64].hex()}
                for s in m.strings
                if s.instances
            ],
        })

    threat_level = "CLEAN"
    if match_results:
        threat_level = "MALICIOUS" if any(
            "cryptominer" in r["rule"].lower() or r["mitre_attack"] for r in match_results
        ) else "SUSPICIOUS"

    return {
        "filename": file.filename,
        "sha256": sha256,
        "md5": md5,
        "size_bytes": len(content),
        "scanned": True,
        "threat_level": threat_level,
        "match_count": len(match_results),
        "matches": match_results,
        "scan_time_ms": round(scan_time_ms, 3),
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/api/scan/rules", tags=["Malware Detection"])
def list_yara_rules():
    """List all loaded YARA rules and their metadata."""
    rule_files = list(YARA_RULES_DIR.glob("*.yar")) + list(YARA_RULES_DIR.glob("*.yara"))
    rules_info = []
    for rf in rule_files:
        try:
            content = rf.read_text()
            meta_lines = {}
            in_meta = False
            for line in content.splitlines():
                line = line.strip()
                if line == "meta:":
                    in_meta = True
                    continue
                if in_meta and line.startswith("strings:"):
                    break
                if in_meta and "=" in line:
                    k, _, v = line.partition("=")
                    meta_lines[k.strip()] = v.strip().strip('"')
            import re
            rule_names = re.findall(r'^rule\s+(\w+)', content, re.MULTILINE)
            rules_info.append({
                "file": rf.name,
                "rules": rule_names,
                "description": meta_lines.get("description", ""),
                "author": meta_lines.get("author", ""),
                "mitre_attack": meta_lines.get("mitre_attack", ""),
                "date": meta_lines.get("date", ""),
                "validated_against": meta_lines.get("validated_against", ""),
                "false_positive_corpus": meta_lines.get("false_positive_corpus", ""),
                "false_positive_rate": meta_lines.get("false_positive_rate", ""),
                "avg_scan_latency_ms": meta_lines.get("avg_scan_latency_ms", ""),
            })
        except Exception as e:
            rules_info.append({"file": rf.name, "error": str(e)})

    return {
        "rules_directory": str(YARA_RULES_DIR),
        "rule_files": rules_info,
        "total_files": len(rule_files),
    }


# ── RAG: semantic search + investigation agent ──────────────────────────────
def get_db_path_for_request(authorization: str = Header(None)) -> str:
    """Same auth resolution as get_db_for_request, but returns the file path (needed for Chroma)."""
    if authorization:
        token = authorization.replace("Bearer ", "").strip()
        payload = verify_token(token)
        if payload:
            return get_db_path_for_user(payload.get("user_id"))
    return DB_PATH


class SimilaritySearchRequest(BaseModel):
    query: str
    top_k: int = 5


@app.post("/api/search/similar", tags=["RAG"])
def search_similar_detections(req: SimilaritySearchRequest, db_path: str = Depends(get_db_path_for_request)):
    """Semantic search over past detections (divergence + collusion) using local embeddings."""
    try:
        from rag.semantic_search import search_similar
        results = search_similar(db_path, req.query, top_k=req.top_k)
        return {"query": req.query, "results": results, "count": len(results)}
    except Exception as e:
        return {"query": req.query, "results": [], "count": 0, "error": str(e)}


@app.post("/api/detections/{session_id}/explain", tags=["RAG"])
def explain_detection(session_id: str, db_path: str = Depends(get_db_path_for_request)):
    """LangGraph investigation agent: retrieves similar past incidents + MITRE ATLAS context, then generates a grounded explanation via a local LLM."""
    try:
        from rag.investigation_agent import investigate
        return investigate(db_path, session_id)
    except Exception as e:
        return {"session_id": session_id, "found": False, "explanation": "", "error": str(e)}