"""
IRIS  -  Day 5: Live Security Dashboard (v2)
Animated, modern, production-grade SOC aesthetic.
"""
import sys, pathlib, time, requests, json
import pandas as pd
from datetime import datetime
import streamlit as st

import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(
    page_title="IRIS  -  Agentic Security Monitor",
    page_icon="", layout="wide",
    initial_sidebar_state="expanded",
)

# Authentication
import sys, pathlib, os
_root = pathlib.Path(__file__).parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

DIRECT_DB = os.getenv("DIRECT_DB", "false").lower() == "true"

from auth.ui import init_session_state, show_auth_page, show_user_header

init_session_state()
if not st.session_state.get("authenticated", False):
    _auth_placeholder = st.empty()
    with _auth_placeholder.container():
        show_auth_page()
    st.stop()

show_user_header()

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")

# CSS
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Space+Grotesk:wght@300;400;500;600;700&display=swap');

:root {
  --bg:       #060912;
  --surface:  #0d1117;
  --surface2: #161b22;
  --border:   #21262d;
  --green:    #00ff88;
  --red:      #ff4757;
  --amber:    #ffa502;
  --blue:     #00d2ff;
  --purple:   #a855f7;
  --text:     #e6edf3;
  --muted:    #484f58;
}

html,body,[class*="css"]{
  font-family:'Space Grotesk',sans-serif;
  background:var(--bg); color:var(--text);
}
.main .block-container{
  padding:1.5rem 2rem; max-width:100%;
  background:var(--bg);
}

/* Animated scan line */
.main::before{
  content:'';position:fixed;top:0;left:0;right:0;
  height:2px;background:linear-gradient(90deg,transparent,var(--green),transparent);
  animation:scan 3s ease-in-out infinite;z-index:999;opacity:0.6;
}
@keyframes scan{0%{transform:translateX(-100%)}100%{transform:translateX(100vw)}}

/* Header */
.iris-logo{
  font-family:'JetBrains Mono',monospace;
  font-size:2.8rem;font-weight:700;
  background:linear-gradient(135deg,var(--green) 0%,var(--blue) 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  letter-spacing:-0.04em;line-height:1;
  animation:glow 3s ease-in-out infinite alternate;
}
@keyframes glow{
  from{filter:drop-shadow(0 0 8px rgba(0,255,136,0.3))}
  to{filter:drop-shadow(0 0 20px rgba(0,210,255,0.5))}
}
.iris-sub{
  font-family:'JetBrains Mono',monospace;
  font-size:0.65rem;letter-spacing:0.2em;
  color:var(--muted);text-transform:uppercase;margin-top:2px;
}

/* KPI cards */
.kpi-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:1.5rem 0;}
.kpi{
  background:var(--surface);border:1px solid var(--border);
  border-radius:12px;padding:1.2rem 1.4rem;position:relative;
  overflow:hidden;transition:transform 0.2s,border-color 0.2s;
  cursor:default;
}
.kpi:hover{transform:translateY(-2px);}
.kpi::after{
  content:'';position:absolute;inset:0;
  background:linear-gradient(135deg,rgba(255,255,255,0.02) 0%,transparent 60%);
  pointer-events:none;
}
.kpi-accent{position:absolute;top:0;left:0;right:0;height:2px;}
.kpi-val{
  font-family:'JetBrains Mono',monospace;
  font-size:2.2rem;font-weight:700;line-height:1;
  margin-bottom:6px;
}
.kpi-label{font-size:0.65rem;color:var(--muted);
  text-transform:uppercase;letter-spacing:0.12em;font-weight:500;}
.kpi-delta{font-size:0.7rem;margin-top:4px;}

/* Section */
.sec{
  font-family:'JetBrains Mono',monospace;font-size:0.65rem;
  color:var(--muted);letter-spacing:0.2em;text-transform:uppercase;
  display:flex;align-items:center;gap:8px;margin:1.8rem 0 1rem;
}
.sec::after{content:'';flex:1;height:1px;background:var(--border);}

/* Event row */
.ev{
  display:flex;align-items:center;gap:10px;
  padding:7px 12px;border-bottom:1px solid rgba(33,38,45,0.5);
  font-family:'JetBrains Mono',monospace;font-size:0.78rem;
  transition:background 0.15s;
}
.ev:hover{background:rgba(255,255,255,0.02);}

/* Detection card */
.det{
  background:var(--surface);border:1px solid var(--border);
  border-radius:10px;padding:1.2rem 1.4rem;margin-bottom:10px;
  border-left:3px solid var(--red);position:relative;overflow:hidden;
  transition:transform 0.15s,box-shadow 0.15s;
}
.det:hover{transform:translateX(3px);
  box-shadow:-3px 0 15px rgba(255,71,87,0.15);}
.det.normal{border-left-color:var(--green);}
.det.normal:hover{box-shadow:-3px 0 15px rgba(0,255,136,0.1);}

/* Collusion card */
.col-card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:10px;padding:1.4rem;margin-bottom:12px;
  border-top:2px solid var(--amber);
  animation:fadein 0.4s ease;
}
@keyframes fadein{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.agent-box{
  background:rgba(0,0,0,0.3);border-radius:8px;
  padding:10px 14px;flex:1;
}
.connector{
  display:flex;flex-direction:column;align-items:center;
  gap:4px;color:var(--red);font-size:1.2rem;min-width:80px;
  font-family:'JetBrains Mono',monospace;
}

/* Graph node */
.node{
  display:inline-flex;align-items:center;gap:6px;
  background:rgba(0,0,0,0.4);border-radius:6px;
  padding:4px 10px;font-family:'JetBrains Mono',monospace;
  font-size:0.75rem;margin:3px;border:1px solid var(--border);
}
.node.allowed{border-color:rgba(0,255,136,0.3);}
.node.blocked{border-color:rgba(255,71,87,0.4);
  background:rgba(255,71,87,0.05);}

/* Live pulse */
.pulse{
  display:inline-block;width:8px;height:8px;border-radius:50%;
  margin-right:6px;animation:blink 1.5s ease infinite;
}
.pulse.live{background:var(--green);}
.pulse.dead{background:var(--red);animation:none;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0.2}}

/* Badge */
.badge{
  display:inline-block;padding:2px 8px;border-radius:20px;
  font-size:0.65rem;font-weight:600;letter-spacing:0.05em;
  font-family:'JetBrains Mono',monospace;text-transform:uppercase;
}
.badge-red{background:rgba(255,71,87,0.15);color:var(--red);
  border:1px solid rgba(255,71,87,0.3);}
.badge-amber{background:rgba(255,165,2,0.15);color:var(--amber);
  border:1px solid rgba(255,165,2,0.3);}
.badge-green{background:rgba(0,255,136,0.1);color:var(--green);
  border:1px solid rgba(0,255,136,0.2);}
.badge-blue{background:rgba(0,210,255,0.1);color:var(--blue);
  border:1px solid rgba(0,210,255,0.2);}

/* Sidebar */
[data-testid="stSidebar"]{
  background:var(--surface);border-right:1px solid var(--border);
}
#MainMenu,footer,header{visibility:hidden;}
.stRadio > div{gap:4px;}
.stRadio > div > label{
  padding:8px 12px !important;border-radius:6px !important;
  font-size:0.85rem !important;
  transition:background 0.15s !important;
}

/* Scrollbar */
::-webkit-scrollbar{width:4px;height:4px;}
::-webkit-scrollbar-track{background:var(--bg);}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px;}

/* Force sidebar always visible */
[data-testid="stSidebarCollapsedControl"]{display:none !important;}
section[data-testid="stSidebar"]{
  transform:none !important;
  min-width:260px !important;
  width:260px !important;
}

/* Plotly override */
.js-plotly-plot .plotly .main-svg{background:transparent !important;}
</style>
""", unsafe_allow_html=True)

# Helpers
def _get_headers():
    """Get auth headers for current user."""
    token = st.session_state.get("token")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}

def _is_demo_user():
    """Check if current user is demo."""
    user = st.session_state.get("user", {})
    return user.get("is_demo", False)

@st.cache_data(ttl=3)
def fetch(ep, params=None, _token=None):
    """Fetch data from API with auth token."""
    try:
        headers = {"Authorization": f"Bearer {_token}"} if _token else {}
        r = requests.get(f"{API_BASE}{ep}", params=params,
                        headers=headers, timeout=3)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

if DIRECT_DB:
    import importlib, pathlib as _pl
    _db_spec = importlib.util.spec_from_file_location(
        "db_direct", _pl.Path(__file__).parent / "db_direct.py"
    )
    _db = importlib.util.module_from_spec(_db_spec)
    _db_spec.loader.exec_module(_db)

    def _direct_fetch(ep, params):
        p = params or {}
        if ep == "/api/metrics":
            return _db.get_metrics()
        if ep == "/api/sessions":
            return _db.get_sessions(
                status=p.get("status"), role=p.get("role"),
                limit=int(p.get("limit", 50)),
            )
        if ep.startswith("/api/sessions/"):
            return _db.get_session_detail(ep.split("/")[-1])
        if ep == "/api/detections":
            return _db.get_detections(
                verdict=p.get("verdict"), limit=int(p.get("limit", 50)),
            )
        if ep == "/api/collusion":
            return _db.get_collusion(
                severity=p.get("severity"), limit=int(p.get("limit", 50)),
            )
        if ep == "/api/graphs":
            return _db.get_graphs(limit=int(p.get("limit", 20)))
        if ep.startswith("/api/graphs/"):
            return _db.get_graph_detail(ep.split("/")[-1])
        if ep == "/api/events":
            return _db.get_events(
                limit=int(p.get("limit", 100)),
                blocked_only=bool(p.get("blocked_only", False)),
                role=p.get("role"),
            )
        return None

def fetch_user(ep, params=None):
    """Fetch user-scoped data using current token."""
    if DIRECT_DB:
        if _is_demo_user():
            return _direct_fetch(ep, params)
        return None
    token = st.session_state.get("token")
    return fetch(ep, params=params, _token=token)

def online():
    if DIRECT_DB:
        return True
    try: return requests.get(f"{API_BASE}/", timeout=2).status_code == 200
    except: return False

def threat_color(score):
    if score >= 80: return "var(--red)"
    if score >= 60: return "var(--amber)"
    if score >= 30: return "var(--blue)"
    return "var(--green)"

def threat_badge(score):
    if score >= 80: return "badge-red","CRITICAL"
    if score >= 60: return "badge-red","HIGH"
    if score >= 30: return "badge-amber","MEDIUM"
    return "badge-green","LOW"

PLOT = dict(
    plot_bgcolor="rgba(0,0,0,0)",
    paper_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#e6edf3", family="JetBrains Mono", size=10),
    margin=dict(l=0,r=0,t=32,b=0),
    xaxis=dict(gridcolor="#21262d",showgrid=True,title=None,tickfont=dict(size=9)),
    yaxis=dict(gridcolor="#21262d",showgrid=True,title=None,tickfont=dict(size=9)),
)

# Sidebar
with st.sidebar:
    st.markdown("""
    <div style='font-family:JetBrains Mono,monospace;font-size:1.3rem;
                font-weight:700;color:#00ff88;margin-bottom:2px;'>IRIS</div>
    <div style='font-size:0.6rem;color:#484f58;letter-spacing:0.15em;
                text-transform:uppercase;margin-bottom:20px;'>
        Identity Risk Intelligence
    </div>""", unsafe_allow_html=True)

    api_ok = online()
    dot = "live" if api_ok else "dead"
    txt = "API ONLINE" if api_ok else "API OFFLINE"
    col = "#00ff88" if api_ok else "#ff4757"
    st.markdown(f"""
    <div style='font-family:JetBrains Mono,monospace;font-size:0.72rem;
                color:{col};margin-bottom:20px;'>
        <span class='pulse {dot}'></span>{txt}
    </div>""", unsafe_allow_html=True)

    if not api_ok:
        st.error("Run: `python3 run_day4.py`")
        st.stop()

    st.markdown("---")
    page = st.radio("", [
        "⬡  Overview","⬡  Sessions","⬡  Detections",
        "⬡  Collusion","⬡  Attack Graphs","⬡  Live Feed"
    ], label_visibility="collapsed")
    page = page.replace("⬡  ","")

    st.markdown("---")
    auto = st.toggle("Auto-refresh", True)
    rate = st.slider("Interval (sec)", 2, 30, 5)
    st.markdown(f"""
    <div style='font-family:JetBrains Mono,monospace;font-size:0.6rem;
                color:#21262d;margin-top:16px;'>
        v1.0 · {datetime.utcnow().strftime('%H:%M:%S')} UTC
    </div>""", unsafe_allow_html=True)

# Header
c1,c2 = st.columns([5,1])
with c1:
    st.markdown("""
    <div class='iris-logo'>IRIS</div>
    <div class='iris-sub'>Agentic Identity Risk Intelligence System</div>
    """, unsafe_allow_html=True)
with c2:
    st.markdown("<div style='height:20px'></div>",unsafe_allow_html=True)
    if st.button("↻  Refresh", use_container_width=True):
        st.cache_data.clear(); st.rerun()

# OVERVIEW
if page == "Overview":
    m = fetch_user("/api/metrics")
    if not m:
        st.error("No data  -  run day1/day2/day3 first"); st.stop()

    # KPI row
    st.markdown("<div class='sec'>// system metrics</div>",unsafe_allow_html=True)
    kpis = [
        (m.get("total_events",0),      "Tool Calls Monitored", "#00ff88",""),
        (f"{m.get('detection_rate_pct',0)}%","Detection Rate",  "#00d2ff",""),
        (f"{m.get('avg_detection_latency_ms',0)}ms","Avg Latency","#a855f7",""),
        (m.get("collusion_detections",0),"Collusion Patterns", "#ff4757",""),
        (m.get("suspicious_divergences",0),"Suspicious Intents","#ffa502",""),
        (m.get("blocked_events",0),     "Blocked Calls",       "#ff4757",""),
    ]
    cols = st.columns(6)
    for col,(val,label,color,delta) in zip(cols,kpis):
        with col:
            st.markdown(f"""
            <div class='kpi'>
                <div class='kpi-accent' style='background:{color};'></div>
                <div class='kpi-val' style='color:{color};'>{val}</div>
                <div class='kpi-label'>{label}</div>
            </div>""",unsafe_allow_html=True)

    st.markdown("<div style='height:8px'></div>",unsafe_allow_html=True)

    # Charts
    st.markdown("<div class='sec'>// threat intelligence</div>",unsafe_allow_html=True)
    cl,cr = st.columns([3,2])

    with cl:
        ev = fetch_user("/api/events",{"limit":300})
        if ev and ev.get("events"):
            df = pd.DataFrame(ev["events"])
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            df["minute"] = df["timestamp"].dt.floor("1min")
            df["status"] = df["allowed"].apply(lambda x:"Allowed" if x else "Blocked")
            agg = df.groupby(["minute","status"]).size().reset_index(name="n")
            fig = go.Figure()
            for status,color,fill in [
                ("Allowed","#00ff88","rgba(0,255,136,0.08)"),
                ("Blocked","#ff4757","rgba(255,71,87,0.15)")
            ]:
                d = agg[agg.status==status]
                fig.add_trace(go.Scatter(
                    x=d["minute"],y=d["n"],name=status,
                    line=dict(color=color,width=2),
                    fill="tozeroy",fillcolor=fill,mode="lines",
                ))
            fig.update_layout(
                title=dict(text="Tool Call Activity",font=dict(size=11,color="#484f58")),
                legend=dict(orientation="h",yanchor="bottom",y=1.02,font=dict(size=9)),
                **PLOT
            )
            st.plotly_chart(fig, use_container_width=True)

    with cr:
        ttp = m.get("ttp_breakdown",{})
        if ttp:
            fig2 = go.Figure(go.Pie(
                labels=list(ttp.keys()),values=list(ttp.values()),
                hole=0.65,
                marker=dict(
                    colors=["#ff4757","#ffa502","#00d2ff","#00ff88","#a855f7"],
                    line=dict(color="#060912",width=2)
                ),
                textinfo="label+percent",
                textfont=dict(size=9,family="JetBrains Mono"),
                hovertemplate="<b>%{label}</b><br>%{value} events<extra></extra>",
            ))
            fig2.update_layout(
                title=dict(text="MITRE ATLAS TTPs",font=dict(size=11,color="#484f58")),
                showlegend=False,
                annotations=[dict(
                    text=f"<b>{sum(ttp.values())}</b><br><span style='font-size:9px'>TTPs</span>",
                    x=0.5,y=0.5,font_size=18,font_color="#00ff88",
                    font_family="JetBrains Mono",showarrow=False,
                )],
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e6edf3",family="JetBrains Mono"),
                margin=dict(l=0,r=0,t=32,b=0),
            )
            st.plotly_chart(fig2, use_container_width=True)

    # Risk heatmap
    st.markdown("<div class='sec'>// agent risk heatmap</div>",unsafe_allow_html=True)
    sd = fetch_user("/api/sessions",{"limit":50})
    if sd and sd.get("sessions"):
        df_s = pd.DataFrame(sd["sessions"])
        if not df_s.empty and "cumulative_risk" in df_s.columns:
            df_s = df_s.sort_values("cumulative_risk",ascending=False).head(20)
            fig3 = go.Figure(go.Bar(
                x=df_s["agent_id"].str[:14],
                y=df_s["cumulative_risk"],
                marker=dict(
                    color=df_s["cumulative_risk"],
                    colorscale=[[0,"#00ff88"],[0.4,"#ffa502"],[0.7,"#ff4757"],[1,"#ff0000"]],
                    line=dict(width=0),
                ),
                hovertemplate="<b>%{x}</b><br>Risk: %{y:.0f}<extra></extra>",
            ))
            fig3.update_layout(
                title=dict(text="Agent Risk Scores (top 20)",font=dict(size=11,color="#484f58")),
                xaxis=dict(tickangle=35,tickfont=dict(size=8),gridcolor="#21262d"),
                yaxis=dict(gridcolor="#21262d",tickfont=dict(size=9)),
                paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e6edf3",family="JetBrains Mono"),
                margin=dict(l=0,r=0,t=32,b=60),
            )
            st.plotly_chart(fig3, use_container_width=True)

# SESSIONS
elif page == "Sessions":
    st.markdown("<div class='sec'>// active agent sessions</div>",unsafe_allow_html=True)
    cf1,cf2 = st.columns(2)
    with cf1:
        rf = st.selectbox("Role",["All","admin","analyst","reader"],
                          label_visibility="collapsed")
    with cf2:
        sf = st.selectbox("Status",["All","critical","warning","normal"],
                          label_visibility="collapsed")

    p = {"limit":100}
    if rf!="All": p["role"]=rf
    if sf!="All": p["status"]=sf
    data = fetch_user("/api/sessions",p)

    if data and data.get("sessions"):
        for s in data["sessions"]:
            risk = s.get("cumulative_risk",0) or 0
            bc,bl = threat_badge(risk)
            role  = s.get("agent_role","")
            aid   = s.get("agent_id","")
            calls = s.get("call_count",0)
            blk   = s.get("blocked_count",0)
            color = threat_color(risk)

            col_a,col_b,col_c,col_d,col_e = st.columns([3,1,1,1,1])
            with col_a:
                st.markdown(f"""
                <div style='font-family:JetBrains Mono,monospace;font-size:0.82rem;
                            color:#e6edf3;padding:8px 0;'>
                    {aid}
                </div>""",unsafe_allow_html=True)
            with col_b:
                st.markdown(f"""
                <div style='font-size:0.78rem;color:#484f58;padding:8px 0;'>
                    {role}
                </div>""",unsafe_allow_html=True)
            with col_c:
                st.markdown(f"""
                <div style='font-family:JetBrains Mono,monospace;font-size:0.9rem;
                            font-weight:700;color:{color};padding:8px 0;'>
                    {risk:.0f}
                </div>""",unsafe_allow_html=True)
            with col_d:
                st.markdown(f"""
                <div style='font-size:0.78rem;color:#484f58;padding:8px 0;'>
                    {calls} calls
                </div>""",unsafe_allow_html=True)
            with col_e:
                st.markdown(f"""
                <span class='badge {bc}'>{bl}</span>
                """,unsafe_allow_html=True)

            st.markdown("<hr style='border-color:#21262d;margin:0;'>",
                        unsafe_allow_html=True)

        st.markdown(f"""
        <div style='font-size:0.7rem;color:#484f58;margin-top:8px;
                    font-family:JetBrains Mono,monospace;'>
            {data['count']} sessions
        </div>""",unsafe_allow_html=True)

# DETECTIONS
elif page == "Detections":
    st.markdown("<div class='sec'>// intent-action divergence detections</div>",
                unsafe_allow_html=True)
    data = fetch_user("/api/detections",{"limit":50})

    if data and data.get("detections"):
        suspicious = [d for d in data["detections"] if d.get("verdict")=="SUSPICIOUS"]
        normal     = [d for d in data["detections"] if d.get("verdict")!="SUSPICIOUS"]

        c1,c2,c3 = st.columns(3)
        with c1:
            st.markdown(f"""
            <div class='kpi'>
                <div class='kpi-accent' style='background:#ff4757;'></div>
                <div class='kpi-val' style='color:#ff4757;'>{len(suspicious)}</div>
                <div class='kpi-label'>Suspicious</div>
            </div>""",unsafe_allow_html=True)
        with c2:
            st.markdown(f"""
            <div class='kpi'>
                <div class='kpi-accent' style='background:#00ff88;'></div>
                <div class='kpi-val' style='color:#00ff88;'>{len(normal)}</div>
                <div class='kpi-label'>Normal</div>
            </div>""",unsafe_allow_html=True)
        with c3:
            total = data.get("count",0)
            rate  = round(len(suspicious)/total*100,1) if total>0 else 0
            st.markdown(f"""
            <div class='kpi'>
                <div class='kpi-accent' style='background:#a855f7;'></div>
                <div class='kpi-val' style='color:#a855f7;'>{rate}%</div>
                <div class='kpi-label'>Detection Rate</div>
            </div>""",unsafe_allow_html=True)

        st.markdown("<div style='height:16px'></div>",unsafe_allow_html=True)

        for det in data["detections"]:
            verdict    = det.get("verdict","NORMAL")
            divergence = det.get("divergence_score",0)
            task       = det.get("task","")[:90]
            role       = det.get("agent_role","")
            expected   = det.get("expected_tools",[])
            actual     = det.get("actual_tools",[])
            reason     = det.get("sensitivity_reason","")
            is_sus     = verdict == "SUSPICIOUS"

            border_c = "#ff4757" if is_sus else "#00ff88"
            div_c    = "#ff4757" if is_sus else "#00ff88"
            icon     = "warning" if is_sus else "ok"

            exp_html = " ".join(
                f"<span class='node allowed'>{t}</span>"
                for t in (expected if isinstance(expected,list) else [])
            )
            act_set  = list(dict.fromkeys(actual if isinstance(actual,list) else []))
            act_html = " ".join(
                f"<span class='node {'blocked' if t not in (expected or []) else 'allowed'}'>"
                f"{t}</span>"
                for t in act_set[:8]
            )
            reason_html = (
                f"<div style='color:#ff4757;font-size:0.73rem;margin-top:8px;"
                f"font-family:JetBrains Mono,monospace;'>"
                f"warning {reason}</div>"
            ) if reason else ""

            st.markdown(f"""
            <div class='det {"" if is_sus else "normal"}'>
                <div style='display:flex;justify-content:space-between;
                            align-items:center;margin-bottom:10px;'>
                    <div>
                        <span style='font-weight:600;font-size:0.85rem;
                                     margin-right:8px;'>{icon} {role.upper()}</span>
                        <span class='badge {"badge-red" if is_sus else "badge-green"}'>
                            {verdict}
                        </span>
                    </div>
                    <div style='font-family:JetBrains Mono,monospace;
                                font-size:1.3rem;font-weight:700;color:{div_c};'>
                        {divergence}%
                    </div>
                </div>
                <div style='font-size:0.78rem;color:#484f58;
                            margin-bottom:12px;font-style:italic;'>
                    "{task}..."
                </div>
                <div style='display:grid;grid-template-columns:1fr 1fr;gap:12px;'>
                    <div>
                        <div style='font-size:0.6rem;color:#484f58;
                                    text-transform:uppercase;letter-spacing:0.1em;
                                    margin-bottom:6px;font-family:JetBrains Mono,monospace;'>
                            Expected
                        </div>
                        <div>{exp_html if exp_html else "<span style='color:#484f58;font-size:0.75rem;'> - </span>"}</div>
                    </div>
                    <div>
                        <div style='font-size:0.6rem;color:#484f58;
                                    text-transform:uppercase;letter-spacing:0.1em;
                                    margin-bottom:6px;font-family:JetBrains Mono,monospace;'>
                            Actual
                        </div>
                        <div>{act_html if act_html else "<span style='color:#484f58;font-size:0.75rem;'> - </span>"}</div>
                    </div>
                </div>
                {reason_html}
            </div>""",unsafe_allow_html=True)
    else: st.info("No detections. Run day2 first.")

# COLLUSION
elif page == "Collusion":
    st.markdown("<div class='sec'>// cross-agent collusion detections</div>",
                unsafe_allow_html=True)
    data = fetch_user("/api/collusion")

    if data and data.get("detections"):
        c1,c2,c3 = st.columns(3)
        for col,(val,label,color) in zip([c1,c2,c3],[
            (data["count"],"Total Patterns","#ff4757"),
            (data["critical"],"Critical","#ff4757"),
            (data["high"],"High","#ffa502"),
        ]):
            with col:
                st.markdown(f"""
                <div class='kpi'>
                    <div class='kpi-accent' style='background:{color};'></div>
                    <div class='kpi-val' style='color:{color};'>{val}</div>
                    <div class='kpi-label'>{label}</div>
                </div>""",unsafe_allow_html=True)

        st.markdown("<div style='height:20px'></div>",unsafe_allow_html=True)

        for det in data["detections"]:
            sev     = det.get("severity","HIGH")
            pattern = det.get("pattern_name","")
            desc    = det.get("description","")
            ttp     = det.get("ttp_id","")
            delta   = det.get("time_delta_ms",0) or 0
            a1r     = det.get("agent_1_role","")
            a1t     = det.get("agent_1_tool","")
            a1ts    = det.get("agent_1_time","")[:19] if det.get("agent_1_time") else ""
            a2r     = det.get("agent_2_role","")
            a2t     = det.get("agent_2_tool","")

            sev_c   = "#ff4757" if sev=="CRITICAL" else "#ffa502"
            sev_bc  = "badge-red" if sev=="CRITICAL" else "badge-amber"

            st.markdown(f"""
            <div class='col-card'>
                <div style='display:flex;justify-content:space-between;
                            align-items:center;margin-bottom:12px;'>
                    <div>
                        <span style='font-size:0.9rem;font-weight:600;
                                     margin-right:8px;'>! {pattern}</span>
                        <span class='badge {sev_bc}'>{sev}</span>
                        <span class='badge badge-blue' style='margin-left:4px;'>
                            {ttp}
                        </span>
                    </div>
                    <div style='font-size:0.72rem;color:#484f58;
                                font-family:JetBrains Mono,monospace;'>{a1ts}</div>
                </div>
                <div style='font-size:0.78rem;color:#484f58;margin-bottom:16px;'>
                    {desc}
                </div>
                <div style='display:flex;align-items:center;gap:12px;'>
                    <div class='agent-box'>
                        <div style='font-size:0.6rem;color:#484f58;
                                    text-transform:uppercase;letter-spacing:0.1em;
                                    margin-bottom:6px;font-family:JetBrains Mono,monospace;'>
                            Agent A
                        </div>
                        <div style='color:#00ff88;font-family:JetBrains Mono,monospace;
                                    font-size:0.85rem;font-weight:600;'>
                            {a1r}
                        </div>
                        <div style='color:#e6edf3;font-family:JetBrains Mono,monospace;
                                    font-size:0.8rem;margin-top:2px;'>
                            -> {a1t}
                        </div>
                    </div>
                    <div class='connector'>
                        <div style='font-size:1.4rem;'>!</div>
                        <div style='font-size:0.65rem;color:#484f58;'>
                            {delta/1000:.1f}s apart
                        </div>
                        <div style='font-size:0.7rem;color:{sev_c};'>COORDINATED</div>
                    </div>
                    <div class='agent-box' style='border:1px solid rgba(255,71,87,0.2);'>
                        <div style='font-size:0.6rem;color:#484f58;
                                    text-transform:uppercase;letter-spacing:0.1em;
                                    margin-bottom:6px;font-family:JetBrains Mono,monospace;'>
                            Agent B
                        </div>
                        <div style='color:#ff4757;font-family:JetBrains Mono,monospace;
                                    font-size:0.85rem;font-weight:600;'>
                            {a2r}
                        </div>
                        <div style='color:#e6edf3;font-family:JetBrains Mono,monospace;
                                    font-size:0.8rem;margin-top:2px;'>
                            -> {a2t}
                        </div>
                    </div>
                </div>
            </div>""",unsafe_allow_html=True)
    else: st.info("No collusion detections. Run day3 first.")

# ATTACK GRAPHS
elif page == "Attack Graphs":
    st.markdown("<div class='sec'>// attack graph reconstruction</div>",
                unsafe_allow_html=True)

    graphs = fetch_user("/api/graphs",{"limit":30})

    if not graphs or not graphs.get("graphs"):
        st.info("No attack graphs. Run day3 first.")
    else:
        df = pd.DataFrame(graphs["graphs"])

        tf = st.selectbox(
            "Threat level",["All","CRITICAL","HIGH","MEDIUM","LOW"],
            label_visibility="collapsed"
        )
        if tf != "All" and "threat_level" in df.columns:
            df = df[df["threat_level"]==tf]

        for _,row in df.iterrows():
            threat = row.get("threat_level","LOW")
            color_map = {"CRITICAL":"#ff4757","HIGH":"#ffa502",
                         "MEDIUM":"#00d2ff","LOW":"#00ff88"}
            color  = color_map.get(threat,"#00ff88")
            bc,bl  = threat_badge(row.get("max_risk",0) or 0)
            role   = row.get("agent_role","")
            sid    = row.get("session_id","")
            calls  = row.get("total_calls",0)
            blkd   = row.get("blocked",0) or 0

            label = (
                f"[{threat}]  {role.upper()}  ·  "
                f"{sid[:16]}...  ·  "
                f"{calls} calls  ·  {blkd} blocked"
            )

            with st.expander(label, expanded=(threat=="CRITICAL")):
                detail = fetch_user(f"/api/graphs/{sid}")
                if detail and detail.get("kill_chain"):
                    chain = detail["kill_chain"]

                    # Visual node graph using plotly
                    tools_called = list(dict.fromkeys(
                        c["tool_name"] for c in chain
                    ))
                    resources = list(dict.fromkeys(
                        str(c.get("args",""))[:25]
                        for c in chain if c.get("args")
                    ))[:6]

                    # Build network-style scatter
                    node_x,node_y,node_text,node_color,node_size = [],[],[],[],[]
                    edge_x,edge_y = [],[]

                    # Agent node
                    node_x.append(0.5); node_y.append(1.0)
                    node_text.append(f"{role} agent")
                    node_color.append(color); node_size.append(20)

                    # Tool nodes
                    n = len(tools_called)
                    for i,t in enumerate(tools_called):
                        x = (i+1)/(n+1)
                        node_x.append(x); node_y.append(0.5)
                        node_text.append(t)
                        # Check if any call for this tool was blocked
                        blocked_tool = any(
                            not c.get("allowed",True) for c in chain
                            if c["tool_name"]==t
                        )
                        node_color.append("#ff4757" if blocked_tool else "#00ff88")
                        node_size.append(14)
                        # Edge from agent to tool
                        edge_x += [0.5,x,None]
                        edge_y += [1.0,0.5,None]

                    fig = go.Figure()

                    # Edges
                    fig.add_trace(go.Scatter(
                        x=edge_x,y=edge_y,mode="lines",
                        line=dict(color="#21262d",width=1.5),
                        hoverinfo="none",showlegend=False,
                    ))

                    # Nodes
                    fig.add_trace(go.Scatter(
                        x=node_x,y=node_y,mode="markers+text",
                        marker=dict(
                            color=node_color,size=node_size,
                            line=dict(color="#060912",width=2),
                        ),
                        text=node_text,
                        textposition="bottom center",
                        textfont=dict(
                            family="JetBrains Mono",size=9,color="#e6edf3"
                        ),
                        hovertemplate="%{text}<extra></extra>",
                        showlegend=False,
                    ))

                    fig.update_layout(
                        height=180,showlegend=False,
                        xaxis=dict(showgrid=False,zeroline=False,
                                   showticklabels=False,range=[-0.1,1.1]),
                        yaxis=dict(showgrid=False,zeroline=False,
                                   showticklabels=False,range=[0.2,1.2]),
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        margin=dict(l=0,r=0,t=10,b=20),
                    )
                    st.plotly_chart(fig,use_container_width=True)

                    # Kill chain text
                    for c in chain:
                        allowed  = bool(c.get("allowed",True))
                        risk     = c.get("risk_score",0)
                        tool     = c.get("tool_name","")
                        ttp      = c.get("ttp_name","")
                        args_str = str(c.get("args",""))[:35]
                        risk_c   = threat_color(risk)
                        icon     = "ok" if allowed else "fail"
                        ic       = "#00ff88" if allowed else "#ff4757"
                        ttp_html = (
                            f"<span style='color:#ff4757;font-size:0.7rem;'>"
                            f" · {ttp}</span>"
                        ) if ttp and ttp!=" - " else ""

                        st.markdown(f"""
                        <div class='ev'>
                            <span style='color:{ic};min-width:12px;
                                         font-weight:700;'>{icon}</span>
                            <span style='color:#e6edf3;min-width:130px;'>{tool}</span>
                            <span style='color:#484f58;flex:1;'>{args_str}</span>
                            <span style='color:{risk_c};min-width:60px;
                                         text-align:right;font-weight:600;'>
                                {risk:.0f}
                            </span>
                            {ttp_html}
                        </div>""",unsafe_allow_html=True)

# LIVE FEED
elif page == "Live Feed":
    st.markdown("<div class='sec'>// real-time event stream</div>", unsafe_allow_html=True)

    cl,cr = st.columns([1,2])
    with cl: bo = st.toggle("Blocked only",False)
    with cr:
        rf = st.selectbox("Role",["All","admin","analyst","reader"],label_visibility="collapsed")

    p = {"limit":60}
    if bo: p["blocked_only"]=True
    if rf!="All": p["role"]=rf

    ev = fetch_user("/api/events",p)

    if ev and ev.get("events"):
        st.markdown(f"""
        <div style='font-family:JetBrains Mono,monospace;font-size:0.7rem;
                    color:#484f58;margin-bottom:12px;display:flex;
                    align-items:center;'>
            <span class='pulse live'></span>
            {ev['count']} events · auto-refresh every {rate}s
        </div>
        <div style='background:var(--surface);border:1px solid var(--border);
                    border-radius:10px;overflow:hidden;'>
        <div class='ev' style='background:var(--surface2);
                                border-bottom:1px solid var(--border);'>
            <span style='color:#484f58;min-width:12px;'>_</span>
            <span style='color:#484f58;min-width:145px;font-size:0.65rem;
                         text-transform:uppercase;letter-spacing:0.1em;'>
                Timestamp
            </span>
            <span style='color:#484f58;min-width:65px;font-size:0.65rem;
                         text-transform:uppercase;letter-spacing:0.1em;'>
                Role
            </span>
            <span style='color:#484f58;min-width:145px;font-size:0.65rem;
                         text-transform:uppercase;letter-spacing:0.1em;'>
                Tool
            </span>
            <span style='color:#484f58;flex:1;font-size:0.65rem;
                         text-transform:uppercase;letter-spacing:0.1em;'>
                Risk
            </span>
            <span style='color:#484f58;font-size:0.65rem;
                         text-transform:uppercase;letter-spacing:0.1em;'>
                TTP
            </span>
        </div>
        """,unsafe_allow_html=True)

        for e in ev["events"][:40]:
            allowed = bool(e.get("allowed",True))
            risk = e.get("risk_score",0) or 0
            role = e.get("agent_role","")
            tool= e.get("tool_name","")
            label= e.get("label","")
            ttp= e.get("ttp_name","") or ""
            ts = e.get("timestamp","")[:19]
            icon = "yayy allowed" if allowed else "noooo not allowed"
            ic = "#00ff88" if allowed else "#ff4757"
            rc = threat_color(risk)
            ttp_html = (
                f"<span style='color:#ff4757;'>{ttp}</span>"
                if ttp and ttp!=" - " else
                "<span style='color:#21262d;'> - </span>"
            )

            st.markdown(f"""
            <div class='ev'>
                <span style='color:{ic};min-width:12px;font-weight:700;'>{icon}</span>
                <span style='color:#484f58;min-width:145px;'>{ts}</span>
                <span style='color:#e6edf3;min-width:65px;'>{role}</span>
                <span style='color:#e6edf3;min-width:145px;'>{tool}</span>
                <span style='color:{rc};flex:1;font-weight:600;'>{risk:.0f}</span>
                {ttp_html}
            </div>""",unsafe_allow_html=True)

        st.markdown("</div>",unsafe_allow_html=True)
    else: st.info("No events. Run day1/day2/day3 first.")

# Auto refresh
if auto:
    time.sleep(rate)
    st.cache_data.clear()
    st.rerun()
