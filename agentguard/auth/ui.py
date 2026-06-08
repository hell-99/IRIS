"""
IRIS: Authentication UI

Login and register pages for the Streamlit dashboard.
Handles session state, token storage, and user context.
"""
import os
import requests
import streamlit as st

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")

_DEMO_USER = {
    "token": "demo",
    "user_id": "demo",
    "email": "demo@iris-security.com",
    "name": "Demo User",
    "is_demo": True,
    "plan": "pro",
}


def _is_direct_db() -> bool:
    try:
        return str(st.secrets.get("DIRECT_DB", os.getenv("DIRECT_DB", "false"))).lower() == "true"
    except Exception:
        return os.getenv("DIRECT_DB", "false").lower() == "true"


def _api_post(endpoint: str, data: dict) -> dict:
    direct_db = _is_direct_db()
    if direct_db:
        if endpoint == "/auth/login":
            if (data.get("email") == "demo@iris-security.com" and
                    data.get("password") == "demo123"):
                return _DEMO_USER
            return {"detail": "Use demo@iris-security.com / demo123"}
        return {"detail": "Registration not available in demo mode"}
    try:
        r = requests.post(f"{API_BASE}{endpoint}", json=data, timeout=5)
        return r.json()
    except Exception as e:
        return {"detail": str(e)}


def init_session_state():
    """Initializing all auth-related session state."""
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "token" not in st.session_state:
        st.session_state.token = None
    if "user" not in st.session_state:
        st.session_state.user = None
    if "auth_page" not in st.session_state:
        st.session_state.auth_page = "login"

def logout():
    """Clearing session state and log out."""
    st.session_state.authenticated = False
    st.session_state.token = None
    st.session_state.user = None
    st.rerun()


def show_login_page():
    """Rendering the login page."""
    st.markdown("""
    <div style='text-align:center; padding: 2rem 0 1rem 0;'>
        <h1 style='color:#00ff88; font-size:3rem; font-family:monospace; letter-spacing:0.2em;'>IRIS</h1>
        <p style='color:#64748b; font-size:0.9rem; letter-spacing:0.3em;'>AGENTIC IDENTITY RISK INTELLIGENCE SYSTEM</p>
    </div>
    """, unsafe_allow_html=True)

    _, col2, _ = st.columns([1, 2, 1])
    with col2:
        st.markdown("### Sign In")

        with st.form("login_form"):
            email = st.text_input("Email", placeholder="you@company.com")
            password = st.text_input("Password", type="password", placeholder="*********")
            submitted = st.form_submit_button("Sign In", use_container_width=True)

            if submitted:
                if not email or not password:
                    st.error("Please enter email and password")
                elif (email == "demo@iris-security.com" and password == "demo123"):
                    st.session_state.authenticated = True
                    st.session_state.token = "demo"
                    st.session_state.user = {
                        "user_id": "demo",
                        "email": "demo@iris-security.com",
                        "name": "Demo User",
                        "is_demo": True,
                        "plan": "pro",
                    }
                    st.rerun()
                else:
                    with st.spinner("Signing in..."):
                        result = _api_post("/auth/login", {
                            "email": email,
                            "password": password,
                        })
                    if "token" in result:
                        st.session_state.authenticated = True
                        st.session_state.token = result["token"]
                        st.session_state.user = {
                            "user_id": result["user_id"],
                            "email": result["email"],
                            "name": result["name"],
                            "is_demo": result["is_demo"],
                            "plan": result["plan"],
                        }
                        st.rerun()
                    else:
                        st.error(result.get("detail", "Invalid credentials"))

        st.markdown("---")

        # Demo account shortcut
        st.markdown(
            "<p style='text-align:center; color:#64748b; font-size:0.85rem;'>Try the demo</p>",
            unsafe_allow_html=True
        )
        if st.button("Sign in as Demo User", use_container_width=True):
            st.session_state.authenticated = True
            st.session_state.token = "demo"
            st.session_state.user = {
                "user_id": "demo",
                "email": "demo@iris-security.com",
                "name": "Demo User",
                "is_demo": True,
                "plan": "pro",
            }
            st.rerun()

        st.markdown("---")
        st.markdown(
            "<p style='text-align:center; color:#64748b; font-size:0.85rem;'>Don't have an account?</p>",
            unsafe_allow_html=True
        )
        if st.button("Create Account", use_container_width=True):
            st.session_state.auth_page = "register"
            st.rerun()


def show_register_page():
    """Rendering the register page."""
    st.markdown("""
    <div style='text-align:center; padding: 2rem 0 1rem 0;'>
        <h1 style='color:#00ff88; font-size:3rem; font-family:monospace; letter-spacing:0.2em;'>IRIS</h1>
        <p style='color:#64748b; font-size:0.9rem; letter-spacing:0.3em;'>AGENTIC IDENTITY RISK INTELLIGENCE SYSTEM</p>
    </div>
    """, unsafe_allow_html=True)

    _, col2, _ = st.columns([1, 2, 1])
    with col2:
        st.markdown("### Create Account")

        with st.form("register_form"):
            name = st.text_input("Full Name", placeholder="abc xyz")
            email = st.text_input("Email", placeholder="you@company.com")
            password = st.text_input("Password", type="password", placeholder="Min 6 characters")
            password2 = st.text_input("Confirm Password", type="password", placeholder="Repeat password")
            submitted = st.form_submit_button("Create Account", use_container_width=True)

            if submitted:
                if not name or not email or not password:
                    st.error("All fields are required")
                elif password != password2:
                    st.error("Passwords do not match")
                elif len(password) < 6:
                    st.error("Password must be at least 6 characters")
                else:
                    with st.spinner("Creating account..."):
                        result = _api_post("/auth/register", {
                            "email": email,
                            "name":name,
                            "password":password,
                        })

                    if "token" in result:
                        st.session_state.authenticated = True
                        st.session_state.token = result["token"]
                        st.session_state.user= {
                            "user_id": result["user_id"],
                            "email":result["email"],
                            "name":result["name"],
                            "is_demo":result["is_demo"],
                            "plan":result["plan"],
                        }
                        st.success("Account created!")
                        st.rerun()
                    else: st.error(result.get("detail", "Registration failed"))

        st.markdown("---")
        if st.button("<- Back to Sign In", use_container_width=True):
            st.session_state.auth_page = "login"
            st.rerun()


def show_auth_page():
    """Showing login or register page based on session state."""
    init_session_state()
    if st.session_state.auth_page == "register":
        show_register_page()
    else: show_login_page()


def show_user_header():
    """Showing user info and logout button in sidebar."""
    if st.session_state.user:
        user = st.session_state.user
        st.sidebar.markdown("---")

        # User badge
        plan_color = "#00ff88" if user["plan"] == "pro" else "#64748b"
        st.sidebar.markdown(
            f"<div style='padding:0.5rem; border:1px solid #1e293b; border-radius:6px;'>"
            f"<p style='margin:0; color:#e2e8f0; font-size:0.85rem;'>👤 {user['name']}</p>"
            f"<p style='margin:0; color:#64748b; font-size:0.75rem;'>{user['email']}</p>"
            f"<p style='margin:0; color:{plan_color}; font-size:0.75rem; text-transform:uppercase;'>"
            f"{'*' if user['plan'] == 'pro' else ''}{user['plan']}"
            f"{'  -  Demo Account' if user['is_demo'] else ''}</p>"
            f"</div>",
            unsafe_allow_html=True
        )

        st.sidebar.markdown("")
        if st.sidebar.button("Sign Out", use_container_width=True):
            logout()


def require_auth():
    """
    Calling this at the top of dashboard/app.py.
    Returns True if authenticated, False if showing auth page.
    """
    init_session_state()
    if not st.session_state.authenticated:
        show_auth_page()
        return False
    return True
