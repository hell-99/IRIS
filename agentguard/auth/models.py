"""
IRIS: Auth Models

User management, password hashing, database operations.
"""
import sqlite3
import hashlib
import secrets
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional


AUTH_DB = Path("data/logs/iris_auth.db")


def _get_con():
    AUTH_DB.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(str(AUTH_DB))

def init_auth_db():
    """Initializing auth database with users table."""
    con = _get_con()
    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id      TEXT PRIMARY KEY,
            email        TEXT UNIQUE NOT NULL,
            name         TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt         TEXT NOT NULL,
            created_at   TEXT DEFAULT (datetime('now')),
            is_demo      INTEGER DEFAULT 0,
            plan         TEXT DEFAULT 'free'
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            token_id     TEXT PRIMARY KEY,
            user_id      TEXT NOT NULL,
            created_at   TEXT DEFAULT (datetime('now')),
            expires_at   TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)
    con.commit()
    con.close()

    _ensure_demo_account()

def _ensure_demo_account():
    """Creating the demo account pre-loaded with real data."""
    con = _get_con()
    existing = con.execute(
        "SELECT user_id FROM users WHERE email = ?",
        ("demo@iris-security.com",)
    ).fetchone()

    if not existing:
        salt = secrets.token_hex(16)
        pw_hash = _hash_password("demo123", salt)
        con.execute("""
            INSERT INTO users (user_id, email, name, password_hash, salt, is_demo, plan)
            VALUES (?, ?, ?, ?, ?, 1, 'pro')
        """, (
            "demo-user-iris-2026",
            "demo@iris-security.com",
            "IRIS Demo",
            pw_hash,
            salt,
        ))
        con.commit()
    con.close()

def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()


def create_user(email: str, name: str, password: str) -> dict:
    """Registering a new user. Returns user dict or raises ValueError."""
    con = _get_con()

    # Check if email already exists
    existing = con.execute(
        "SELECT user_id FROM users WHERE email = ?", (email,)
    ).fetchone()
    if existing:
        con.close()
        raise ValueError("Email already registered")

    user_id = str(uuid.uuid4())
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt)

    con.execute("""
        INSERT INTO users (user_id, email, name, password_hash, salt)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, email, name, pw_hash, salt))
    con.commit()
    con.close()

    return {"user_id":user_id, "email":email, "name":name}


def verify_user(email: str, password: str) -> Optional[dict]:
    """Verifing credentials. Returns user dict or None."""
    con = _get_con()
    row = con.execute("""
        SELECT user_id, email, name, password_hash, salt, is_demo, plan
        FROM users WHERE email = ?
    """, (email,)).fetchone()
    con.close()

    if not row:
        return None

    user_id, email, name, pw_hash, salt, is_demo, plan = row
    if _hash_password(password, salt) != pw_hash:
        return None

    return {
        "user_id": user_id,
        "email":email,
        "name":name,
        "is_demo": bool(is_demo),
        "plan":plan,
    }

def get_user(user_id: str) -> Optional[dict]:
    """Get user by ID."""
    con= _get_con()
    row= con.execute("""
        SELECT user_id, email, name, is_demo, plan
        FROM users WHERE user_id = ?
    """, (user_id,)).fetchone()
    con.close()

    if not row:
        return None
    return {
        "user_id": row[0],
        "email":row[1],
        "name": row[2],
        "is_demo": bool(row[3]),
        "plan":row[4],
    }


def get_db_path_for_user(user_id: str) -> str:
    """
    Getting the database path for a user.

    Demo user gets the main agentguard.db with all real data.
    Other users get their own isolated database.
    """
    if user_id == "demo-user-iris-2026":
        return "data/logs/agentguard.db"

    # Each user gets their own database
    user_db = Path(f"data/logs/user_{user_id[:8]}.db")
    user_db.parent.mkdir(parents=True, exist_ok=True)
    return str(user_db)
