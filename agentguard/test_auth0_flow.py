"""
IRIS — Auth0 M2M Integration Test

Tests the full flow:
  1. Exchange client credentials with Auth0 → access token
  2. Decode token and verify claims (role scope present)
  3. Call IRIS /api/agent/intercept with the token
  4. Confirm role is extracted from token, not from caller

Run from agentguard/:
    python3 test_auth0_flow.py
"""

import os
import sys
import json
import base64
import httpx
from dotenv import load_dotenv

load_dotenv()

AUTH0_DOMAIN   = os.getenv("AUTH0_DOMAIN", "")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "https://iris-security-api")
IRIS_API_URL   = os.getenv("IRIS_API_URL", "http://localhost:8000")

AGENTS = [
    {
        "name":          "IRIS Admin Agent",
        "client_id":     os.getenv("IRIS_ADMIN_CLIENT_ID", ""),
        "client_secret": os.getenv("IRIS_ADMIN_CLIENT_SECRET", ""),
        "expected_role": "admin",
        "tool_name":     "read_file",
        "tool_args":     {"path": "public/readme.txt"},
    },
    {
        "name":          "IRIS Analyst Agent",
        "client_id":     os.getenv("IRIS_ANALYST_CLIENT_ID", ""),
        "client_secret": os.getenv("IRIS_ANALYST_CLIENT_SECRET", ""),
        "expected_role": "analyst",
        "tool_name":     "query_db",
        "tool_args":     {"query": "SELECT name, role FROM employees LIMIT 2"},
    },
    {
        "name":          "IRIS Reader Agent",
        "client_id":     os.getenv("IRIS_READER_CLIENT_ID", ""),
        "client_secret": os.getenv("IRIS_READER_CLIENT_SECRET", ""),
        "expected_role": "reader",
        "tool_name":     "read_file",
        "tool_args":     {"path": "public/readme.txt"},
    },
]


def _decode_payload(token: str) -> dict:
    """Decode JWT payload without verifying (just for display)."""
    try:
        part = token.split(".")[1]
        padding = 4 - len(part) % 4
        decoded = base64.urlsafe_b64decode(part + "=" * padding)
        return json.loads(decoded)
    except Exception:
        return {}


def get_token(agent: dict) -> "str | None":
    """Exchange client credentials with Auth0 for an access token."""
    if not agent["client_id"] or not agent["client_secret"]:
        print(f"  SKIP — {agent['name']}: client_id/secret not set in .env")
        return None

    resp = httpx.post(
        f"https://{AUTH0_DOMAIN}/oauth/token",
        json={
            "client_id":     agent["client_id"],
            "client_secret": agent["client_secret"],
            "audience":      AUTH0_AUDIENCE,
            "grant_type":    "client_credentials",
        },
        timeout=10,
    )

    if resp.status_code != 200:
        print(f"  FAIL — Auth0 token request: {resp.status_code} {resp.text}")
        return None

    return resp.json().get("access_token")


def check_iris_running() -> bool:
    try:
        r = httpx.get(f"{IRIS_API_URL}/", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def test_intercept(agent: dict, token: str) -> None:
    """Call IRIS /api/agent/intercept with the Okta token."""
    resp = httpx.post(
        f"{IRIS_API_URL}/api/agent/intercept",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "tool_name":  agent["tool_name"],
            "tool_args":  agent["tool_args"],
            "session_id": f"test-session-{agent['expected_role']}",
            "label":      "benign",
        },
        timeout=10,
    )

    if resp.status_code == 200:
        data = resp.json()
        identity = data.get("identity", {})
        role_from_token = identity.get("agent_role", "?")
        allowed = data.get("allowed", False)
        risk    = data.get("risk_score", 0)
        print(f"  IRIS intercept: role_from_token={role_from_token}  allowed={allowed}  risk={risk:.1f}")
        if role_from_token == agent["expected_role"]:
            print(f"  PASS — role correctly extracted from token (not caller-supplied)")
        else:
            print(f"  WARN — expected role '{agent['expected_role']}', got '{role_from_token}'")
    else:
        print(f"  IRIS intercept failed: {resp.status_code} {resp.text[:200]}")


def main():
    if not AUTH0_DOMAIN:
        print("ERROR: AUTH0_DOMAIN not set in .env")
        sys.exit(1)

    print(f"Auth0 domain : {AUTH0_DOMAIN}")
    print(f"Audience     : {AUTH0_AUDIENCE}")
    print(f"IRIS API     : {IRIS_API_URL}")
    iris_up = check_iris_running()
    print(f"IRIS running : {'yes' if iris_up else 'no (token test only)'}")
    print()

    for agent in AGENTS:
        print(f"── {agent['name']}")

        token = get_token(agent)
        if not token:
            print()
            continue

        payload = _decode_payload(token)
        scope   = payload.get("scope", "(none)")
        sub     = payload.get("sub", "?")
        exp     = payload.get("exp", 0)

        print(f"  Token obtained  sub={sub}")
        print(f"  Scopes          {scope}")
        print(f"  Expires         {exp}")

        # Verify expected scope is present
        expected_scope = f"iris:{agent['expected_role']}"
        if expected_scope in scope:
            print(f"  PASS — '{expected_scope}' scope present in token")
        else:
            print(f"  FAIL — '{expected_scope}' NOT in token scopes. Check Auth0 app permissions.")

        if iris_up:
            test_intercept(agent, token)

        print()

    print("Done.")


if __name__ == "__main__":
    main()
