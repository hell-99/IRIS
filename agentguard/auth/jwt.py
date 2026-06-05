"""
IRIS: JWT Authentication

Token creation and verification for API security.
"""
import os
import json
import hmac
import hashlib
import base64
import time
from typing import Optional

JWT_SECRET = os.getenv("JWT_SECRET", "iris-security-secret-key-2026-change-in-prod")
JWT_EXPIRY = 60 * 60 * 24 * 7  # 7 days


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)

def create_token(user_id: str, email: str) -> str:
    """Creating a JWT token for a user."""
    header = _b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64encode(json.dumps({
        "user_id": user_id,
        "email":email,
        "iat":int(time.time()),
        "exp":int(time.time()) + JWT_EXPIRY,
    }).encode())

    signature= _b64encode(
        hmac.new(
            JWT_SECRET.encode(),
            f"{header}.{payload}".encode(),
            hashlib.sha256,
        ).digest()
    )
    return f"{header}.{payload}.{signature}"


def verify_token(token: str) -> Optional[dict]:
    """Verifying a JWT token. Returns payload dict or None."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header, payload, signature = parts

        # Verifying signature
        expected = _b64encode(
            hmac.new(
                JWT_SECRET.encode(),
                f"{header}.{payload}".encode(),
                hashlib.sha256,
            ).digest()
        )
        if not hmac.compare_digest(signature, expected):
            return None

        data = json.loads(_b64decode(payload))

        if data.get("exp", 0) < time.time():
            return None

        return data

    except Exception:
        return None


def get_user_id_from_token(token: str) -> Optional[str]:
    """Extracting user_id from a valid token."""
    payload = verify_token(token)
    return payload.get("user_id") if payload else None
