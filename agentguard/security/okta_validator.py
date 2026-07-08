"""
IRIS — Auth0 M2M Agent Identity Validator

Each LLM agent authenticates with Auth0 using the OAuth 2.0 Client Credentials
flow and presents the resulting access token to IRIS. This module validates
those tokens cryptographically so IRIS never trusts a caller-supplied role.

Flow:
    1. Agent:  POST https://{AUTH0_DOMAIN}/oauth/token
                    client_id=<agent_client_id>
                    client_secret=<agent_client_secret>
                    grant_type=client_credentials
                    audience=https://iris-security-api

    2. IRIS:   Validates the RS256 JWT against Auth0's public JWKS
               Extracts the granted permissions → maps to IRIS agent role
               Rejects any caller-supplied role — role comes from the token only

Auth0 setup (free developer tier — auth0.com):
    - Create a custom API: Applications → APIs → Create API
        Name: IRIS Security API
        Identifier (audience): https://iris-security-api
        Add permissions: iris:admin, iris:analyst, iris:reader
    - Create one M2M application per agent role, authorized to the IRIS API
        with the matching permission checked

Environment variables required when OKTA_ENABLED=true:
    AUTH0_DOMAIN    e.g. dev-xxxx.us.auth0.com
    AUTH0_AUDIENCE  e.g. https://iris-security-api
    OKTA_ENABLED    set to "true" to enforce; if absent/false IRIS falls back to demo mode

Note: OKTA_ENABLED is kept as the toggle name for backward compatibility
      with docker-compose.yml — Auth0 and Okta both use the same OAuth 2.0 standard.
"""

import os
import threading
from typing import Optional

import jwt
from jwt import PyJWKClient, exceptions as jwt_exc


AUTH0_DOMAIN   = os.getenv("AUTH0_DOMAIN", os.getenv("OKTA_DOMAIN", ""))
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", os.getenv("OKTA_AUDIENCE", "https://iris-security-api"))
OKTA_ENABLED   = os.getenv("OKTA_ENABLED", "false").lower() == "true"

# Permission → IRIS role mapping.
# Auth0 API permissions defined on the IRIS Security API must match these.
_SCOPE_TO_ROLE: dict[str, str] = {
    "iris:admin":   "admin",
    "iris:analyst": "analyst",
    "iris:reader":  "reader",
}


class OktaValidationError(Exception):
    """Raised when an agent token fails validation."""


class OktaValidator:
    """
    Validates Auth0-issued RS256 access tokens for IRIS agent identity.

    JWKS are fetched from Auth0's well-known endpoint and cached.
    The cache is invalidated on key-ID (kid) miss so key rotation is
    handled transparently.
    """

    JWKS_TTL_SECONDS = 300   # re-fetch public keys every 5 minutes

    def __init__(self):
        if not AUTH0_DOMAIN:
            raise RuntimeError(
                "AUTH0_DOMAIN env var is not set. "
                "Set it or disable with OKTA_ENABLED=false."
            )
        # Auth0 issuer always ends with a trailing slash
        self._issuer   = f"https://{AUTH0_DOMAIN}/"
        self._jwks_uri = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
        self._jwks_client = PyJWKClient(
            self._jwks_uri,
            cache_jwk_set=True,
            lifespan=self.JWKS_TTL_SECONDS,
        )
        self._lock = threading.Lock()

    def validate(self, token: str) -> dict:
        """
        Validate an Auth0 access token and return its decoded payload.

        Verifies: RS256 signature, issuer, audience, expiry.
        Raises OktaValidationError on any failure.
        """
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=AUTH0_AUDIENCE,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "iss", "aud"]},
            )
            return payload
        except jwt_exc.ExpiredSignatureError:
            raise OktaValidationError("Token has expired")
        except jwt_exc.InvalidAudienceError:
            raise OktaValidationError(f"Token audience mismatch (expected {AUTH0_AUDIENCE})")
        except jwt_exc.InvalidIssuerError:
            raise OktaValidationError(f"Token issuer mismatch (expected {self._issuer})")
        except jwt_exc.PyJWKClientError as e:
            raise OktaValidationError(f"JWKS fetch failed: {e}")
        except jwt_exc.PyJWTError as e:
            raise OktaValidationError(f"Token validation failed: {e}")

    def extract_role(self, payload: dict) -> str:
        """
        Map Auth0 permissions from the token payload to an IRIS agent role.

        Auth0 M2M tokens carry permissions in the 'scope' claim as a
        space-separated string. Check in privilege order: admin > analyst > reader.
        Raises OktaValidationError if no IRIS permission is present.
        """
        raw_scope = payload.get("scope", "")
        scopes    = set(raw_scope.split()) if isinstance(raw_scope, str) else set(raw_scope)

        for scope in ("iris:admin", "iris:analyst", "iris:reader"):
            if scope in scopes:
                return _SCOPE_TO_ROLE[scope]

        raise OktaValidationError(
            f"Token has no IRIS permission (got: {scopes}). "
            "Expected one of: iris:admin, iris:analyst, iris:reader"
        )

    def validate_and_get_role(self, token: str) -> tuple[dict, str]:
        """Convenience: validate token and return (payload, iris_role)."""
        payload = self.validate(token)
        role    = self.extract_role(payload)
        return payload, role


# Singleton — created lazily only when OKTA_ENABLED=true
_validator: Optional[OktaValidator] = None
_validator_lock = threading.Lock()


def get_validator() -> OktaValidator:
    """Return the singleton OktaValidator, creating it on first call."""
    global _validator
    if _validator is None:
        with _validator_lock:
            if _validator is None:
                _validator = OktaValidator()
    return _validator


def validate_agent_token(bearer_token: str) -> tuple[str, str, dict]:
    """
    Top-level entry point for the API layer.

    Returns (agent_id, agent_role, token_payload).
    agent_id is taken from the token's 'sub' claim (Okta application client_id).
    agent_role is derived from the token's granted scopes.

    Raises OktaValidationError on any failure.
    """
    if not OKTA_ENABLED:
        raise OktaValidationError("Okta is not enabled (OKTA_ENABLED != true)")

    token = bearer_token.replace("Bearer ", "").strip()
    payload, role = get_validator().validate_and_get_role(token)

    # 'sub' in a client credentials token is the client_id of the Okta application
    agent_id = payload.get("sub", "unknown-agent")
    return agent_id, role, payload
