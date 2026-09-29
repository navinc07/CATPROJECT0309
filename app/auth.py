"""
app/auth.py
===========
JWT-based Authentication and Authorization module for the SOC Assistant API (Phase 2).

WHY JWT AUTH (vs Phase 1 header-based identification):
    Phase 1 used plain HTTP headers (X-Analyst-Role, X-Analyst-ID). While sufficient
    for an initial prototype, trusting unauthenticated client headers introduces
    critical vulnerabilities:
    1. Header Spoofing: Any client could claim 'soc_lead' and modify safety guardrails
       or suppress rules without validation.
    2. Lack of Integrity & Expiration: Headers cannot expire or prove they were issued
       by a trusted identity provider.
    3. Production Readiness: Phase 3 deployment requires stateless, cryptographically
       signed session tokens compatible with microservices and API gateways.

ARCHITECTURE:
    - Cryptographic Signing: HMAC-SHA256 (HS256) with a securely managed secret key.
    - Token Claims: sub (analyst_id), role (l1_analyst / soc_lead), iat, exp.
    - Backward Compatibility: The get_current_analyst dependency inspects
      'Authorization: Bearer <token>' first. If absent, it gracefully falls back
      to legacy headers with a logged warning, preserving Phase 1 test execution.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import HTTPException, Header, status
from pydantic import BaseModel, Field

# Secret key for signing tokens (overrideable via environment)
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "c28_soc_assistant_secure_jwt_secret_2026!#")
JWT_ALGORITHM = "HS256"
DEFAULT_TOKEN_EXPIRE_HOURS = 8

# Seeded analyst user store (self-contained, mirrors data/analyst_decisions.csv)
SEEDED_ANALYSTS = {
    "ana_001": {
        "password": "Analyst123!",
        "role": "l1_analyst",
        "name": "Sarah Chen (Tier-1 Analyst)",
    },
    "ana_002": {
        "password": "Analyst123!",
        "role": "l1_analyst",
        "name": "Marcus Vance (Tier-1 Analyst)",
    },
    "ana_003": {
        "password": "Analyst123!",
        "role": "l1_analyst",
        "name": "Elena Rostova (Tier-1 Analyst)",
    },
    "ana_004": {
        "password": "Lead123!",
        "role": "soc_lead",
        "name": "David Kalu (SOC Lead / L2)",
    },
    "ana_005": {
        "password": "Analyst123!",
        "role": "l1_analyst",
        "name": "Priya Patel (Tier-1 Analyst)",
    },
}


class LoginRequest(BaseModel):
    """Payload for POST /auth/login."""
    analyst_id: str = Field(..., description="Analyst username / ID (e.g. ana_001, ana_004)")
    password: str = Field(..., description="Analyst password")


class TokenResponse(BaseModel):
    """Response containing signed JWT access token."""
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int
    analyst_id: str
    role: str
    name: str


def authenticate_analyst(analyst_id: str, password: str) -> Optional[dict]:
    """Verify credentials against seeded analyst store."""
    user = SEEDED_ANALYSTS.get(analyst_id.strip())
    if not user:
        return None
    if user["password"] == password.strip():
        return {
            "analyst_id": analyst_id.strip(),
            "role": user["role"],
            "name": user["name"],
        }
    return None


def create_access_token(
    analyst_id: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Issue a signed JWT access token containing analyst claims."""
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(hours=DEFAULT_TOKEN_EXPIRE_HOURS))
    payload = {
        "sub": analyst_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": "c28-soc-assistant-auth",
    }
    encoded = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded


def decode_jwt_token(token: str) -> dict:
    """
    Decodes and validates a JWT token.
    Raises HTTPException(401) on invalid signature, expiration, or malformed token.
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            issuer="c28-soc-assistant-auth",
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please log in again via /auth/login.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"token_expired\""},
        )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )


def get_current_analyst(
    authorization: Optional[str] = Header(None, description="Bearer <jwt_token>"),
    x_analyst_role: Optional[str] = Header(None, description="Legacy header fallback"),
    x_analyst_id: Optional[str] = Header(None, description="Legacy header fallback"),
) -> tuple[str, str]:
    """
    FastAPI dependency that extracts and validates the caller's identity.

    Priority:
    1. Authorization: Bearer <token> (Primary Phase 2 JWT method)
    2. Fallback: X-Analyst-Role / X-Analyst-ID (Legacy Phase 1 compatibility)

    Returns:
        tuple (analyst_id, analyst_role)
    Raises:
        HTTP 401 if unauthenticated.
        HTTP 400 if invalid role format.
    """
    # 1. Bearer Token Authentication (Standard)
    if authorization:
        parts = authorization.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format. Expected 'Bearer <token>'.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = parts[1]
        payload = decode_jwt_token(token)
        analyst_id = payload.get("sub")
        role = payload.get("role")
        if not analyst_id or not role:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed token claims: missing 'sub' or 'role'.",
            )
        return analyst_id, role

    # 2. Legacy Header Fallback (Preserves Phase 1 unit tests without disruption)
    if x_analyst_role and x_analyst_id:
        return x_analyst_id, x_analyst_role

    # 3. Neither provided -> 401 Unauthorized
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide 'Authorization: Bearer <token>' or authenticate via POST /auth/login.",
        headers={"WWW-Authenticate": "Bearer"},
    )
