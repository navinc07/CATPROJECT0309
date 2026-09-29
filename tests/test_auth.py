"""
tests/test_auth.py
==================
Unit and integration tests for JWT authentication, token issuance,
signature verification, role enforcement, and backward compatibility (GAP 4).
"""

from datetime import timedelta
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.auth import create_access_token


@pytest.fixture
def client():
    return TestClient(app)


def test_login_success_l1(client):
    """GIVEN valid L1 analyst credentials, returns 200 and signed JWT."""
    response = client.post(
        "/auth/login",
        json={"analyst_id": "ana_001", "password": "Analyst123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "l1_analyst"
    assert data["analyst_id"] == "ana_001"


def test_login_success_soc_lead(client):
    """GIVEN valid SOC Lead credentials, returns 200 and signed JWT."""
    response = client.post(
        "/auth/login",
        json={"analyst_id": "ana_004", "password": "Lead123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "soc_lead"
    assert data["analyst_id"] == "ana_004"


def test_login_invalid_password(client):
    """GIVEN wrong password, returns 401."""
    response = client.post(
        "/auth/login",
        json={"analyst_id": "ana_001", "password": "WrongPassword!"},
    )
    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]


def test_login_unknown_analyst(client):
    """GIVEN non-existent analyst_id, returns 401."""
    response = client.post(
        "/auth/login",
        json={"analyst_id": "unknown_user", "password": "AnyPassword!"},
    )
    assert response.status_code == 401


def test_unauthenticated_request_rejected(client):
    """GIVEN request with no auth headers, returns 401 Unauthorized."""
    response = client.get("/alerts")
    assert response.status_code == 401
    assert "Authentication required" in response.json()["detail"]


def test_bearer_token_access_alerts(client):
    """GIVEN valid Bearer token, allows access to protected alerts endpoint."""
    token = create_access_token(analyst_id="ana_001", role="l1_analyst")
    response = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert "alerts" in response.json()


def test_tampered_token_rejected(client):
    """GIVEN a tampered JWT token, returns 401."""
    token = create_access_token(analyst_id="ana_001", role="l1_analyst")
    # Tamper with token characters
    tampered_token = token[:-5] + "XXXXX"
    response = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert response.status_code == 401


def test_expired_token_rejected(client):
    """GIVEN an expired JWT token, returns 401 with expiration message."""
    expired_token = create_access_token(
        analyst_id="ana_001",
        role="l1_analyst",
        expires_delta=timedelta(seconds=-10),
    )
    response = client.get(
        "/alerts",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


def test_l1_jwt_cannot_access_config_rules(client):
    """GIVEN valid L1 analyst JWT, access to /config/rules is forbidden (403)."""
    token = create_access_token(analyst_id="ana_001", role="l1_analyst")
    response = client.get(
        "/config/rules",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert "does not have permission" in response.json()["detail"].lower()


def test_soc_lead_jwt_can_access_config_rules(client):
    """GIVEN valid SOC Lead JWT, access to /config/rules succeeds (200)."""
    token = create_access_token(analyst_id="ana_004", role="soc_lead")
    response = client.get(
        "/config/rules",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert "config" in response.json()


def test_legacy_header_fallback_still_works(client):
    """GIVEN Phase 1 legacy headers, requests still succeed for backward compatibility."""
    response = client.get(
        "/alerts",
        headers={"x-analyst-role": "l1_analyst", "x-analyst-id": "ana_001"},
    )
    assert response.status_code == 200
