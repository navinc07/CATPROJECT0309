"""
tests/test_recommend_v2.py
==========================
Unit and integration tests for Phase 2 ML recommendation endpoint (/alerts/{id}/recommend_v2).
Validates model prediction, confidence scoring, explainability output, and side-by-side execution with Phase 1.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.auth import create_access_token


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def soc_lead_headers():
    token = create_access_token(analyst_id="ana_004", role="soc_lead")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def l1_headers():
    token = create_access_token(analyst_id="ana_001", role="l1_analyst")
    return {"Authorization": f"Bearer {token}"}


def test_recommend_v2_endpoint_success(client, soc_lead_headers, l1_headers):
    """
    GIVEN an existing alert in the database,
    WHEN calling GET /alerts/{alert_id}/recommend_v2,
    THEN returns HTTP 200 with ML recommendation schema matching Phase 1.
    """
    # Fetch an alert ID using SOC lead queue
    list_resp = client.get("/alerts?page_size=1", headers=soc_lead_headers)
    assert list_resp.status_code == 200
    alerts = list_resp.json()["alerts"]
    assert len(alerts) > 0
    alert_id = alerts[0]["alert_id"]

    # Call Phase 2 recommendation endpoint with L1 analyst credentials
    response = client.get(f"/alerts/{alert_id}/recommend_v2", headers=l1_headers)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

    data = response.json()
    assert data["alert_id"] == alert_id
    assert data["recommendation"] in ("suggest_fp", "suggest_tp", "escalate", "anomaly_signal_detected")
    assert "confidence" in data
    assert "tier" in data["confidence"]
    assert "score" in data["confidence"]
    assert "explainability" in data
    assert "top_contributing_features" in data["explainability"]["evidence_detail"]


def test_recommend_v2_side_by_side_comparison(client, soc_lead_headers, l1_headers):
    """
    GIVEN an existing alert,
    WHEN calling both /recommend (Phase 1) and /recommend_v2 (Phase 2),
    THEN both succeed and return consistent schemas for comparison.
    """
    list_resp = client.get("/alerts?page_size=1", headers=soc_lead_headers)
    alert_id = list_resp.json()["alerts"][0]["alert_id"]

    resp_p1 = client.get(f"/alerts/{alert_id}/recommend", headers=l1_headers)
    resp_p2 = client.get(f"/alerts/{alert_id}/recommend_v2", headers=l1_headers)

    assert resp_p1.status_code == 200
    assert resp_p2.status_code == 200

    data_p1 = resp_p1.json()
    data_p2 = resp_p2.json()

    # Both schemas share root keys
    for key in ("alert_id", "recommendation", "confidence", "requires_human_confirmation", "explainability"):
        assert key in data_p1
        assert key in data_p2


def test_recommend_v2_404_for_nonexistent_alert(client, l1_headers):
    """GIVEN a non-existent alert ID, returns HTTP 404."""
    response = client.get("/alerts/ALT-NONEXISTENT-99999/recommend_v2", headers=l1_headers)
    assert response.status_code == 404
