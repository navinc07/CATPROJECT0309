"""
tests/test_failure_cases.py
============================
Tests for the 4 failure/edge cases documented in tests/failure_cases.md.

TESTING STRATEGY:
    Each test creates an isolated, minimal in-memory SQLite database with
    exactly the data needed to trigger the failure case. This avoids
    dependency on the full 13K-row synthetic dataset being generated and
    keeps tests fast and deterministic.

    We use pytest fixtures to create a fresh in-memory DB per test
    (not per session) to ensure test isolation — a decision written in
    one test does not corrupt the recommendation logic in another.

    We also test the FastAPI endpoints directly using TestClient so that
    the full request/response path (including Pydantic validation) is
    exercised, not just the engine functions in isolation.

RUNNING:
    pip install pytest httpx
    pytest tests/test_failure_cases.py -v

EXPECTED RESULT:
    All tests should PASS. If any fails, it means the recommendation engine
    or API is not correctly handling that failure case.
"""

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.db.database import Base, get_db
from app.db.models import Alert, AnalystDecision, EndpointContext, IncidentLabel
from app.main import app
from app.recommendation_engine import (
    get_recommendation,
    REC_INSUFFICIENT,
    REC_CONFLICT,
    REC_ANOMALY,
    REC_SUGGEST_FP,
    TIER_INSUFFICIENT,
    TIER_LOW,
    AUTO_SUGGEST_THRESHOLD_FLOOR,
    MAX_ALLOWED_MISS_RATE_CEILING,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def in_memory_db():
    """
    Creates a fresh in-memory SQLite database per test using a SINGLE engine.

    All session_factory() calls within one test invocation bind to the same
    engine, which points to the same ':memory:' database. This ensures data
    seeded in one session is visible to sessions created by the TestClient.

    Test isolation: each test invocation gets a fresh engine (new :memory: DB).
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def session_factory():
        """Return a new Session bound to the shared in-memory engine."""
        return TestingSession()

    yield session_factory

    # Dispose engine — this destroys the in-memory database.
    engine.dispose()


@pytest.fixture
def client(in_memory_db):
    """
    Creates a TestClient with the in-memory DB injected via dependency override.
    Uses the shared in_memory_db connection so seeded data is visible to the app.
    """
    def override_get_db():
        db = in_memory_db()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _seed_fp_cluster_history(db, pattern_type: str, segment: str, count: int = 20):
    """
    Helper: insert `count` alerts + decisions for a known-FP pattern.
    These create the historical FP cluster that the novel TP will superficially match.
    """
    for i in range(count):
        alert_id = f"HIST-{pattern_type}-{segment}-{i:03d}"
        alert = Alert(
            alert_id=alert_id,
            timestamp="2026-07-01T09:00:00Z",
            source_segment=segment,
            alert_type=pattern_type,
            severity=2,
            src_ip="10.2.1.1",
            dst_ip="10.0.1.2",  # internal DNS — key FP cluster signal
            signature_rule_triggered="IDS-DNS-007",
            raw_score=0.3,
        )
        ctx = EndpointContext(
            alert_id=alert_id,
            device_type="laptop",
            os="Windows 10",
            patch_status="fully_patched",
            is_managed_device=True,
            user_type=segment,
            known_vuln_count=0,  # key FP cluster signal: zero vulns
        )
        decision = AnalystDecision(
            alert_id=alert_id,
            analyst_id="ana_001",
            analyst_role="l1_analyst",
            disposition="false_positive",
            time_spent_minutes=6,
            decision_timestamp="2026-07-01T09:05:00Z",
            override_flag=False,
            override_reason=None,
        )
        db.add(alert)
        db.add(ctx)
        db.add(decision)
    db.commit()


# ---------------------------------------------------------------------------
# F1: Missing Endpoint Context
# ---------------------------------------------------------------------------

class TestF1MissingEndpointContext:
    """
    Failure Case F1: Alert exists, endpoint context record is absent.
    The engine must degrade gracefully with insufficient_evidence recommendation.
    """

    def test_no_context_returns_insufficient_evidence(self, in_memory_db):
        """
        GIVEN: An alert in the database with NO endpoint context record.
        WHEN: get_recommendation() is called.
        THEN: recommendation_type == 'insufficient_evidence'
              requires_human_confirmation == True
              'MISSING_ENDPOINT_CONTEXT' in anomaly_flags
        """
        db = in_memory_db()

        # Seed enough FP history so the pattern would normally get a recommendation
        _seed_fp_cluster_history(db, "DNS_FLOOD", "guest", count=20)

        # Create the test alert WITHOUT endpoint context
        alert_id = "TEST-F1-001"
        alert = Alert(
            alert_id=alert_id,
            timestamp="2026-07-15T10:00:00Z",
            source_segment="guest",
            alert_type="DNS_FLOOD",
            severity=3,
            src_ip="10.2.5.5",
            dst_ip="10.0.1.2",
            signature_rule_triggered="IDS-DNS-007",
            raw_score=0.35,
        )
        db.add(alert)
        db.commit()
        # NOTE: Deliberately NOT adding EndpointContext for this alert_id

        result = get_recommendation(alert_id, db)
        db.close()

        assert result.recommendation_type == REC_INSUFFICIENT, (
            f"Expected {REC_INSUFFICIENT}, got {result.recommendation_type}. "
            "Engine should NOT suggest FP when endpoint context is missing."
        )
        assert result.requires_human_confirmation is True, (
            "Missing context must require human confirmation — cannot assess risk."
        )
        assert result.confidence_tier == TIER_INSUFFICIENT, (
            f"Expected TIER_INSUFFICIENT, got {result.confidence_tier}."
        )
        # Check anomaly flag is present
        missing_flag_present = any(
            "MISSING_ENDPOINT_CONTEXT" in flag for flag in result.anomaly_flags
        )
        assert missing_flag_present, (
            f"Expected MISSING_ENDPOINT_CONTEXT in anomaly_flags, got: {result.anomaly_flags}"
        )

    def test_no_context_does_not_crash(self, in_memory_db):
        """
        GIVEN: An alert with no context.
        WHEN: get_recommendation() is called.
        THEN: No exception is raised.
        """
        db = in_memory_db()
        alert_id = "TEST-F1-002"
        alert = Alert(
            alert_id=alert_id,
            timestamp="2026-07-15T10:00:00Z",
            source_segment="guest",
            alert_type="DNS_FLOOD",
            severity=3,
            src_ip="10.2.5.6",
            dst_ip="10.0.1.2",
            signature_rule_triggered="IDS-DNS-007",
            raw_score=0.3,
        )
        db.add(alert)
        db.commit()

        try:
            result = get_recommendation(alert_id, db)
        except Exception as e:
            pytest.fail(f"get_recommendation raised an exception with missing context: {e}")
        finally:
            db.close()

    def test_api_endpoint_handles_missing_context(self, tmp_path):
        """
        GIVEN: A GET /alerts/{id}/recommend request for an alert with no context.
        WHEN: The endpoint is called via TestClient.
        THEN: HTTP 200 (not 500), recommendation == insufficient_evidence.

        NOTE: This test uses a file-based SQLite temp DB (not :memory:) because
        SQLite :memory: databases are connection-scoped — the TestClient opens a
        new connection and sees an empty database. A file DB is accessible to all
        connections simultaneously.
        """
        import os
        from sqlalchemy import create_engine as ce2
        from sqlalchemy.orm import sessionmaker as sm2

        db_file = tmp_path / "test_f1_api.db"
        test_engine = ce2(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=test_engine)
        TestSession = sm2(autocommit=False, autoflush=False, bind=test_engine)

        # Seed data
        db = TestSession()
        for i in range(20):
            a_id = f"HIST-DNS_FLOOD-guest-{i:03d}"
            db.add(Alert(
                alert_id=a_id, timestamp="2026-07-01T09:00:00Z",
                source_segment="guest", alert_type="DNS_FLOOD", severity=2,
                src_ip="10.2.1.1", dst_ip="10.0.1.2",
                signature_rule_triggered="IDS-DNS-007", raw_score=0.3,
            ))
            db.add(EndpointContext(
                alert_id=a_id, device_type="laptop", os="Windows 10",
                patch_status="fully_patched", is_managed_device=True,
                user_type="guest", known_vuln_count=0,
            ))
            db.add(AnalystDecision(
                alert_id=a_id, analyst_id="ana_001", analyst_role="l1_analyst",
                disposition="false_positive", time_spent_minutes=6,
                decision_timestamp="2026-07-01T09:05:00Z",
                override_flag=False, override_reason=None,
            ))

        alert_id = "TEST-F1-API-001"
        db.add(Alert(
            alert_id=alert_id, timestamp="2026-07-15T11:00:00Z",
            source_segment="guest", alert_type="DNS_FLOOD", severity=3,
            src_ip="10.2.5.7", dst_ip="10.0.1.2",
            signature_rule_triggered="IDS-DNS-007", raw_score=0.3,
        ))
        # NO EndpointContext for this alert — this is the failure case
        db.commit()
        db.close()

        def override_get_db():
            s = TestSession()
            try:
                yield s
            finally:
                s.close()

        app.dependency_overrides[get_db] = override_get_db
        with TestClient(app) as test_client:
            response = test_client.get(
                f"/alerts/{alert_id}/recommend",
                headers={"x-analyst-role": "l1_analyst", "x-analyst-id": "ana_001"},
            )
        app.dependency_overrides.clear()

        assert response.status_code == 200, (
            f"Expected HTTP 200, got {response.status_code}: {response.text}"
        )
        data = response.json()
        assert data["recommendation"] == REC_INSUFFICIENT


# ---------------------------------------------------------------------------
# F2: Conflicting Analyst History
# ---------------------------------------------------------------------------

class TestF2ConflictingAnalystHistory:
    """
    Failure Case F2: Same (alert_type, segment) pattern has both FP and TP decisions.
    The engine must detect the conflict and refuse to suggest FP suppression.
    """

    def test_conflict_returns_conflicting_evidence(self, in_memory_db):
        """
        GIVEN: A pattern with 15 FP decisions AND 3 TP decisions in history.
               (3 TPs >= conflict_threshold=2 from config)
        WHEN: get_recommendation() is called for a new alert of the same pattern.
        THEN: recommendation_type == 'conflicting_evidence'
              requires_human_confirmation == True
              recommendation is NOT 'suggest_fp'
        """
        db = in_memory_db()

        # Seed 15 FP decisions for PORT_SCAN / student
        for i in range(15):
            alert_id = f"CONF-FP-{i:03d}"
            alert = Alert(
                alert_id=alert_id,
                timestamp="2026-07-01T09:00:00Z",
                source_segment="student",
                alert_type="PORT_SCAN",
                severity=4,
                src_ip="10.1.1.1",
                dst_ip="10.0.0.1",
                signature_rule_triggered="IDS-SCAN-003",
                raw_score=0.4,
            )
            ctx = EndpointContext(
                alert_id=alert_id,
                device_type="laptop",
                os="Windows 10",
                patch_status="fully_patched",
                is_managed_device=True,
                user_type="student",
                known_vuln_count=0,
            )
            decision = AnalystDecision(
                alert_id=alert_id,
                analyst_id="ana_001",
                analyst_role="l1_analyst",
                disposition="false_positive",
                time_spent_minutes=6,
                decision_timestamp="2026-07-01T09:05:00Z",
                override_flag=False,
                override_reason=None,
            )
            db.add(alert)
            db.add(ctx)
            db.add(decision)

        # Seed 3 TP decisions for the SAME pattern (conflict!)
        for i in range(3):
            alert_id = f"CONF-TP-{i:03d}"
            alert = Alert(
                alert_id=alert_id,
                timestamp="2026-07-05T09:00:00Z",
                source_segment="student",
                alert_type="PORT_SCAN",
                severity=6,
                src_ip="10.1.2.2",
                dst_ip="10.0.0.1",
                signature_rule_triggered="IDS-SCAN-003",
                raw_score=0.7,
            )
            ctx = EndpointContext(
                alert_id=alert_id,
                device_type="laptop",
                os="Windows 10",
                patch_status="fully_patched",
                is_managed_device=True,
                user_type="student",
                known_vuln_count=0,
            )
            decision = AnalystDecision(
                alert_id=alert_id,
                analyst_id="ana_002",
                analyst_role="l1_analyst",
                disposition="true_positive",  # TP — conflict!
                time_spent_minutes=15,
                decision_timestamp="2026-07-05T09:30:00Z",
                override_flag=True,
                override_reason="Observed lateral movement attempt after port scan",
            )
            db.add(alert)
            db.add(ctx)
            db.add(decision)

        db.commit()

        # New alert of the same pattern
        new_alert_id = "TEST-F2-001"
        new_alert = Alert(
            alert_id=new_alert_id,
            timestamp="2026-07-15T10:00:00Z",
            source_segment="student",
            alert_type="PORT_SCAN",
            severity=4,
            src_ip="10.1.3.3",
            dst_ip="10.0.0.1",
            signature_rule_triggered="IDS-SCAN-003",
            raw_score=0.45,
        )
        new_ctx = EndpointContext(
            alert_id=new_alert_id,
            device_type="laptop",
            os="Windows 11",
            patch_status="fully_patched",
            is_managed_device=True,
            user_type="student",
            known_vuln_count=0,
        )
        db.add(new_alert)
        db.add(new_ctx)
        db.commit()

        result = get_recommendation(new_alert_id, db)
        db.close()

        assert result.recommendation_type == REC_CONFLICT, (
            f"Expected {REC_CONFLICT}, got {result.recommendation_type}. "
            "Engine must detect conflicting FP+TP history and refuse to suggest FP."
        )
        assert result.requires_human_confirmation is True
        assert result.recommendation_type != REC_SUGGEST_FP, (
            "CRITICAL: Engine suggested FP despite conflicting history. This is unsafe."
        )
        # Evidence should mention the conflict
        assert "tp_count" in str(result.evidence_detail) or "tp" in str(result.evidence_detail).lower(), (
            "Evidence detail should include TP count information."
        )

    def test_fp_only_history_suggests_fp(self, in_memory_db):
        """
        GIVEN: A pattern with 20 FP decisions and 0 TP decisions (clean cluster).
        WHEN: get_recommendation() is called.
        THEN: recommendation_type == 'suggest_fp' (happy path — contrast with F2).
        """
        db = in_memory_db()
        _seed_fp_cluster_history(db, "DNS_FLOOD", "guest", count=20)

        alert_id = "TEST-F2-HAPPY"
        alert = Alert(
            alert_id=alert_id,
            timestamp="2026-07-15T10:00:00Z",
            source_segment="guest",
            alert_type="DNS_FLOOD",
            severity=2,
            src_ip="10.2.1.50",
            dst_ip="10.0.1.2",
            signature_rule_triggered="IDS-DNS-007",
            raw_score=0.3,
        )
        ctx = EndpointContext(
            alert_id=alert_id,
            device_type="smartphone",
            os="iOS 16",
            patch_status="fully_patched",
            is_managed_device=True,
            user_type="guest",
            known_vuln_count=0,
        )
        db.add(alert)
        db.add(ctx)
        db.commit()

        result = get_recommendation(alert_id, db)
        db.close()

        assert result.recommendation_type == REC_SUGGEST_FP, (
            f"Expected {REC_SUGGEST_FP} for clean FP cluster, got {result.recommendation_type}."
        )


# ---------------------------------------------------------------------------
# F3: Novel TP Masquerading as Known FP Cluster
# ---------------------------------------------------------------------------

class TestF3NovelTPMasqueradingAsFP:
    """
    Failure Case F3: Alert matches FP cluster surface pattern but has
    anomalous endpoint context signals. Engine must NOT suggest FP.
    """

    def _seed_dns_fp_cluster(self, db, count: int = 25):
        """Seed a clean DNS_FLOOD/guest FP cluster (managed, patched, 0 vulns, internal dst)."""
        for i in range(count):
            alert_id = f"DNS-FP-HIST-{i:03d}"
            alert = Alert(
                alert_id=alert_id,
                timestamp="2026-07-01T10:00:00Z",
                source_segment="guest",
                alert_type="DNS_FLOOD",
                severity=2,
                src_ip="10.2.1.1",
                dst_ip="10.0.1.2",  # INTERNAL dns server
                signature_rule_triggered="IDS-DNS-007",
                raw_score=0.3,
            )
            ctx = EndpointContext(
                alert_id=alert_id,
                device_type="smartphone",
                os="iOS 16",
                patch_status="fully_patched",
                is_managed_device=True,
                user_type="guest",
                known_vuln_count=0,  # ZERO vulns
            )
            decision = AnalystDecision(
                alert_id=alert_id,
                analyst_id="ana_001",
                analyst_role="l1_analyst",
                disposition="false_positive",
                time_spent_minutes=5,
                decision_timestamp="2026-07-01T10:05:00Z",
                override_flag=False,
                override_reason=None,
            )
            db.add(alert)
            db.add(ctx)
            db.add(decision)
        db.commit()

    def test_anomaly_signals_prevent_fp_suggestion(self, in_memory_db):
        """
        GIVEN: DNS_FLOOD/guest has 25 FP history (clean cluster, fp_rate=1.0).
               New alert has: same alert_type, same segment
               BUT endpoint context: unmanaged, unpatched, known_vuln_count=5,
               dst_ip=8.8.8.8 (external).
        WHEN: get_recommendation() is called.
        THEN: recommendation_type == 'anomaly_signal_detected' (NOT 'suggest_fp')
              requires_human_confirmation == True
              anomaly_flags is non-empty and contains specific signal names
        """
        db = in_memory_db()
        self._seed_dns_fp_cluster(db, count=25)

        # Novel TP alert — same surface pattern, anomalous context
        alert_id = "TEST-F3-NOVEL-TP-001"
        novel_alert = Alert(
            alert_id=alert_id,
            timestamp="2026-07-20T14:00:00Z",
            source_segment="guest",     # SAME segment as FP cluster
            alert_type="DNS_FLOOD",     # SAME type as FP cluster
            severity=4,                 # slightly higher
            src_ip="10.2.9.9",
            dst_ip="8.8.8.8",           # EXTERNAL — key anomaly signal
            signature_rule_triggered="IDS-DNS-007",  # SAME rule as FP cluster
            raw_score=0.72,             # higher score
        )
        anomalous_ctx = EndpointContext(
            alert_id=alert_id,
            device_type="unknown",
            os="Unknown",
            patch_status="unpatched",   # ANOMALY: unpatched
            is_managed_device=False,    # ANOMALY: unmanaged
            user_type="guest",
            known_vuln_count=5,         # ANOMALY: high vuln count (threshold=2)
        )
        db.add(novel_alert)
        db.add(anomalous_ctx)
        db.commit()

        result = get_recommendation(alert_id, db)
        db.close()

        # Critical assertion: must NOT suggest FP
        assert result.recommendation_type != REC_SUGGEST_FP, (
            "CRITICAL FAILURE: Engine suggested FP for a novel TP with anomaly signals. "
            "This would cause a DNS-tunnelling C2 alert to be auto-closed. "
            f"Got recommendation_type={result.recommendation_type}, "
            f"anomaly_flags={result.anomaly_flags}"
        )

        assert result.recommendation_type == REC_ANOMALY, (
            f"Expected {REC_ANOMALY}, got {result.recommendation_type}."
        )
        assert result.requires_human_confirmation is True
        assert len(result.anomaly_flags) > 0, (
            "anomaly_flags must be non-empty for the novel TP case."
        )

        # Verify specific anomaly signals are detected
        flags_str = " ".join(result.anomaly_flags)
        assert "UNMANAGED_DEVICE" in flags_str, (
            f"Expected UNMANAGED_DEVICE flag. Got: {result.anomaly_flags}"
        )
        assert "UNPATCHED_DEVICE" in flags_str, (
            f"Expected UNPATCHED_DEVICE flag. Got: {result.anomaly_flags}"
        )
        assert "HIGH_VULN_COUNT" in flags_str, (
            f"Expected HIGH_VULN_COUNT flag. Got: {result.anomaly_flags}"
        )
        assert "EXTERNAL_DST_IP" in flags_str, (
            f"Expected EXTERNAL_DST_IP flag. Got: {result.anomaly_flags}"
        )

    def test_evidence_summary_explains_override(self, in_memory_db):
        """
        GIVEN: Novel TP scenario (same as above).
        WHEN: get_recommendation() is called.
        THEN: evidence_summary contains language about pattern matching FP cluster
              AND explains why it is escalated (anomaly signals override).
        """
        db = in_memory_db()
        self._seed_dns_fp_cluster(db, count=25)

        alert_id = "TEST-F3-EVIDENCE-001"
        novel_alert = Alert(
            alert_id=alert_id,
            timestamp="2026-07-21T14:00:00Z",
            source_segment="guest",
            alert_type="DNS_FLOOD",
            severity=4,
            src_ip="10.2.9.8",
            dst_ip="8.8.8.8",
            signature_rule_triggered="IDS-DNS-007",
            raw_score=0.70,
        )
        anomalous_ctx = EndpointContext(
            alert_id=alert_id,
            device_type="unknown",
            os="Unknown",
            patch_status="unpatched",
            is_managed_device=False,
            user_type="guest",
            known_vuln_count=4,
        )
        db.add(novel_alert)
        db.add(anomalous_ctx)
        db.commit()

        result = get_recommendation(alert_id, db)
        db.close()

        # Evidence summary should be human-readable and explanatory
        assert len(result.evidence_summary) > 20, "Evidence summary too short to be useful."
        # Should mention the FP cluster match AND the override
        summary_lower = result.evidence_summary.lower()
        assert "fp" in summary_lower or "false_positive" in summary_lower or "cluster" in summary_lower, (
            f"Evidence summary should mention FP pattern match: {result.evidence_summary}"
        )
        assert "anomaly" in summary_lower or "signal" in summary_lower or "escalat" in summary_lower, (
            f"Evidence summary should explain why escalating: {result.evidence_summary}"
        )

    def test_confidence_tier_is_low_for_novel_tp(self, in_memory_db):
        """
        GIVEN: Novel TP scenario.
        WHEN: get_recommendation() is called.
        THEN: confidence_tier == 'LOW' (not HIGH or MEDIUM).
              A borderline case should never get HIGH confidence.
        """
        db = in_memory_db()
        self._seed_dns_fp_cluster(db, count=25)

        alert_id = "TEST-F3-TIER-001"
        novel_alert = Alert(
            alert_id=alert_id,
            timestamp="2026-07-22T14:00:00Z",
            source_segment="guest",
            alert_type="DNS_FLOOD",
            severity=4,
            src_ip="10.2.9.7",
            dst_ip="8.8.8.8",
            signature_rule_triggered="IDS-DNS-007",
            raw_score=0.68,
        )
        anomalous_ctx = EndpointContext(
            alert_id=alert_id,
            device_type="unknown",
            os="Unknown",
            patch_status="unpatched",
            is_managed_device=False,
            user_type="guest",
            known_vuln_count=3,
        )
        db.add(novel_alert)
        db.add(anomalous_ctx)
        db.commit()

        result = get_recommendation(alert_id, db)
        db.close()

        assert result.confidence_tier == TIER_LOW, (
            f"Expected TIER_LOW for novel TP, got {result.confidence_tier}."
        )


# ---------------------------------------------------------------------------
# F4: Extreme Config Values — Safety Guardrails
# ---------------------------------------------------------------------------

class TestF4ExtremeConfigGuardrails:
    """
    Failure Case F4: Config values outside safety guardrails are clamped,
    not accepted silently, and not crashing the application.
    """

    def test_auto_suggest_threshold_below_floor_is_clamped(self, in_memory_db, tmp_path, monkeypatch):
        """
        GIVEN: config/rules.yaml has auto_suggest_threshold = 0.30 (below floor 0.60).
        WHEN: _validate_config_against_guardrails() is called.
        THEN: The returned config has auto_suggest_threshold = 0.60 (floor).
              A warning is included in the warnings list.
              No exception is raised.
        """
        from app.recommendation_engine import _validate_config_against_guardrails

        # Create a config dict with an extreme value
        extreme_cfg = {
            "auto_suggest_threshold": 0.30,  # BELOW floor (0.60)
            "max_allowed_miss_rate": 0.02,
            "evidence": {
                "min_evidence_count": 10,
                "min_fp_rate_for_suggestion": 0.80,
                "high_confidence_fp_threshold": 0.90,
                "lookback_window": 100,
            },
            "conflict": {"conflict_threshold": 2, "conflict_tp_fraction": 0.10},
            "anomaly_signals": {
                "known_vuln_count_threshold": 2,
                "unpatched_triggers_anomaly": True,
                "unmanaged_triggers_anomaly": True,
                "external_dst_ip_triggers_anomaly": True,
            },
            "high_impact_actions": ["auto_suppress"],
            "auto_suggest_eligible_alert_types": ["DNS_FLOOD"],
            "auto_suggest_excluded_alert_types": ["LATERAL_MOVE"],
            "role_permissions": {},
        }

        validated_cfg, warnings = _validate_config_against_guardrails(extreme_cfg)

        assert validated_cfg["auto_suggest_threshold"] == AUTO_SUGGEST_THRESHOLD_FLOOR, (
            f"Expected threshold to be clamped to {AUTO_SUGGEST_THRESHOLD_FLOOR}, "
            f"got {validated_cfg['auto_suggest_threshold']}."
        )
        assert len(warnings) >= 1, (
            "Expected at least 1 config warning when threshold is below floor."
        )
        config_rejected_in_warnings = any("CONFIG_REJECTED" in w for w in warnings)
        assert config_rejected_in_warnings, (
            f"Expected CONFIG_REJECTED in warnings, got: {warnings}"
        )

    def test_max_miss_rate_above_ceiling_is_clamped(self, in_memory_db):
        """
        GIVEN: config has max_allowed_miss_rate = 0.50 (above ceiling 0.10).
        WHEN: _validate_config_against_guardrails() is called.
        THEN: The returned config has max_allowed_miss_rate = 0.10 (ceiling).
              A CONFIG_REJECTED warning is issued.
        """
        from app.recommendation_engine import _validate_config_against_guardrails

        extreme_cfg = {
            "auto_suggest_threshold": 0.92,
            "max_allowed_miss_rate": 0.50,  # ABOVE ceiling (0.10)
            "evidence": {
                "min_evidence_count": 10,
                "min_fp_rate_for_suggestion": 0.80,
                "high_confidence_fp_threshold": 0.90,
                "lookback_window": 100,
            },
            "conflict": {"conflict_threshold": 2, "conflict_tp_fraction": 0.10},
            "anomaly_signals": {
                "known_vuln_count_threshold": 2,
                "unpatched_triggers_anomaly": True,
                "unmanaged_triggers_anomaly": True,
                "external_dst_ip_triggers_anomaly": True,
            },
            "high_impact_actions": ["auto_suppress"],
            "auto_suggest_eligible_alert_types": [],
            "auto_suggest_excluded_alert_types": [],
            "role_permissions": {},
        }

        validated_cfg, warnings = _validate_config_against_guardrails(extreme_cfg)

        assert validated_cfg["max_allowed_miss_rate"] == MAX_ALLOWED_MISS_RATE_CEILING, (
            f"Expected miss rate clamped to {MAX_ALLOWED_MISS_RATE_CEILING}, "
            f"got {validated_cfg['max_allowed_miss_rate']}."
        )
        assert any("CONFIG_REJECTED" in w for w in warnings), (
            "Expected CONFIG_REJECTED warning for miss rate above ceiling."
        )

    def test_guardrail_violation_does_not_crash_recommendation(self, in_memory_db, monkeypatch):
        """
        GIVEN: The config has auto_suggest_threshold = 0.10 (extremely low).
        WHEN: get_recommendation() is called for a normal alert.
        THEN: No exception is raised. The recommendation response includes
              config_warnings in evidence_detail.
        """
        db = in_memory_db()
        # Seed a normal FP cluster
        _seed_fp_cluster_history(db, "DNS_FLOOD", "guest", count=20)

        alert_id = "TEST-F4-GUARDRAIL-001"
        alert = Alert(
            alert_id=alert_id,
            timestamp="2026-07-15T10:00:00Z",
            source_segment="guest",
            alert_type="DNS_FLOOD",
            severity=2,
            src_ip="10.2.1.99",
            dst_ip="10.0.1.2",
            signature_rule_triggered="IDS-DNS-007",
            raw_score=0.3,
        )
        ctx = EndpointContext(
            alert_id=alert_id,
            device_type="laptop",
            os="Windows 10",
            patch_status="fully_patched",
            is_managed_device=True,
            user_type="guest",
            known_vuln_count=0,
        )
        db.add(alert)
        db.add(ctx)
        db.commit()

        # Monkeypatch get_config to return extreme config
        extreme_cfg = {
            "auto_suggest_threshold": 0.10,  # will be clamped to 0.60
            "max_allowed_miss_rate": 0.02,
            "evidence": {
                "min_evidence_count": 10,
                "min_fp_rate_for_suggestion": 0.80,
                "high_confidence_fp_threshold": 0.90,
                "lookback_window": 100,
            },
            "conflict": {"conflict_threshold": 2, "conflict_tp_fraction": 0.10},
            "anomaly_signals": {
                "known_vuln_count_threshold": 2,
                "unpatched_triggers_anomaly": True,
                "unmanaged_triggers_anomaly": True,
                "external_dst_ip_triggers_anomaly": True,
            },
            "high_impact_actions": ["auto_suppress"],
            "auto_suggest_eligible_alert_types": ["DNS_FLOOD"],
            "auto_suggest_excluded_alert_types": ["LATERAL_MOVE"],
            "role_permissions": {
                "l1_analyst": ["alerts:read", "alerts:recommend", "alerts:disposition", "view:l1"],
                "soc_lead": ["alerts:read", "alerts:read_all", "alerts:recommend",
                             "alerts:disposition", "config:read", "config:write",
                             "view:l1", "view:soc_lead", "actions:approve_high_impact"],
            },
        }

        import app.recommendation_engine as eng
        original_get_config = eng.get_config
        eng.get_config = lambda: extreme_cfg

        try:
            result = get_recommendation(alert_id, db)
        except Exception as e:
            pytest.fail(f"get_recommendation crashed with extreme config: {e}")
        finally:
            eng.get_config = original_get_config
            db.close()

        # Verify warning is in evidence_detail
        warnings = result.evidence_detail.get("config_warnings", [])
        assert len(warnings) > 0, (
            "Expected config_warnings in evidence_detail when guardrail was triggered."
        )

    def test_valid_override_reason_required(self, client, in_memory_db):
        """
        GIVEN: A POST /alerts/{id}/disposition with override_flag=True
               but override_reason is empty string.
        WHEN: The endpoint is called.
        THEN: HTTP 422 (Unprocessable Entity) is returned.
              Error message references override_reason requirement.
        """
        db_session = in_memory_db()
        alert_id = "TEST-F4-OVERRIDE-001"
        alert = Alert(
            alert_id=alert_id,
            timestamp="2026-07-15T10:00:00Z",
            source_segment="student",
            alert_type="PORT_SCAN",
            severity=3,
            src_ip="10.1.1.1",
            dst_ip="10.0.0.1",
            signature_rule_triggered="IDS-SCAN-003",
            raw_score=0.4,
        )
        db_session.add(alert)
        db_session.commit()
        db_session.close()

        def override_get_db():
            db = in_memory_db()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db

        response = client.post(
            f"/alerts/{alert_id}/disposition",
            headers={"x-analyst-role": "l1_analyst", "x-analyst-id": "ana_001"},
            json={
                "disposition": "false_positive",
                "override_flag": True,
                "override_reason": "",  # EMPTY — should be rejected
            },
        )

        assert response.status_code == 422, (
            f"Expected HTTP 422 for missing override_reason, got {response.status_code}: {response.text}"
        )
        error_detail = str(response.json())
        assert "override_reason" in error_detail.lower() or "override" in error_detail.lower(), (
            f"Error message should mention override_reason requirement: {response.json()}"
        )

    def test_role_access_control_l1_cannot_access_config(self, client):
        """
        GIVEN: An L1 analyst attempts to access GET /config/rules.
        WHEN: The request is made with x-analyst-role=l1_analyst.
        THEN: HTTP 403 Forbidden.
        """
        response = client.get(
            "/config/rules",
            headers={"x-analyst-role": "l1_analyst", "x-analyst-id": "ana_001"},
        )
        assert response.status_code == 403, (
            f"Expected HTTP 403 for L1 accessing config, got {response.status_code}."
        )
