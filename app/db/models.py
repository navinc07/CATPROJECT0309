"""
app/db/models.py
================
SQLAlchemy ORM models — the database schema for the SOC assistant.

WHY THESE TABLES:
    The four tables mirror the four CSV datasets exactly, with one addition:
    the recommendations table captures every recommendation the assistant makes.
    This is critical for Phase 2: the training data for the learned model
    comes from (recommendation, analyst_decision) pairs where the analyst
    either accepted or overrode the recommendation. Without this table, we
    cannot measure recommendation quality or train a better model.

    The override_log view (embedded in analyst_decisions) captures WHY
    analysts disagree — this is qualitative training signal for Phase 2.
"""

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey
)
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from app.db.database import Base


class Alert(Base):
    """
    Mirrors alerts.csv. Primary record for each IDS/SIEM alert.
    source_segment is load-bearing: the recommendation engine uses it to
    look up the segment-specific FP rate, not just the global rate.
    """
    __tablename__ = "alerts"

    alert_id = Column(String, primary_key=True, index=True)
    timestamp = Column(String, nullable=False)
    source_segment = Column(String, nullable=False, index=True)
    alert_type = Column(String, nullable=False, index=True)
    severity = Column(Integer, nullable=False)
    src_ip = Column(String, nullable=False)
    dst_ip = Column(String, nullable=False)
    signature_rule_triggered = Column(String, nullable=False)
    raw_score = Column(Float, nullable=False)

    # Relationships (lazy-loaded for performance)
    decisions = relationship("AnalystDecision", back_populates="alert")
    endpoint_context = relationship("EndpointContext", back_populates="alert", uselist=False)
    incident_label = relationship("IncidentLabel", back_populates="alert", uselist=False)
    recommendations = relationship("Recommendation", back_populates="alert")


class AnalystDecision(Base):
    """
    Mirrors analyst_decisions.csv. Every analyst action on an alert.
    override_flag + override_reason are the key fields for the Phase 2
    learning component — they capture when and why analysts disagree with
    the assistant.

    ENFORCEMENT NOTE: The API (app/main.py) refuses to write a decision
    with override_flag=True and override_reason=None or empty string.
    This is enforced at the FastAPI layer, not the DB layer, because the
    DB needs to store historical data from before this requirement existed.
    """
    __tablename__ = "analyst_decisions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String, ForeignKey("alerts.alert_id"), nullable=False, index=True)
    analyst_id = Column(String, nullable=False, index=True)
    analyst_role = Column(String, nullable=False)
    disposition = Column(String, nullable=False)  # false_positive / true_positive / escalated
    time_spent_minutes = Column(Integer, nullable=True)
    decision_timestamp = Column(String, nullable=False)
    override_flag = Column(Boolean, default=False, nullable=False)
    override_reason = Column(Text, nullable=True)  # Required when override_flag=True (enforced at API level)

    alert = relationship("Alert", back_populates="decisions")


class EndpointContext(Base):
    """
    Mirrors endpoint_context.csv. Device/user context for each alert.

    NULLABLE FIELDS: is_managed_device and known_vuln_count can be None
    when the device is not in the university's MDM/asset inventory (e.g.,
    guest BYOD devices). The recommendation engine treats None as an
    anomaly signal (failure case F1: missing context).
    """
    __tablename__ = "endpoint_context"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String, ForeignKey("alerts.alert_id"), nullable=False, unique=True, index=True)
    device_type = Column(String, nullable=True)
    os = Column(String, nullable=True)
    patch_status = Column(String, nullable=True)  # fully_patched / partially_patched / unpatched / unknown
    is_managed_device = Column(Boolean, nullable=True)  # None = unknown
    user_type = Column(String, nullable=True)  # student / guest / faculty / lab_admin / unknown
    known_vuln_count = Column(Integer, nullable=True)  # None = scanner could not reach device

    alert = relationship("Alert", back_populates="endpoint_context")


class IncidentLabel(Base):
    """
    Mirrors incident_labels.csv. Ground-truth label for confirmed incidents.
    confirmed_by is always an L2 (SOC Lead) analyst_id — L1 cannot confirm incidents.
    """
    __tablename__ = "incident_labels"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String, ForeignKey("alerts.alert_id"), nullable=False, unique=True, index=True)
    confirmed_incident = Column(Boolean, nullable=False, default=False)
    incident_category = Column(String, nullable=True)
    confirmed_by = Column(String, nullable=True)
    confirmation_date = Column(String, nullable=True)

    alert = relationship("Alert", back_populates="incident_label")


class Recommendation(Base):
    """
    Every recommendation the assistant makes, with its full evidence trail.
    This table does NOT exist in the CSV files — it is new in the app layer.

    WHY THIS TABLE IS CRITICAL:
        - Provides the Phase 2 training dataset: (recommendation, outcome) pairs.
        - Enables the SOC Lead's override audit view.
        - Makes the assistant's reasoning auditable retrospectively.
        - Supports the explainability requirement: evidence_detail stores the
          exact rule and counts behind every recommendation.

    FIELDS:
        recommendation_type: suggest_fp / suggest_tp / escalate / insufficient_evidence
        confidence_tier: HIGH / MEDIUM / LOW / INSUFFICIENT_EVIDENCE
        confidence_score: float 0-1 (fraction of similar cases that were FP)
        evidence_detail: JSON string with the full evidence (pattern, count, rate, anomalies)
        requires_human_confirmation: True if action is high-impact
        anomaly_flags: JSON list of anomaly signals detected (empty if none)
        pattern_key: the lookup key used (e.g., "DNS_FLOOD::guest") for auditability
    """
    __tablename__ = "recommendations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String, ForeignKey("alerts.alert_id"), nullable=False, index=True)
    recommendation_type = Column(String, nullable=False)
    confidence_tier = Column(String, nullable=False)
    confidence_score = Column(Float, nullable=True)
    evidence_detail = Column(Text, nullable=False)  # JSON string
    requires_human_confirmation = Column(Boolean, nullable=False, default=False)
    anomaly_flags = Column(Text, nullable=True)      # JSON list string
    pattern_key = Column(String, nullable=True)       # e.g., "DNS_FLOOD::guest"
    created_at = Column(String, nullable=False,
                        default=lambda: datetime.now(timezone.utc).isoformat())
    rule_triggered = Column(String, nullable=True)    # which config rule triggered this
    auto_suggest_eligible = Column(Boolean, nullable=False, default=False)

    alert = relationship("Alert", back_populates="recommendations")
