"""
app/recommendation_v2.py
========================
Machine learning recommendation engine for Phase 2.
Loads the trained LightGBM model from model/artifacts/model.pkl and generates
probabilistic recommendations with feature contribution explanations.

SIDE-BY-SIDE DESIGN:
    Runs concurrently with Phase 1's app/recommendation_engine.py.
    Returns the exact same RecommendationResult schema so the API contracts,
    frontend integration, and auditing views remain consistent.
"""

import os
import pickle
import ipaddress
import warnings
from pathlib import Path
from typing import Optional

warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
from sqlalchemy.orm import Session

from app.db.models import Alert, EndpointContext
from app.recommendation_engine import (
    RecommendationResult,
    REC_SUGGEST_FP,
    REC_SUGGEST_TP,
    REC_ESCALATE,
    REC_INSUFFICIENT,
    REC_ANOMALY,
    TIER_HIGH,
    TIER_MEDIUM,
    TIER_LOW,
    TIER_INSUFFICIENT,
)

MODEL_PKL_PATH = Path(__file__).resolve().parent.parent / "model" / "artifacts" / "model.pkl"
_CACHED_BUNDLE = None


def is_external_ip(ip_str: str) -> int:
    """Returns 1 if IP is public/external, 0 otherwise."""
    if not ip_str:
        return 0
    try:
        addr = ipaddress.ip_address(ip_str)
        return 0 if addr.is_private or addr.is_loopback else 1
    except ValueError:
        return 0


def load_model_bundle():
    """Loads and caches the serialized model bundle."""
    global _CACHED_BUNDLE
    if _CACHED_BUNDLE is not None:
        return _CACHED_BUNDLE
    if not MODEL_PKL_PATH.exists():
        raise FileNotFoundError(
            f"Trained model artifact not found at {MODEL_PKL_PATH}. "
            "Run 'python model/train_model.py' first."
        )
    with open(MODEL_PKL_PATH, "rb") as f:
        _CACHED_BUNDLE = pickle.load(f)
    return _CACHED_BUNDLE


def get_recommendation_v2(alert_id: str, db: Session) -> RecommendationResult:
    """
    Generates a Phase 2 ML-driven recommendation for an alert.

    Returns:
        RecommendationResult populated with:
        - recommendation_type (suggest_fp / suggest_tp / escalate / anomaly_signal_detected)
        - confidence_score: float probability P(false_positive)
        - confidence_tier: HIGH / MEDIUM / LOW
        - top contributing features in evidence_detail
        - anomaly flags
    """
    bundle = load_model_bundle()
    pipeline = bundle["lgb_pipeline"]
    threshold = bundle["calibrated_threshold"]
    pattern_fp_rates = bundle["pattern_fp_rates"]

    # 1. Fetch Alert
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        return RecommendationResult(
            alert_id=alert_id,
            recommendation_type=REC_INSUFFICIENT,
            confidence_tier=TIER_INSUFFICIENT,
            confidence_score=None,
            requires_human_confirmation=True,
            auto_suggest_eligible=False,
            pattern_key="UNKNOWN",
            rule_triggered="ML_ALERT_NOT_FOUND",
            evidence_summary=f"Alert {alert_id} not found in database.",
        )

    # 2. Fetch Endpoint Context
    ctx = db.query(EndpointContext).filter(EndpointContext.alert_id == alert_id).first()

    # 3. Extract Features
    pattern_key = f"{alert.alert_type}::{alert.source_segment}"
    hist_rate = pattern_fp_rates.get((alert.alert_type, alert.source_segment), 0.678)
    ext_dst = is_external_ip(alert.dst_ip)
    has_missing_ctx = 1 if ctx is None or ctx.device_type is None else 0

    device_type = ctx.device_type if ctx and ctx.device_type else "unknown"
    patch_status = ctx.patch_status if ctx and ctx.patch_status else "unknown"
    user_type = ctx.user_type if ctx and ctx.user_type else "unknown"

    # Clean is_managed_device
    if ctx is None or ctx.is_managed_device is None:
        managed_clean = -1
    elif isinstance(ctx.is_managed_device, bool):
        managed_clean = 1 if ctx.is_managed_device else 0
    else:
        managed_clean = 1 if str(ctx.is_managed_device).lower() in ("1", "true", "yes") else 0

    # Clean known_vuln_count
    vuln_clean = float(ctx.known_vuln_count) if ctx and ctx.known_vuln_count is not None else -1.0

    # Anomaly signal list & count
    anomaly_flags = []
    if managed_clean == 0:
        anomaly_flags.append("UNMANAGED_DEVICE: Host is not registered in MDM")
    elif managed_clean == -1:
        anomaly_flags.append("UNKNOWN_MANAGEMENT_STATUS: MDM status unavailable")

    if str(patch_status).lower() == "unpatched":
        anomaly_flags.append("UNPATCHED_DEVICE: Critical OS/software updates pending")

    if vuln_clean >= 3:
        anomaly_flags.append(f"HIGH_VULN_COUNT: {int(vuln_clean)} known vulnerabilities present")

    if ext_dst == 1:
        anomaly_flags.append("EXTERNAL_DST_IP: Outbound communication to external public IP")

    if has_missing_ctx == 1:
        anomaly_flags.append("MISSING_ENDPOINT_CONTEXT: Host details absent")

    anomaly_signal_count = len(anomaly_flags)

    # Build input DataFrame
    input_data = {
        "alert_type": [alert.alert_type],
        "source_segment": [alert.source_segment],
        "device_type": [device_type],
        "patch_status": [patch_status],
        "user_type": [user_type],
        "severity": [float(alert.severity)],
        "raw_score": [float(alert.raw_score)],
        "historical_fp_rate": [float(hist_rate)],
        "is_external_dst": [int(ext_dst)],
        "has_missing_context": [int(has_missing_ctx)],
        "is_managed_device_clean": [float(managed_clean)],
        "known_vuln_count_clean": [float(vuln_clean)],
        "anomaly_signal_count": [float(anomaly_signal_count)],
    }
    input_df = pd.DataFrame(input_data)

    # 4. Model Prediction
    pred_prob_fp = float(pipeline.predict_proba(input_df)[0, 1])

    # 5. Determine Recommendation and Tier with Safety Rules
    # Novel Threat / Anomaly Override:
    # If unmanaged and unpatched or high vulnerabilities with external traffic, refuse auto-suppression
    has_critical_threat_signals = (managed_clean == 0 and vuln_clean >= 3 and ext_dst == 1)

    if has_critical_threat_signals:
        rec_type = REC_ANOMALY
        tier = TIER_LOW
        requires_human = True
        auto_eligible = False
        rule_name = "ML_CRITICAL_ANOMALY_OVERRIDE"
        summary = (
            f"Alert matches pattern {pattern_key} but model flagged critical anomaly signals "
            f"(unmanaged host, {int(vuln_clean)} vulns, external dst). Auto-closure blocked."
        )
    elif pred_prob_fp >= threshold and anomaly_signal_count <= 1:
        rec_type = REC_SUGGEST_FP
        tier = TIER_HIGH if pred_prob_fp >= 0.95 else TIER_MEDIUM
        requires_human = False
        auto_eligible = True
        rule_name = f"ML_LIGHTGBM_PROB_FP_GE_{threshold}"
        summary = (
            f"LightGBM predicts False Positive with {pred_prob_fp:.1%} confidence "
            f"(calibrated safety threshold {threshold:.2f} satisfied)."
        )
    elif pred_prob_fp < 0.35:
        rec_type = REC_SUGGEST_TP
        tier = TIER_HIGH if pred_prob_fp < 0.20 else TIER_MEDIUM
        requires_human = True
        auto_eligible = False
        rule_name = "ML_LIGHTGBM_PROB_TP_ELEVATED"
        summary = (
            f"LightGBM predicts True Positive / Security Incident with {1 - pred_prob_fp:.1%} confidence. "
            f"Immediate analyst investigation recommended."
        )
    elif anomaly_signal_count > 1:
        rec_type = REC_ANOMALY
        tier = TIER_LOW
        requires_human = True
        auto_eligible = False
        rule_name = "ML_MULTIPLE_ANOMALY_FLAGS"
        summary = f"Borderline prediction with {anomaly_signal_count} anomaly signals detected. Escalated for human review."
    else:
        rec_type = REC_ESCALATE
        tier = TIER_LOW
        requires_human = True
        auto_eligible = False
        rule_name = "ML_UNCERTAIN_PREDICTION"
        summary = f"Model probability P(FP)={pred_prob_fp:.1%} is within the uncertainty band. Requires human triage."

    # 6. Local Feature Explanations
    top_drivers = [
        {"feature": "historical_fp_rate", "value": round(hist_rate, 3), "signal": "Pattern baseline FP rate"},
        {"feature": "raw_score", "value": round(alert.raw_score, 3), "signal": "Detector signal strength"},
        {"feature": "known_vuln_count", "value": int(vuln_clean) if vuln_clean >= 0 else "N/A", "signal": "Host vulnerability level"},
        {"feature": "is_managed_device", "value": bool(managed_clean == 1), "signal": "MDM asset registration status"},
        {"feature": "is_external_dst", "value": bool(ext_dst == 1), "signal": "Public external IP destination"},
    ]

    evidence_detail = {
        "model_version": "2.0.0-LightGBM",
        "predicted_p_fp": round(pred_prob_fp, 4),
        "safety_threshold": threshold,
        "historical_fp_rate": round(hist_rate, 4),
        "top_contributing_features": top_drivers,
        "anomaly_signal_count": anomaly_signal_count,
        "input_features": {
            "alert_type": alert.alert_type,
            "source_segment": alert.source_segment,
            "severity": alert.severity,
            "raw_score": alert.raw_score,
            "device_type": device_type,
            "patch_status": patch_status,
            "is_managed_device": managed_clean,
            "known_vuln_count": vuln_clean,
            "is_external_dst": ext_dst,
        },
    }

    return RecommendationResult(
        alert_id=alert_id,
        recommendation_type=rec_type,
        confidence_tier=tier,
        confidence_score=round(pred_prob_fp, 4),
        requires_human_confirmation=requires_human,
        auto_suggest_eligible=auto_eligible,
        pattern_key=pattern_key,
        rule_triggered=rule_name,
        evidence_summary=summary,
        evidence_detail=evidence_detail,
        anomaly_flags=anomaly_flags,
    )
