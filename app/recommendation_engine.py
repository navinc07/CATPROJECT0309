"""
app/recommendation_engine.py
=============================
Rule-based recommendation engine for Phase 1.

WHY RULE-BASED (not ML) IN PHASE 1:
    The problem statement explicitly requires a baseline that the Phase 2
    learned model must BEAT. If we skip straight to ML, we have no reference
    point to prove that ML adds value. This rule-based engine:
    (a) Is fully explainable — every recommendation cites specific evidence.
    (b) Establishes a legitimate "before" state for the Phase 2 comparison.
    (c) Demonstrates that even a simple rule-based system reduces FP workload
        significantly, contextualising the ML improvement in Phase 2.

THE CORE ALGORITHM:
    1. Look up the (alert_type, source_segment) pattern in historical decisions.
    2. Compute the FP rate: fp_count / total_count for the last N cases.
    3. Check for anomaly signals in endpoint_context.
    4. Apply config thresholds to produce a recommendation + confidence tier.
    5. Check if the pattern has conflicting evidence (TP and FP decisions).
    6. If action is high-impact, set requires_human_confirmation = True always.

HARD-CODED SAFETY GUARDRAILS (non-configurable by design):
    These are deliberately NOT in config/rules.yaml. They are permanent
    safety rails that no SOC Lead should be able to disable:

    1. AUTO_SUGGEST_THRESHOLD_FLOOR = 0.60
       The assistant will never auto-suggest FP with confidence < 60%,
       regardless of what the config says. Below 60% is coin-flip territory.

    2. MAX_ALLOWED_MISS_RATE_CEILING = 0.10
       The assistant will refuse to operate at a config-specified miss rate
       above 10%. Above 10%, the assistant is missing more than 1 in 10
       real incidents — unacceptable for a security tool.

    3. HIGH_IMPACT_ACTIONS always require human confirmation.
       No confidence score, no matter how high, can override this.
       It is enforced by the literal code path, not by a threshold check.

    These guardrails are documented here and in tests/failure_cases.md (F4).

PHASE 2 NOTE:
    In Phase 2, this engine will be replaced or augmented by a trained
    classifier (e.g., gradient-boosted trees or logistic regression) that
    learns from analyst_decisions. The interface (RecommendationResult) will
    remain identical so that the API layer and tests do not need to change.
    The Phase 2 model must beat this rule-based baseline on:
    - FP hours saved (efficiency)
    - Miss rate at the same confidence threshold (safety)
    Both metrics are computed in baseline/compute_baseline.py.
"""

import json
import ipaddress
from dataclasses import dataclass, field, asdict
from typing import Optional
from sqlalchemy.orm import Session

from app.db.models import Alert, AnalystDecision, EndpointContext
from app.config_loader import get_config

# ---------------------------------------------------------------------------
# Non-configurable safety guardrails (see module docstring for rationale)
# ---------------------------------------------------------------------------
AUTO_SUGGEST_THRESHOLD_FLOOR: float = 0.60   # Hard floor — not configurable
MAX_ALLOWED_MISS_RATE_CEILING: float = 0.10  # Hard ceiling — not configurable

# Recommendation type constants
REC_SUGGEST_FP = "suggest_fp"
REC_SUGGEST_TP = "suggest_tp"
REC_ESCALATE = "escalate"
REC_INSUFFICIENT = "insufficient_evidence"
REC_ANOMALY = "anomaly_signal_detected"
REC_CONFLICT = "conflicting_evidence"

# Confidence tier constants
TIER_HIGH = "HIGH"
TIER_MEDIUM = "MEDIUM"
TIER_LOW = "LOW"
TIER_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"


@dataclass
class RecommendationResult:
    """
    The full output of the recommendation engine for a single alert.

    EXPLAINABILITY REQUIREMENT: Every field in this dataclass is either
    directly human-readable or maps to a human-readable evidence entry.
    No field is a black-box score without context.
    """
    alert_id: str
    recommendation_type: str            # REC_* constant
    confidence_tier: str                # TIER_* constant
    confidence_score: Optional[float]   # float 0-1, or None if insufficient
    requires_human_confirmation: bool   # Always True for high-impact actions
    auto_suggest_eligible: bool         # Whether alert type is in whitelist
    pattern_key: str                    # e.g., "DNS_FLOOD::guest"
    rule_triggered: str                 # which rule/check produced this rec.

    # Human-readable evidence trail — this is the explainability output.
    # Every recommendation must populate this with specific counts/rates.
    evidence_summary: str               # One-sentence plain-English summary
    evidence_detail: dict = field(default_factory=dict)  # Structured detail

    # Anomaly signals detected (empty list if none)
    anomaly_flags: list = field(default_factory=list)

    def to_api_response(self) -> dict:
        """Convert to the API JSON response format."""
        return {
            "alert_id": self.alert_id,
            "recommendation": self.recommendation_type,
            "confidence": {
                "tier": self.confidence_tier,
                "score": self.confidence_score,
            },
            "requires_human_confirmation": self.requires_human_confirmation,
            "auto_suggest_eligible": self.auto_suggest_eligible,
            "explainability": {
                "rule_triggered": self.rule_triggered,
                "evidence_summary": self.evidence_summary,
                "evidence_detail": self.evidence_detail,
                "anomaly_flags": self.anomaly_flags,
                "pattern_key": self.pattern_key,
            },
            "phase1_note": (
                "This recommendation is produced by the Phase 1 rule-based engine. "
                "It is intentionally simple and explainable. Phase 2 will replace "
                "or augment this with a trained classifier."
            ),
        }

    def to_db_dict(self) -> dict:
        """Convert to fields for storing in the Recommendation model."""
        return {
            "recommendation_type": self.recommendation_type,
            "confidence_tier": self.confidence_tier,
            "confidence_score": self.confidence_score,
            "evidence_detail": json.dumps(self.evidence_detail),
            "requires_human_confirmation": self.requires_human_confirmation,
            "anomaly_flags": json.dumps(self.anomaly_flags),
            "pattern_key": self.pattern_key,
            "rule_triggered": self.rule_triggered,
            "auto_suggest_eligible": self.auto_suggest_eligible,
        }


def _is_external_ip(ip_str: str) -> bool:
    """
    Check if an IP address is external (not RFC1918 private).
    Used to detect anomalous dst_ip in alerts that historically
    only connected to internal addresses.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return not addr.is_private
    except ValueError:
        return False


def _get_pattern_history(
    db: Session,
    alert_type: str,
    source_segment: str,
    lookback: int,
) -> dict:
    """
    Query historical analyst decisions for the (alert_type, source_segment) pattern.

    Returns:
        {
            "total": int,
            "fp_count": int,
            "tp_count": int,
            "escalated_count": int,
            "fp_rate": float,
            "tp_rate": float,
        }

    WHY QUERY BY PATTERN (not by alert_id):
        The whole point of the rule-based engine is to generalise from past
        cases of similar patterns to the current alert. Looking up by alert_id
        would only find exact matches (useless). Pattern lookup is what makes
        this a "learning from history" system.
    """
    # Join Alert → AnalystDecision to get decisions for matching pattern
    rows = (
        db.query(AnalystDecision.disposition)
        .join(Alert, AnalystDecision.alert_id == Alert.alert_id)
        .filter(
            Alert.alert_type == alert_type,
            Alert.source_segment == source_segment,
        )
        .order_by(AnalystDecision.id.desc())  # most recent first
        .limit(lookback)
        .all()
    )

    total = len(rows)
    fp_count = sum(1 for r in rows if r.disposition == "false_positive")
    tp_count = sum(1 for r in rows if r.disposition == "true_positive")
    esc_count = sum(1 for r in rows if r.disposition == "escalated")

    return {
        "total": total,
        "fp_count": fp_count,
        "tp_count": tp_count,
        "escalated_count": esc_count,
        "fp_rate": fp_count / total if total > 0 else 0.0,
        "tp_rate": tp_count / total if total > 0 else 0.0,
    }


def _detect_anomaly_signals(
    ctx: Optional[EndpointContext],
    alert: Alert,
    cfg: dict,
) -> list[str]:
    """
    Detect endpoint anomaly signals that should override a confident FP suggestion.

    This is the critical logic for the novel-TP preservation requirement.
    Returns a list of human-readable anomaly flag strings.
    If empty: no anomalies detected.
    If non-empty: the recommendation must be ESCALATE, not suggest_fp.

    WHY THESE SIGNALS:
        These signals were deliberately absent from the FP clusters (§4.2-4.3
        of data/README_dataset.md) but present in the novel TP (§4.4).
        They are the distinguishing features the engine uses to override a
        naive "pattern matches FP cluster → suggest FP" conclusion.
    """
    anomaly_cfg = cfg.get("anomaly_signals", {})
    flags = []

    if ctx is None:
        # No endpoint context at all — this is failure case F1
        flags.append(
            "MISSING_ENDPOINT_CONTEXT: No endpoint context record found for this alert. "
            "Cannot verify device state. Confidence degraded."
        )
        return flags

    # Check 1: Unknown/unmanaged device
    if anomaly_cfg.get("unmanaged_triggers_anomaly", True):
        if ctx.is_managed_device is False:
            flags.append(
                "UNMANAGED_DEVICE: Device is not in university MDM/inventory. "
                "Historical FP cases for this pattern all involved managed devices."
            )
        elif ctx.is_managed_device is None:
            flags.append(
                "UNKNOWN_MANAGEMENT_STATUS: is_managed_device is null (device not in MDM). "
                "Cannot confirm device is managed. Confidence degraded."
            )

    # Check 2: Unpatched device
    if anomaly_cfg.get("unpatched_triggers_anomaly", True):
        if ctx.patch_status == "unpatched":
            flags.append(
                "UNPATCHED_DEVICE: Device patch_status is 'unpatched'. "
                "Historical FP cases for this pattern had fully or partially patched devices."
            )

    # Check 3: High vulnerability count
    vuln_threshold = anomaly_cfg.get("known_vuln_count_threshold", 2)
    if ctx.known_vuln_count is None:
        flags.append(
            "UNKNOWN_VULN_COUNT: Vulnerability count unavailable (scanner could not reach device). "
            "Cannot assess risk posture."
        )
    elif ctx.known_vuln_count >= vuln_threshold:
        flags.append(
            f"HIGH_VULN_COUNT: Device has {ctx.known_vuln_count} known vulnerabilities "
            f"(threshold: {vuln_threshold}). Historical FP cases had known_vuln_count=0."
        )

    # Check 4: External destination IP
    if anomaly_cfg.get("external_dst_ip_triggers_anomaly", True):
        if _is_external_ip(alert.dst_ip):
            flags.append(
                f"EXTERNAL_DST_IP: Destination IP {alert.dst_ip} is external (non-private). "
                "Historical FP cases for this pattern all used internal dst_ips (captive portal DNS). "
                "External dst_ip suggests potential DNS tunnelling or C2 communication."
            )

    return flags


def _determine_confidence_tier(fp_rate: float, cfg: dict) -> str:
    """Map a numeric FP rate to a confidence tier string using config thresholds."""
    high_threshold = cfg["evidence"]["high_confidence_fp_threshold"]
    min_threshold = cfg["evidence"]["min_fp_rate_for_suggestion"]

    if fp_rate >= high_threshold:
        return TIER_HIGH
    elif fp_rate >= min_threshold:
        return TIER_MEDIUM
    else:
        return TIER_LOW


def _check_auto_suggest_eligible(alert_type: str, cfg: dict) -> bool:
    """Check if this alert type is in the auto-suggest whitelist from config."""
    eligible = cfg.get("auto_suggest_eligible_alert_types", [])
    excluded = cfg.get("auto_suggest_excluded_alert_types", [])
    if alert_type in excluded:
        return False
    return alert_type in eligible


def _requires_confirmation(action_type: str, cfg: dict) -> bool:
    """
    Check if an action requires SOC Lead human confirmation.

    HARD RULE (non-configurable): High-impact actions ALWAYS require confirmation.
    This function checks the config list, but the check_high_impact path in
    get_recommendation() enforces this regardless of any config override attempt.
    """
    high_impact = cfg.get("high_impact_actions", [])
    return action_type in high_impact


def _validate_config_against_guardrails(cfg: dict) -> tuple[dict, list[str]]:
    """
    Validate config values against hard-coded safety guardrails.

    Returns (validated_cfg, warnings_list).
    Warnings are returned so they can be logged and surfaced to the SOC Lead.

    This is failure case F4: extreme config values are rejected silently
    at this layer, and the system operates at the guardrail value instead.
    """
    warnings = []
    cfg = dict(cfg)  # shallow copy to avoid mutating the loaded config

    # Validate auto_suggest_threshold >= floor
    threshold = cfg.get("auto_suggest_threshold", AUTO_SUGGEST_THRESHOLD_FLOOR)
    if threshold < AUTO_SUGGEST_THRESHOLD_FLOOR:
        warnings.append(
            f"CONFIG_REJECTED: auto_suggest_threshold={threshold} is below the "
            f"hard safety floor ({AUTO_SUGGEST_THRESHOLD_FLOOR}). "
            f"Using floor value {AUTO_SUGGEST_THRESHOLD_FLOOR}. "
            "This floor is non-configurable. See app/recommendation_engine.py."
        )
        cfg["auto_suggest_threshold"] = AUTO_SUGGEST_THRESHOLD_FLOOR

    # Validate max_allowed_miss_rate <= ceiling
    miss_rate = cfg.get("max_allowed_miss_rate", 0.02)
    if miss_rate > MAX_ALLOWED_MISS_RATE_CEILING:
        warnings.append(
            f"CONFIG_REJECTED: max_allowed_miss_rate={miss_rate} exceeds the "
            f"hard safety ceiling ({MAX_ALLOWED_MISS_RATE_CEILING}). "
            f"Using ceiling value {MAX_ALLOWED_MISS_RATE_CEILING}. "
            "This ceiling is non-configurable. See app/recommendation_engine.py."
        )
        cfg["max_allowed_miss_rate"] = MAX_ALLOWED_MISS_RATE_CEILING

    return cfg, warnings


def get_recommendation(
    alert_id: str,
    db: Session,
) -> RecommendationResult:
    """
    Main entry point: compute and return a recommendation for a single alert.

    This function orchestrates all checks in order:
    1. Load alert + endpoint context from DB.
    2. Validate config (guardrail check).
    3. Get pattern history.
    4. Check failure cases (missing context, conflict, novel TP anomaly).
    5. Apply evidence thresholds to produce recommendation.
    6. Determine if human confirmation required.
    7. Return structured RecommendationResult.

    Every early-return path produces a full RecommendationResult with a
    complete evidence_detail — there is no path that returns a bare score.
    """
    # --- Load config (from file, runtime-editable by SOC Lead) ---
    raw_cfg = get_config()
    cfg, config_warnings = _validate_config_against_guardrails(raw_cfg)

    # --- Load alert ---
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if alert is None:
        return RecommendationResult(
            alert_id=alert_id,
            recommendation_type=REC_INSUFFICIENT,
            confidence_tier=TIER_INSUFFICIENT,
            confidence_score=None,
            requires_human_confirmation=True,
            auto_suggest_eligible=False,
            pattern_key="UNKNOWN",
            rule_triggered="ALERT_NOT_FOUND",
            evidence_summary=f"Alert {alert_id} not found in database.",
            evidence_detail={"error": "alert_not_found"},
            anomaly_flags=[],
        )

    pattern_key = f"{alert.alert_type}::{alert.source_segment}"

    # --- Load endpoint context (may be None — failure case F1) ---
    ctx = db.query(EndpointContext).filter(
        EndpointContext.alert_id == alert_id
    ).first()

    # --- Check auto-suggest eligibility ---
    eligible = _check_auto_suggest_eligible(alert.alert_type, cfg)

    # --- Get historical pattern data ---
    lookback = cfg["evidence"]["lookback_window"]
    history = _get_pattern_history(
        db, alert.alert_type, alert.source_segment, lookback
    )

    min_evidence = cfg["evidence"]["min_evidence_count"]

    # --- FAILURE CASE F1: Missing endpoint context ---
    anomaly_flags = _detect_anomaly_signals(ctx, alert, cfg)
    missing_context = ctx is None or (
        "MISSING_ENDPOINT_CONTEXT" in " ".join(anomaly_flags)
    )

    if missing_context:
        # Cannot make a confident recommendation without endpoint context.
        # The system degrades gracefully: low confidence, human review required.
        return RecommendationResult(
            alert_id=alert_id,
            recommendation_type=REC_INSUFFICIENT,
            confidence_tier=TIER_INSUFFICIENT,
            confidence_score=None,
            requires_human_confirmation=True,
            auto_suggest_eligible=eligible,
            pattern_key=pattern_key,
            rule_triggered="MISSING_ENDPOINT_CONTEXT",
            evidence_summary=(
                f"No endpoint context for {alert_id}. Cannot verify device state. "
                "Recommendation withheld — human review required."
            ),
            evidence_detail={
                "pattern_key": pattern_key,
                "history": history,
                "reason": "Endpoint context record absent or incomplete. "
                          "The recommendation engine requires endpoint context to detect "
                          "anomaly signals (unpatched device, unmanaged device, etc). "
                          "Without it, the risk of missing a novel threat is too high.",
                "config_warnings": config_warnings,
            },
            anomaly_flags=anomaly_flags,
        )

    # --- FAILURE CASE F2: Conflicting analyst history ---
    conflict_threshold = cfg["conflict"]["conflict_threshold"]
    conflict_tp_fraction = cfg["conflict"]["conflict_tp_fraction"]

    tp_count = history["tp_count"]
    total_count = history["total"]
    tp_fraction = history["tp_rate"]

    if tp_count >= conflict_threshold and tp_fraction >= conflict_tp_fraction:
        return RecommendationResult(
            alert_id=alert_id,
            recommendation_type=REC_CONFLICT,
            confidence_tier=TIER_INSUFFICIENT,
            confidence_score=history["fp_rate"],
            requires_human_confirmation=True,
            auto_suggest_eligible=eligible,
            pattern_key=pattern_key,
            rule_triggered="CONFLICTING_ANALYST_HISTORY",
            evidence_summary=(
                f"Pattern {pattern_key} has conflicting analyst history: "
                f"{history['fp_count']} FP decisions AND {tp_count} TP decisions "
                f"in the last {total_count} cases. Auto-suggestion disabled. "
                "SOC Lead review recommended."
            ),
            evidence_detail={
                "pattern_key": pattern_key,
                "history": history,
                "conflict_threshold": conflict_threshold,
                "conflict_tp_fraction_threshold": conflict_tp_fraction,
                "observed_tp_fraction": round(tp_fraction, 4),
                "reason": (
                    "When the same alert pattern has been dispositioned BOTH as "
                    "false_positive AND true_positive by different analysts, the "
                    "pattern is ambiguous. Auto-suggesting FP suppression could "
                    "cause the system to auto-close a genuine incident. "
                    "Escalating to SOC Lead for pattern review and rule clarification."
                ),
                "config_warnings": config_warnings,
            },
            anomaly_flags=anomaly_flags,
        )

    # --- FAILURE CASE F3: Anomaly signal overrides FP suggestion ---
    # anomaly_flags is already populated (above). If non-empty and we would
    # otherwise suggest FP, we must escalate instead.
    non_context_flags = [f for f in anomaly_flags
                         if "MISSING_ENDPOINT_CONTEXT" not in f
                         and "UNKNOWN_MANAGEMENT_STATUS" not in f]

    if non_context_flags and history["fp_rate"] >= cfg["evidence"]["min_fp_rate_for_suggestion"]:
        # Pattern matches FP cluster, but anomaly signals present → escalate
        # This is the critical novel-TP preservation path.
        return RecommendationResult(
            alert_id=alert_id,
            recommendation_type=REC_ANOMALY,
            confidence_tier=TIER_LOW,
            confidence_score=history["fp_rate"],
            requires_human_confirmation=True,
            auto_suggest_eligible=eligible,
            pattern_key=pattern_key,
            rule_triggered="ANOMALY_SIGNAL_OVERRIDES_FP_PATTERN",
            evidence_summary=(
                f"Pattern {pattern_key} matches a known FP cluster "
                f"({history['fp_count']}/{total_count} historical cases = FP), "
                f"BUT anomaly signals are present that were absent in historical "
                f"FP cases. Escalating instead of suggesting FP. "
                f"Signals: {len(non_context_flags)} detected."
            ),
            evidence_detail={
                "pattern_key": pattern_key,
                "history": history,
                "fp_rate_observed": round(history["fp_rate"], 4),
                "anomaly_signals_detected": non_context_flags,
                "reason": (
                    "The recommendation engine detected contextual signals that "
                    "distinguish this alert from the historical FP cluster. "
                    "Even though the surface pattern (alert_type + segment) matches "
                    "a high-FP cluster, suppressing without human review risks missing "
                    "a novel threat that is deliberately masquerading as known-noisy traffic. "
                    "This is a core safety property of the system (see docs/01_problem_analysis.md §4)."
                ),
                "config_warnings": config_warnings,
            },
            anomaly_flags=anomaly_flags,
        )

    # --- INSUFFICIENT EVIDENCE ---
    if total_count < min_evidence:
        return RecommendationResult(
            alert_id=alert_id,
            recommendation_type=REC_INSUFFICIENT,
            confidence_tier=TIER_INSUFFICIENT,
            confidence_score=None,
            requires_human_confirmation=True,
            auto_suggest_eligible=eligible,
            pattern_key=pattern_key,
            rule_triggered="BELOW_MIN_EVIDENCE_COUNT",
            evidence_summary=(
                f"Only {total_count} historical cases for {pattern_key} "
                f"(minimum required: {min_evidence}). "
                "Insufficient evidence to make a reliable recommendation."
            ),
            evidence_detail={
                "pattern_key": pattern_key,
                "history": history,
                "min_evidence_count": min_evidence,
                "reason": (
                    "The rule-based engine requires a minimum number of prior "
                    "analyst decisions for the same (alert_type, source_segment) "
                    "pattern before making a recommendation. This threshold prevents "
                    "the system from making overconfident recommendations based on "
                    "a handful of cases that may not be representative."
                ),
                "config_warnings": config_warnings,
            },
            anomaly_flags=anomaly_flags,
        )

    # --- MAIN RECOMMENDATION PATH ---
    fp_rate = history["fp_rate"]
    confidence_tier = _determine_confidence_tier(fp_rate, cfg)
    auto_suggest_threshold = cfg.get("auto_suggest_threshold", AUTO_SUGGEST_THRESHOLD_FLOOR)

    min_fp_for_suggestion = cfg["evidence"]["min_fp_rate_for_suggestion"]

    if fp_rate >= min_fp_for_suggestion:
        # Recommend false_positive
        action_type = "auto_suppress" if (
            eligible and fp_rate >= auto_suggest_threshold
        ) else "suggest_fp"

        # HARD RULE: auto_suppress always requires human confirmation
        needs_confirmation = (
            _requires_confirmation(action_type, cfg)
            or action_type == "auto_suppress"  # belt-and-suspenders
        )

        return RecommendationResult(
            alert_id=alert_id,
            recommendation_type=REC_SUGGEST_FP,
            confidence_tier=confidence_tier,
            confidence_score=round(fp_rate, 4),
            requires_human_confirmation=needs_confirmation,
            auto_suggest_eligible=eligible,
            pattern_key=pattern_key,
            rule_triggered="FP_RATE_ABOVE_THRESHOLD",
            evidence_summary=(
                f"{history['fp_count']} of the last {total_count} similar alerts "
                f"from {alert.source_segment} segment with alert_type={alert.alert_type} "
                f"were dispositioned false_positive "
                f"({100 * fp_rate:.1f}% FP rate). "
                f"Confidence tier: {confidence_tier}."
            ),
            evidence_detail={
                "pattern_key": pattern_key,
                "history": history,
                "fp_rate_observed": round(fp_rate, 4),
                "fp_threshold_used": min_fp_for_suggestion,
                "high_confidence_threshold": cfg["evidence"]["high_confidence_fp_threshold"],
                "auto_suggest_threshold": auto_suggest_threshold,
                "action_type": action_type,
                "eligible_for_auto_suggest": eligible,
                "endpoint_context": {
                    "device_type": ctx.device_type if ctx else None,
                    "patch_status": ctx.patch_status if ctx else None,
                    "is_managed_device": ctx.is_managed_device if ctx else None,
                    "known_vuln_count": ctx.known_vuln_count if ctx else None,
                },
                "config_warnings": config_warnings,
            },
            anomaly_flags=anomaly_flags,
        )

    elif history["tp_rate"] >= 0.5:
        # More likely TP than FP based on history
        return RecommendationResult(
            alert_id=alert_id,
            recommendation_type=REC_SUGGEST_TP,
            confidence_tier=TIER_MEDIUM,
            confidence_score=round(history["tp_rate"], 4),
            requires_human_confirmation=True,
            auto_suggest_eligible=eligible,
            pattern_key=pattern_key,
            rule_triggered="TP_RATE_ABOVE_FIFTY_PERCENT",
            evidence_summary=(
                f"{history['tp_count']} of last {total_count} similar alerts "
                f"were true_positive ({100 * history['tp_rate']:.1f}% TP rate). "
                "Suggesting true_positive — investigate this alert."
            ),
            evidence_detail={
                "pattern_key": pattern_key,
                "history": history,
                "tp_rate_observed": round(history["tp_rate"], 4),
                "config_warnings": config_warnings,
            },
            anomaly_flags=anomaly_flags,
        )

    else:
        # Ambiguous — neither FP nor TP is clearly dominant
        return RecommendationResult(
            alert_id=alert_id,
            recommendation_type=REC_ESCALATE,
            confidence_tier=TIER_LOW,
            confidence_score=round(fp_rate, 4),
            requires_human_confirmation=True,
            auto_suggest_eligible=eligible,
            pattern_key=pattern_key,
            rule_triggered="AMBIGUOUS_PATTERN",
            evidence_summary=(
                f"Pattern {pattern_key}: {history['fp_count']} FP, "
                f"{history['tp_count']} TP, {history['escalated_count']} escalated "
                f"in last {total_count} cases. Pattern is too ambiguous for a "
                "confident recommendation. Escalating for human review."
            ),
            evidence_detail={
                "pattern_key": pattern_key,
                "history": history,
                "fp_rate": round(fp_rate, 4),
                "min_fp_for_suggestion": min_fp_for_suggestion,
                "reason": "Neither FP nor TP rate exceeds decision thresholds.",
                "config_warnings": config_warnings,
            },
            anomaly_flags=anomaly_flags,
        )
