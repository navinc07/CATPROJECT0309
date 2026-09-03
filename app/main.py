"""
app/main.py
===========
FastAPI application — the main entry point for the SOC False-Positive
Reduction Assistant API.

ARCHITECTURE RATIONALE:
    FastAPI was chosen because:
    (a) It generates automatic OpenAPI docs (http://localhost:8000/docs)
        which serves as interactive documentation for the viva.
    (b) Type-annotated request/response models (Pydantic) provide clear
        API contracts — important when the frontend (Phase 3) or other
        tools integrate with this API.
    (c) Async support means the server can handle concurrent analyst
        requests without blocking (important if scaled in Phase 3).
    (d) Consistent with prior projects in the course.

ROLE-BASED ACCESS CONTROL:
    Roles are passed via the X-Analyst-Role and X-Analyst-ID headers.
    WHY NOT JWT/OAuth in Phase 1: Authentication infrastructure is out of
    scope for Phase 1. The header approach is a clean placeholder that
    can be replaced by proper JWT middleware in Phase 3 without changing
    any endpoint logic — only the check_role() dependency changes.
    The role permissions are read from config/rules.yaml so they are
    auditable and configurable.

ENDPOINTS:
    GET  /alerts                    — List/filter alerts (role-scoped)
    GET  /alerts/{id}               — Single alert detail
    GET  /alerts/{id}/recommend     — Recommendation + evidence for alert
    POST /alerts/{id}/disposition   — Submit analyst decision
    GET  /config/rules              — Read current rule config (SOC Lead only)
    PUT  /config/rules              — Update rule config (SOC Lead only)
    GET  /roles/{role}/view         — Role-scoped dashboard view

Usage:
    uvicorn app.main:app --reload
"""

import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Header, Query, Path as FPath
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.db.database import get_db, init_db
from app.db.models import Alert, AnalystDecision, EndpointContext, IncidentLabel, Recommendation
from app.recommendation_engine import get_recommendation
from app.config_loader import get_config, update_config

# ---------------------------------------------------------------------------
# Application lifespan — runs once at startup and shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: initialise the database tables.
    Shutdown: nothing needed for SQLite.
    
    WHY LIFESPAN (not @app.on_event):
        The lifespan context manager is the FastAPI-recommended approach
        as of FastAPI 0.93+. It cleanly separates startup/shutdown logic
        and works correctly with pytest fixtures.
    """
    init_db()
    yield


app = FastAPI(
    title="SOC False-Positive Reduction Assistant",
    description=(
        "Phase 1 (Rule-Based Baseline) API for the University SOC "
        "False-Positive Reduction Assistant. "
        "Course: C28 AI Immersion, Semester 5."
    ),
    version="1.0.0-phase1",
    lifespan=lifespan,
)

# Allow all origins in Phase 1 (no frontend yet).
# Phase 3 will restrict this to the specific frontend origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Role-based access control helpers
# ---------------------------------------------------------------------------

VALID_ROLES = {"l1_analyst", "soc_lead"}

def check_role(
    required_permission: str,
    x_analyst_role: str = Header(..., description="Analyst role: l1_analyst or soc_lead"),
    x_analyst_id: str = Header(..., description="Analyst ID, e.g. ana_001"),
):
    """
    FastAPI dependency that checks role permissions against config/rules.yaml.

    Returns (analyst_id, analyst_role) if permitted.
    Raises HTTP 403 if the role does not have the required permission.
    Raises HTTP 400 if the role header is invalid.

    WHY CONFIG-DRIVEN PERMISSIONS:
        Role permissions are defined in config/rules.yaml (role_permissions section).
        This means the SOC Lead can adjust what each role can do without code changes.
        The one exception: the hard-coded check that only soc_lead can approve
        high-impact actions (enforced directly in the endpoint, not via config).
    """
    if x_analyst_role not in VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role '{x_analyst_role}'. Must be one of: {list(VALID_ROLES)}.",
        )
    cfg = get_config()
    role_perms = cfg.get("role_permissions", {})
    allowed = role_perms.get(x_analyst_role, [])
    if required_permission not in allowed:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Role '{x_analyst_role}' does not have permission '{required_permission}'. "
                f"Permitted permissions for this role: {allowed}."
            ),
        )
    return x_analyst_id, x_analyst_role


def require_l1(
    x_analyst_role: str = Header(...),
    x_analyst_id: str = Header(...),
):
    """Shorthand dependency for L1 read access (alerts:read)."""
    return check_role("alerts:read", x_analyst_role, x_analyst_id)


def require_soc_lead(
    x_analyst_role: str = Header(...),
    x_analyst_id: str = Header(...),
):
    """Shorthand dependency for SOC Lead exclusive access."""
    return check_role("config:read", x_analyst_role, x_analyst_id)


# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------

class AlertOut(BaseModel):
    """Response model for a single alert."""
    alert_id: str
    timestamp: str
    source_segment: str
    alert_type: str
    severity: int
    src_ip: str
    dst_ip: str
    signature_rule_triggered: str
    raw_score: float

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    alerts: list[AlertOut]


class DispositionRequest(BaseModel):
    """
    Request body for POST /alerts/{id}/disposition.

    ENFORCEMENT: override_reason is mandatory when override_flag is True.
    This is validated by the field_validator below, which raises HTTP 422
    before the endpoint logic runs — not a database-level constraint.
    
    WHY MANDATORY OVERRIDE REASON:
        Without a documented reason, the SOC Lead cannot audit why analysts
        disagreed with the assistant, and the Phase 2 model cannot learn from
        the disagreement. An empty override reason is indistinguishable from
        no reason — hence the API refuses it.
    """
    disposition: str = Field(
        ...,
        description="One of: false_positive, true_positive, escalated",
    )
    time_spent_minutes: Optional[int] = Field(
        None,
        ge=0,
        description="Minutes spent investigating this alert",
    )
    override_flag: bool = Field(
        False,
        description="True if analyst is overriding the assistant's recommendation",
    )
    override_reason: Optional[str] = Field(
        None,
        description="Required if override_flag=True. Why did you disagree with the assistant?",
    )

    @field_validator("disposition")
    @classmethod
    def disposition_must_be_valid(cls, v):
        valid = {"false_positive", "true_positive", "escalated"}
        if v not in valid:
            raise ValueError(f"disposition must be one of {valid}, got '{v}'")
        return v

    @field_validator("override_reason")
    @classmethod
    def override_reason_required_when_flag_set(cls, v, info):
        # Access other field values via info.data
        if info.data.get("override_flag") and (not v or not v.strip()):
            raise ValueError(
                "override_reason is required when override_flag=True. "
                "Please document why you disagree with the assistant's recommendation. "
                "This is required for audit and Phase 2 model training."
            )
        return v


class DispositionResponse(BaseModel):
    alert_id: str
    decision_id: int
    message: str
    decision_recorded: dict


class RecommendationResponse(BaseModel):
    alert_id: str
    recommendation: str
    confidence: dict
    requires_human_confirmation: bool
    auto_suggest_eligible: bool
    explainability: dict
    phase1_note: str


class ConfigRulesResponse(BaseModel):
    config: dict
    loaded_from: str


class ConfigUpdateRequest(BaseModel):
    updates: dict = Field(
        ...,
        description="Dict of config keys/values to update. Nested keys supported.",
    )


class RoleViewResponse(BaseModel):
    role: str
    analyst_id: str
    summary: dict
    data: dict


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", tags=["Health"])
def root():
    """Health check endpoint."""
    return {
        "status": "online",
        "project": "SOC False-Positive Reduction Assistant",
        "phase": "1 — Rule-Based Baseline",
        "docs": "/docs",
    }


# ---- Alerts ----------------------------------------------------------------

@app.get(
    "/alerts",
    response_model=AlertListResponse,
    tags=["Alerts"],
    summary="List and filter alerts",
)
def list_alerts(
    segment: Optional[str] = Query(None, description="Filter by source_segment"),
    alert_type: Optional[str] = Query(None, description="Filter by alert_type"),
    severity_min: Optional[int] = Query(None, ge=1, le=10),
    severity_max: Optional[int] = Query(None, ge=1, le=10),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    analyst_info: tuple = Depends(require_l1),
    db: Session = Depends(get_db),
):
    """
    List alerts with optional filters. Results are paginated.
    
    L1 Analysts see their own queue (all undispositioned alerts).
    SOC Lead sees all alerts including already-dispositioned ones.
    
    ROLE SCOPE NOTE: In Phase 1, both roles see the same alerts.
    Phase 3 will add per-analyst queue assignment.
    """
    analyst_id, role = analyst_info
    query = db.query(Alert)

    if segment:
        query = query.filter(Alert.source_segment == segment)
    if alert_type:
        query = query.filter(Alert.alert_type == alert_type)
    if severity_min is not None:
        query = query.filter(Alert.severity >= severity_min)
    if severity_max is not None:
        query = query.filter(Alert.severity <= severity_max)

    # L1 only sees unresolved alerts (no disposition yet) — role scoping
    if role == "l1_analyst":
        disposed_ids = db.query(AnalystDecision.alert_id).distinct()
        query = query.filter(~Alert.alert_id.in_(disposed_ids))

    total = query.count()
    alerts = query.offset((page - 1) * page_size).limit(page_size).all()

    return AlertListResponse(
        total=total,
        page=page,
        page_size=page_size,
        alerts=[AlertOut.model_validate(a) for a in alerts],
    )


@app.get(
    "/alerts/{alert_id}",
    response_model=AlertOut,
    tags=["Alerts"],
    summary="Get alert details",
)
def get_alert(
    alert_id: str = FPath(..., description="Alert ID (e.g., ALT-000001)"),
    analyst_info: tuple = Depends(require_l1),
    db: Session = Depends(get_db),
):
    """Get full details for a single alert."""
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    return AlertOut.model_validate(alert)


# ---- Recommendation --------------------------------------------------------

@app.get(
    "/alerts/{alert_id}/recommend",
    response_model=RecommendationResponse,
    tags=["Recommendation"],
    summary="Get recommendation + evidence for an alert",
)
def recommend(
    alert_id: str = FPath(...),
    analyst_info: tuple = Depends(require_l1),
    db: Session = Depends(get_db),
):
    """
    Returns the rule-based recommendation for the given alert.

    Response always includes:
    - recommendation type (suggest_fp / escalate / insufficient_evidence / etc.)
    - confidence tier and score
    - requires_human_confirmation flag (always True for high-impact actions)
    - full explainability block: rule triggered, evidence counts, anomaly flags

    PHASE 1 NOTE: This is the rule-based baseline engine. Phase 2 will
    replace/augment this with a trained classifier but the response schema
    remains identical.
    """
    analyst_id, role = analyst_info

    # Verify alert exists
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    result = get_recommendation(alert_id, db)

    # Persist the recommendation to the database for audit and Phase 2 training
    rec_record = Recommendation(
        alert_id=alert_id,
        **result.to_db_dict(),
    )
    db.add(rec_record)
    db.commit()

    return RecommendationResponse(**result.to_api_response())


# ---- Disposition -----------------------------------------------------------

@app.post(
    "/alerts/{alert_id}/disposition",
    response_model=DispositionResponse,
    tags=["Disposition"],
    summary="Submit analyst disposition for an alert",
    status_code=201,
)
def submit_disposition(
    alert_id: str = FPath(...),
    body: DispositionRequest = ...,
    analyst_info: tuple = Depends(require_l1),
    db: Session = Depends(get_db),
):
    """
    Record an analyst's disposition for an alert.

    OVERRIDE ENFORCEMENT: If override_flag=True, override_reason MUST be
    non-empty. The Pydantic validator (DispositionRequest) enforces this
    before this function is called — if the validation fails, the client
    receives HTTP 422 with a descriptive error.

    HUMAN CONFIRMATION ENFORCEMENT: If the most recent recommendation for
    this alert set requires_human_confirmation=True AND the disposition is
    false_positive (auto-close), this endpoint checks that the requester
    is soc_lead. L1 cannot override human-confirmation requirements.

    WHY PERSIST EVERY DECISION:
        Every decision (including FP decisions) is written to analyst_decisions.
        This builds the historical pattern data that the recommendation engine
        queries. Without persistent decisions, the engine has no history and
        returns INSUFFICIENT_EVIDENCE for every alert.
    """
    analyst_id, role = analyst_info

    # Verify alert exists
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    # Check if the most recent recommendation required human confirmation
    last_rec = (
        db.query(Recommendation)
        .filter(Recommendation.alert_id == alert_id)
        .order_by(Recommendation.id.desc())
        .first()
    )

    if last_rec and last_rec.requires_human_confirmation:
        # Parse the evidence to check what action type this was
        try:
            ev = json.loads(last_rec.evidence_detail or "{}")
            action_type = ev.get("action_type", "")
        except (json.JSONDecodeError, TypeError):
            action_type = ""

        # If action is auto_suppress (or other high-impact), only soc_lead can confirm
        cfg = get_config()
        high_impact_actions = cfg.get("high_impact_actions", [])
        if action_type in high_impact_actions and role != "soc_lead":
            raise HTTPException(
                status_code=403,
                detail=(
                    f"This alert's recommended action ('{action_type}') is classified "
                    "as high-impact and requires SOC Lead (L2) approval. "
                    "L1 Analysts cannot approve high-impact actions. "
                    "Contact your SOC Lead to review this alert."
                ),
            )

    # Record the decision
    decision = AnalystDecision(
        alert_id=alert_id,
        analyst_id=analyst_id,
        analyst_role=role,
        disposition=body.disposition,
        time_spent_minutes=body.time_spent_minutes,
        decision_timestamp=datetime.now(timezone.utc).isoformat(),
        override_flag=body.override_flag,
        override_reason=body.override_reason,
    )
    db.add(decision)
    db.commit()
    db.refresh(decision)

    return DispositionResponse(
        alert_id=alert_id,
        decision_id=decision.id,
        message=(
            f"Disposition '{body.disposition}' recorded for alert {alert_id}. "
            + (f"Override reason saved." if body.override_flag else "")
        ),
        decision_recorded={
            "disposition": body.disposition,
            "override_flag": body.override_flag,
            "override_reason": body.override_reason,
            "analyst_id": analyst_id,
            "analyst_role": role,
        },
    )


# ---- Config (SOC Lead only) ------------------------------------------------

@app.get(
    "/config/rules",
    response_model=ConfigRulesResponse,
    tags=["Configuration"],
    summary="Get current rule configuration (SOC Lead only)",
)
def get_rules(
    analyst_info: tuple = Depends(require_soc_lead),
    db: Session = Depends(get_db),
):
    """
    Returns the full contents of config/rules.yaml.
    Only accessible by SOC Lead (L2).
    """
    cfg = get_config()
    return ConfigRulesResponse(
        config=cfg,
        loaded_from="config/rules.yaml",
    )


@app.put(
    "/config/rules",
    response_model=ConfigRulesResponse,
    tags=["Configuration"],
    summary="Update rule configuration (SOC Lead only)",
)
def update_rules(
    body: ConfigUpdateRequest,
    analyst_info: tuple = Depends(require_soc_lead),
    db: Session = Depends(get_db),
):
    """
    Partially updates config/rules.yaml with the provided key-value pairs.
    Changes take effect immediately (config cache is invalidated).

    GUARDRAIL NOTE: The recommendation engine applies hard floors/ceilings
    to auto_suggest_threshold and max_allowed_miss_rate even after config
    update. Attempting to set these below/above the safety guardrails will
    result in a warning in recommendation responses but NOT an error here —
    the config is stored as specified, the guardrails are applied at
    recommendation time. This is deliberate: it allows the SOC Lead to
    INTENTIONALLY set aggressive values for testing, while the guardrails
    prevent the aggressive values from causing unsafe recommendations.

    Only the analyst with soc_lead role can call this endpoint.
    """
    analyst_id, role = analyst_info
    updated = update_config(body.updates)
    return ConfigRulesResponse(
        config=updated,
        loaded_from="config/rules.yaml",
    )


# ---- Role-scoped views -----------------------------------------------------

@app.get(
    "/roles/{role}/view",
    response_model=RoleViewResponse,
    tags=["Role Views"],
    summary="Role-scoped dashboard view",
)
def role_view(
    role: str = FPath(..., description="Role: l1_analyst or soc_lead"),
    analyst_info: tuple = Depends(require_l1),
    db: Session = Depends(get_db),
):
    """
    Returns a role-scoped summary dashboard.

    L1 Analyst view:
    - Count of pending (undispositioned) alerts
    - Count of alerts with recommendations available
    - Own recent decisions

    SOC Lead view (superset of L1):
    - All of the above
    - Override audit: which analysts override most, and what reasons
    - Aggregate FP/TP rates by segment
    - Alerts requiring high-impact action confirmation
    - Config warnings from the recommendation engine
    """
    analyst_id, caller_role = analyst_info

    if role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Unknown role: {role}")

    # L1 cannot access soc_lead view
    if role == "soc_lead" and caller_role != "soc_lead":
        raise HTTPException(
            status_code=403,
            detail="SOC Lead view requires soc_lead role.",
        )

    # ---- Common metrics (both roles) ----
    total_alerts = db.query(Alert).count()
    disposed_ids = db.query(AnalystDecision.alert_id).distinct().subquery()
    pending_alerts = db.query(Alert).filter(~Alert.alert_id.in_(disposed_ids)).count()
    total_decisions = db.query(AnalystDecision).count()

    # Own recent decisions (L1 view)
    recent_decisions = (
        db.query(AnalystDecision)
        .filter(AnalystDecision.analyst_id == analyst_id)
        .order_by(AnalystDecision.id.desc())
        .limit(10)
        .all()
    )
    recent_disp_summary = [
        {
            "alert_id": d.alert_id,
            "disposition": d.disposition,
            "override_flag": d.override_flag,
            "timestamp": d.decision_timestamp,
        }
        for d in recent_decisions
    ]

    l1_data = {
        "total_alerts": total_alerts,
        "pending_alerts": pending_alerts,
        "total_decisions": total_decisions,
        "your_recent_decisions": recent_disp_summary,
    }

    if role == "l1_analyst":
        return RoleViewResponse(
            role=role,
            analyst_id=analyst_id,
            summary={
                "pending_alerts": pending_alerts,
                "your_decisions_count": len(recent_decisions),
            },
            data=l1_data,
        )

    # ---- SOC Lead view (additional metrics) ----

    # Override audit
    overrides = db.query(AnalystDecision).filter(
        AnalystDecision.override_flag == True
    ).all()
    override_by_analyst: dict[str, int] = {}
    override_reasons: list[str] = []
    for o in overrides:
        override_by_analyst[o.analyst_id] = override_by_analyst.get(o.analyst_id, 0) + 1
        if o.override_reason:
            override_reasons.append(o.override_reason)

    # FP/TP rates by segment
    all_decisions = db.query(AnalystDecision, Alert).join(
        Alert, AnalystDecision.alert_id == Alert.alert_id
    ).all()
    seg_stats: dict[str, dict[str, int]] = {}
    for dec, alrt in all_decisions:
        seg = alrt.source_segment
        if seg not in seg_stats:
            seg_stats[seg] = {"false_positive": 0, "true_positive": 0, "escalated": 0}
        seg_stats[seg][dec.disposition] = seg_stats[seg].get(dec.disposition, 0) + 1

    # Confirmed incidents
    confirmed = db.query(IncidentLabel).filter(
        IncidentLabel.confirmed_incident == True
    ).count()

    # Recommendations awaiting high-impact confirmation
    # (recommendations with requires_human_confirmation=True and no subsequent decision)
    pending_confirmation = (
        db.query(Recommendation)
        .filter(Recommendation.requires_human_confirmation == True)
        .filter(~Recommendation.alert_id.in_(disposed_ids))
        .count()
    )

    soc_data = {
        **l1_data,
        "override_audit": {
            "total_overrides": len(overrides),
            "override_rate_pct": round(100 * len(overrides) / total_decisions, 2) if total_decisions else 0,
            "overrides_by_analyst": override_by_analyst,
            "sample_override_reasons": list(set(override_reasons))[:5],
        },
        "segment_fp_tp_rates": {
            seg: {
                "false_positive": counts["false_positive"],
                "true_positive": counts["true_positive"],
                "escalated": counts.get("escalated", 0),
                "fp_rate_pct": round(
                    100 * counts["false_positive"] / max(1, sum(counts.values())), 1
                ),
            }
            for seg, counts in seg_stats.items()
        },
        "confirmed_incidents": confirmed,
        "alerts_awaiting_high_impact_confirmation": pending_confirmation,
    }

    return RoleViewResponse(
        role=role,
        analyst_id=analyst_id,
        summary={
            "pending_alerts": pending_alerts,
            "total_overrides": len(overrides),
            "confirmed_incidents": confirmed,
            "awaiting_confirmation": pending_confirmation,
        },
        data=soc_data,
    )
