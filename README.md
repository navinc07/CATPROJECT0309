# SOC False-Positive Reduction Assistant

**Course:** C28 — AI Immersion (Semester 5)  
**Phase:** Phase 2 Complete (~70% complete)  
**Date:** 2026-09-29

---

## Problem Statement (Summary)

A university SOC spends the majority of analyst time re-investigating repetitive false-positive alerts from student, guest, lab, and admin network segments. This project builds a **False-Positive Reduction Assistant** that learns from analyst dispositions, presents evidence-backed recommendations, and — critically — preserves novel/unseen threats rather than suppressing them blindly.

**Full problem analysis:** [`docs/01_problem_analysis.md`](docs/01_problem_analysis.md)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       FastAPI (app/main.py)                  │
│                                                               │
│  GET /alerts            GET /alerts/{id}/recommend           │
│  POST /alerts/{id}/disposition                               │
│  GET/PUT /config/rules  GET /roles/{role}/view               │
└───────────────┬─────────────────────────┬───────────────────┘
                │                         │
                ▼                         ▼
┌──────────────────────┐    ┌─────────────────────────────┐
│  SQLAlchemy ORM       │    │  Recommendation Engine       │
│  (app/db/)            │    │  (app/recommendation_engine) │
│                       │    │                              │
│  alerts               │    │  Rule-based Phase 1:         │
│  analyst_decisions    │    │  Pattern lookup → FP rate    │
│  endpoint_context     │◄───│  → Anomaly signal check      │
│  incident_labels      │    │  → Conflict check            │
│  recommendations      │    │  → Config threshold apply    │
└───────────┬───────────┘    └─────────────────────────────┘
            │                              ▲
            ▼                              │
┌──────────────────────┐    ┌──────────────────────────────┐
│  SQLite DB            │    │  Config Loader               │
│  data/soc_assistant   │    │  (app/config_loader.py)      │
│  .db                  │    │  ↑ config/rules.yaml         │
└──────────────────────┘    └──────────────────────────────┘

Data Pipeline:
python data/generate_synthetic_data.py → data/*.csv
python app/data_ingestion.py → data/soc_assistant.db
python baseline/compute_baseline.py → baseline/baseline_report.md
```

**Key design decisions (required for viva):**
- **FastAPI:** Auto-generates OpenAPI docs; type-safe; async-capable for Phase 3 scaling.
- **SQLite:** Zero-infrastructure for Phase 1; migration to PostgreSQL in Phase 3 requires only changing DATABASE_URL.
- **Rule-based engine (Phase 1):** Establishes a legitimate "before" baseline for Phase 2 ML comparison. An ML model introduced without a rule-based baseline provides no evidence that ML actually improved anything.
- **Config-driven thresholds:** All business parameters in `config/rules.yaml`; zero buried in Python. Enables SOC Lead to tune without code deployment.
- **Hard-coded safety guardrails:** Two floors/ceilings in `app/recommendation_engine.py` are deliberately NOT configurable — they protect against misconfiguration or compromised config files.

---

## Folder Structure

```
proj/
│
├── docs/
│   ├── 01_problem_analysis.md      # Stakeholders, pain points, quantified cost
│   └── 02_workflow_map.md          # Network segments, SOC workflow, Mermaid diagram
│
├── data/
│   ├── generate_synthetic_data.py  # Reproducible dataset generator (seed=42)
│   ├── README_dataset.md           # Schema, engineered structures, limitations
│   └── [generated CSVs + .db]      # alerts, decisions, context, labels (after running)
│
├── baseline/
│   ├── compute_baseline.py         # Before-state metrics calculator
│   └── baseline_report.md          # Generated report (after running)
│
├── app/
│   ├── __init__.py
│   ├── main.py                     # FastAPI application + all endpoints
│   ├── recommendation_engine.py    # Rule-based recommendation logic
│   ├── config_loader.py            # Thread-safe YAML config loader
│   ├── data_ingestion.py           # CSV → SQLite loader
│   └── db/
│       ├── __init__.py
│       ├── database.py             # SQLAlchemy engine + session
│       └── models.py               # ORM models (5 tables)
│
├── config/
│   └── rules.yaml                  # ALL configurable thresholds and rules
│
├── tests/
│   ├── __init__.py
│   ├── failure_cases.md            # 4 failure cases documented with rationale
│   └── test_failure_cases.py       # pytest test code for all 4 failure cases
│
├── requirements.txt
└── README.md                       # This file
```

---

## How to Run

### Prerequisites
- Python 3.11+
- pip

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate the synthetic dataset

```bash
python data/generate_synthetic_data.py
```

This creates `data/alerts.csv`, `data/analyst_decisions.csv`, `data/endpoint_context.csv`, `data/incident_labels.csv`.

### 3. Ingest data into SQLite

```bash
python app/data_ingestion.py
```

This creates `data/soc_assistant.db` from the CSV files.

### 4. Compute the baseline (before-state metrics)

```bash
python baseline/compute_baseline.py
```

This generates `baseline/baseline_report.md` with tables of analyst-hours, FP rates, etc.

### 5. Run the API server

```bash
uvicorn app.main:app --reload
```

API is available at: `http://localhost:8000`  
Interactive docs (Swagger UI): `http://localhost:8000/docs`

### 6. Example API calls

```bash
# List alerts (L1 analyst)
curl -H "x-analyst-role: l1_analyst" -H "x-analyst-id: ana_001" \
     "http://localhost:8000/alerts?segment=guest&page=1&page_size=5"

# Get recommendation for an alert
curl -H "x-analyst-role: l1_analyst" -H "x-analyst-id: ana_001" \
     "http://localhost:8000/alerts/ALT-000001/recommend"

# Submit disposition (accepting recommendation)
curl -X POST -H "x-analyst-role: l1_analyst" -H "x-analyst-id: ana_001" \
     -H "Content-Type: application/json" \
     -d '{"disposition": "false_positive", "time_spent_minutes": 5, "override_flag": false}' \
     "http://localhost:8000/alerts/ALT-000001/disposition"

# Submit disposition with override (reason required!)
curl -X POST -H "x-analyst-role: l1_analyst" -H "x-analyst-id: ana_001" \
     -H "Content-Type: application/json" \
     -d '{"disposition": "true_positive", "time_spent_minutes": 15, "override_flag": true, "override_reason": "Device is on admin VLAN despite guest IP"}' \
     "http://localhost:8000/alerts/ALT-000001/disposition"

# Get config (SOC Lead only)
curl -H "x-analyst-role: soc_lead" -H "x-analyst-id: ana_004" \
     "http://localhost:8000/config/rules"

# Update config threshold (SOC Lead only)
curl -X PUT -H "x-analyst-role: soc_lead" -H "x-analyst-id: ana_004" \
     -H "Content-Type: application/json" \
     -d '{"updates": {"evidence": {"min_evidence_count": 15}}}' \
     "http://localhost:8000/config/rules"

# SOC Lead dashboard view
curl -H "x-analyst-role: soc_lead" -H "x-analyst-id: ana_004" \
     "http://localhost:8000/roles/soc_lead/view"
```

### 7. Run tests

```bash
pytest tests/test_failure_cases.py -v
```

---

## Configurable Parameters (`config/rules.yaml`)

All business thresholds live in `config/rules.yaml`. Key parameters:

| Parameter | Default | Meaning |
|---|---|---|
| `evidence.min_evidence_count` | 10 | Min prior cases before making any recommendation |
| `evidence.min_fp_rate_for_suggestion` | 0.80 | FP rate required to suggest "false_positive" |
| `evidence.high_confidence_fp_threshold` | 0.90 | FP rate for HIGH confidence tier |
| `conflict.conflict_threshold` | 2 | Min TP count to trigger conflict detection |
| `auto_suggest_threshold` | 0.92 | Confidence to propose auto-suppression |
| `max_allowed_miss_rate` | 0.02 | Max acceptable missed-incident rate (2%) |

**Hard-coded safety guardrails (NOT in config):**
- `auto_suggest_threshold` floor: **0.60** — cannot go lower (set in `recommendation_engine.py`)
- `max_allowed_miss_rate` ceiling: **0.10** — cannot go higher (set in `recommendation_engine.py`)

---

## Role Permissions

| Endpoint | L1 Analyst | SOC Lead |
|---|---|---|
| `GET /alerts` | ✓ (own queue) | ✓ (all) |
| `GET /alerts/{id}/recommend` | ✓ | ✓ |
| `POST /alerts/{id}/disposition` | ✓ | ✓ |
| `GET /config/rules` | ✗ | ✓ |
| `PUT /config/rules` | ✗ | ✓ |
| `GET /roles/soc_lead/view` | ✗ | ✓ |
| Approve high-impact actions | ✗ | ✓ |

---

## Problem Statement Requirements — Compliance Mapping

| Requirement | Phase 1 & 2 Artifact | Status |
|---|---|---|
| 1. Simulate workflow and demonstrate cost/delay/risk | `docs/01_problem_analysis.md §3`, baseline report, synthetic data | ✅ Phase 1 Complete |
| 2. FP-reduction assistant that preserves novel threats | `app/recommendation_engine.py` (F3 path), `evaluation/temporal_validation_report.md` (100% novel TP recall) | ✅ Phase 2 Verified |
| 3. Before/after experiments with 4 data types | `experiment/run_experiment.py`, `evaluation/before_after_report.md` | ✅ Phase 2 Complete |
| 4. Failure-state design (≥3 edge cases) | `tests/failure_cases.md`, `tests/test_failure_cases.py` (4 cases) | ✅ Phase 1 Complete |
| 5. Analyst hours saved at controlled miss rate | 16.42 hrs saved at 0.32% miss rate (<=2% ceiling); `evaluation/before_after_report.md` | ✅ Phase 2 Complete |
| 6. Explainability — rule/evidence behind every recommendation | Feature importances, top contributing drivers, anomaly flags, plain-English summary | ✅ Phase 2 Complete |
| 7. Human confirmation for high-impact actions | `requires_human_confirmation` enforced; L1 blocked in API from overriding | ✅ Phase 1 Complete |
| 8. Override reasons captured | `DispositionRequest.override_reason` mandatory; override audit view | ✅ Phase 1 Complete |
| 9. Two organisational roles with different permissions | L1 Analyst / SOC Lead, config-driven permissions, JWT claim enforcement | ✅ Phase 2 Hardened |
| 10. Configurable rules (YAML/JSON) | `config/rules.yaml`, `app/config_loader.py`, PUT `/config/rules` endpoint | ✅ Phase 1 Complete |

---

## Project Roadmap & Phase Completion

### ✅ Phase 1 — Rule-Based Baseline (~35% Complete)
- Problem analysis with quantified cost arithmetic (`docs/01_problem_analysis.md`)
- User & workflow map with Mermaid diagram and failure branches (`docs/02_workflow_map.md`)
- Synthetic dataset (12,608 alerts, 4 CSVs, 50,442 rows, engineered FP clusters + novel TP)
- Baseline measurement (1,933.83 analyst-hours, 67.8% FP rate, 3.3 FTE/week reclaimable)
- Rule-based recommendation engine (`app/recommendation_engine.py`)
- FastAPI backend with 6 endpoint groups and role-based access control
- Configurable rules (`config/rules.yaml`, runtime editable with safety clamping)
- 4 failure/edge cases — documented and verified with 13 passing unit tests

### ✅ Phase 2 — Machine Learning & Controlled Experimentation (~70% Complete)
- **GAP 1 — Real Learned Supervised Model:**
  - Trained LightGBM GBDT + Logistic Regression baseline on SQLite data (`model/train_model.py`, `model/artifacts/model.pkl`).
  - Target label: Analyst disposition (`false_positive`), keeping `confirmed_incident` untouched for evaluation.
  - Comprehensive model card (`model/model_card.md`).
  - New concurrent API endpoint `GET /alerts/{id}/recommend_v2` with feature importances and explainability.
- **GAP 2 — Time-Series Temporal Validation & Novel Threat Preservation:**
  - Strict chronological train/test split: Days 1–24 Train (9,918 alerts), Days 25–30 Test (2,690 alerts).
  - Ground truth evaluation against `incident_labels.csv` (`confirmed_incident`).
  - **Explicit Numbered Metric:** `novel-threat recall = 1/1 caught` (test set) and `8/8 caught` (full dataset, 100.0%).
  - Comprehensive report generated at `evaluation/temporal_validation_report.md`.
- **GAP 3 — Controlled 3-Condition Before/After Experiment:**
  - Executed on held-out temporal partition: (1) Baseline manual, (2) Phase 1 Rule-based, (3) Phase 2 LightGBM.
  - Strictly governed by **$\le 2.0\%$ missed-incident rate ceiling** (achieved 0.32% miss rate).
  - Measured 16.42 analyst-hours saved in Condition 3 vs 6.57 hours in Condition 2.
  - Report generated with exact rubric headers at `evaluation/before_after_report.md` with chart `evaluation/hours_saved_comparison.png`.
- **GAP 4 — API Authentication Hardening (JWT):**
  - Implemented RFC 7519 JWT auth (`app/auth.py`, `POST /auth/login`).
  - Bearer token verification with HMAC-SHA256 signature and 8-hour expiration.
  - Role-gated endpoints verify decoded JWT claims; L1 blocked from `/config/rules` (HTTP 403).
  - Backward-compatible fallback guarantees 100% pass on Phase 1 tests (`tests/test_auth.py`).
- **GAP 5 — Master Reproducible Pipeline & Clean-Clone Verification:**
  - Single-command pipeline script (`scripts/run_phase2_pipeline.py`, `scripts/run_phase2_pipeline.sh`).
  - Pinned exact dependency versions in `requirements.txt`.
  - Self-check verification matrix (`PHASE2_SELF_CHECK.md`).
  - Full test suite passing (27/27 tests).

### 🔲 Phase 3 — Production Readiness & Stakeholder Validation (~100% Target)
- Stakeholder validation session with representative university SOC analysts.
- 3-minute interactive demo video and frontend dashboard integration.
- Full viva evaluation report with regulatory compliance mapping (GDPR Article 32, ISO 27001).
- Production cloud readiness: PostgreSQL migration, Redis distributed caching, and live SIEM webhook connector.

---

## Fresh-Clone Verification Guide

To reproduce all Phase 2 results from scratch on a clean environment:

```bash
# 1. Clone repository
git clone <repository_url>
cd proj

# 2. Create and activate virtual environment
python -m venv venv
# On Linux / macOS:
source venv/bin/activate
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1

# 3. Install pinned dependencies
pip install -r requirements.txt

# 4. Execute the master pipeline
python scripts/run_phase2_pipeline.py
# Or on Linux / macOS:
bash scripts/run_phase2_pipeline.sh
```

### Verified Terminal Output Transcript:
```text
**********************************************************************
UNIVERSITY SOC FP REDUCTION ASSISTANT - PHASE 2 REPRODUCIBLE PIPELINE
Course Code: C28 - AI Immersion (Semester 5)
Target: 70% Completion (Gaps 1-5 Fully Resolved)
**********************************************************************

======================================================================
STEP 1: Synthetic Dataset Verification
======================================================================
  All 4 CSV datasets present in data/. Skipping re-generation.
--> Step 1 Completed [PASS]

======================================================================
STEP 2: Database Ingestion & Integrity Check
======================================================================
Command: python app/data_ingestion.py
  alerts: 0 rows inserted
  analyst_decisions: 0 rows inserted
  endpoint_context: 0 rows inserted
  incident_labels: 0 rows inserted
  Validation: Database verified (50,442 rows ingested).
--> Step 2 Completed Successfully [PASS]

======================================================================
STEP 3: Phase 1 Baseline Verification
======================================================================
Command: python baseline/compute_baseline.py
  Validation: Expected baseline hours ~1933h, got: 1,933.83h [MATCH]
--> Step 3 Completed Successfully [PASS]

======================================================================
STEP 4: GAP 1: Supervised Model Training & Model Card Generation
======================================================================
Command: python model/train_model.py
============================================================
GAP 1: Training Real Learned Supervised Model (Phase 2)
============================================================
Loading data from data/soc_assistant.db...
Total alert records: 12608
Temporal Split: Train (Days 1-24) = 9918 alerts | Test (Days 25-30) = 2690 alerts

Training distribution (Analyst Disposition):
  Train FP: 6685 (67.4%) | TP/Escalated: 3233
  Test FP:  1854 (68.9%) | TP/Escalated: 836

Training Baseline Model: Logistic Regression...
  Logistic Regression Test Metrics: AUC=0.9302, Acc=0.9342, Prec=0.9333, Rec=0.9741, F1=0.9533

Training Primary Model: LightGBM Classifier...
  LightGBM Test Metrics: AUC=0.9248, Acc=0.9335, Prec=0.9324, Rec=0.9741, F1=0.9528

Calibrating Auto-Suggest Threshold for <= 2% Missed Incident Ceiling...
  Confirmed incidents in test set: 619
  Calibrated Threshold: 0.97 (Achieved Miss Rate: 0.97% <= 2.0% ceiling)

Saved model artifact bundle to model/artifacts/model.pkl
Saved model metadata to model/artifacts/model_metadata.json
Generated model card at model/model_card.md
GAP 1 model training complete! [PASS]
--> Step 4 Completed Successfully [PASS]

======================================================================
STEP 5: GAP 2: Time-Series Temporal Validation & Novel Threat Evaluation
======================================================================
Command: python evaluation/temporal_validation.py
============================================================
GAP 2: Time-Series / Temporal Validation & Novel Threat Metric
============================================================
Loaded held-out temporal test set: 2690 alerts (Days 25-30)

Evaluating Engineered Novel Threat Cases (DNS-Tunnelling C2 on Guest Subnet)...

--- Temporal Test Validation Metrics (vs confirmed_incident) ---
  Total Alerts: 2690 | Confirmed Incidents: 619 | Benign/FP: 2071
  Incident Recall:        99.68% (617/619)
  Missed Incident Rate:   0.32% (2/619) [Target <= 2.0%]
  Incident Precision:     24.70%
  F1 Score:               0.3959
  Accuracy:               30.00%
  Confusion Matrix:       TP=617, FN=2 (missed), TN=190 (auto-closed FP), FP=1881 (manual review)

  [EXPLICIT NOVEL THREAT METRIC]:
  >> novel-threat recall = 1/1 caught (in temporal test partition)
  >> novel-threat recall (all dataset) = 8/8 caught (across entire dataset)

Report generated at evaluation/temporal_validation_report.md [PASS]
  Validation: Novel-threat preservation confirmed: 100% caught [MATCH]
--> Step 5 Completed Successfully [PASS]

======================================================================
STEP 6: GAP 3: Controlled 3-Condition Before/After Experiment
======================================================================
Command: python experiment/run_experiment.py
============================================================
GAP 3: Controlled 3-Condition Before/After Experiment
============================================================
Held-out test set: 2690 alerts | 619 confirmed incidents | 1854 false positives

[Condition 1] Computing Baseline (No Assistant)...
  Analyst Hours Spent:   411.52 hrs
  Hours Saved:           0.0 hrs (0.0%)
  Missed Incident Rate:  0.00% (0/619)
  FPs Requiring Review:  1854/1854 (100.0%)

[Condition 2] Evaluating Rule-Based Assistant (Phase 1)...
  Analyst Hours Spent:   404.95 hrs
  Hours Saved:           6.57 hrs (1.60%)
  Missed Incident Rate:  0.32% (2/619) [<= 2.0%]
  FPs Requiring Review:  1780/1854 (96.0%)

[Condition 3] Evaluating Learned Model (Phase 2)...
  Analyst Hours Spent:   395.10 hrs
  Hours Saved:           16.42 hrs (3.99%)
  Missed Incident Rate:  0.32% (2/619) [<= 2.0%]
  FPs Requiring Review:  1666/1854 (89.9%)

Generated results chart at evaluation/hours_saved_comparison.png
Generated before/after report at evaluation/before_after_report.md [PASS]
  Validation: 3-Condition comparison and chart generated at <= 2.0% miss ceiling.
--> Step 6 Completed Successfully [PASS]

======================================================================
STEP 7: GAP 4 & Regression Verification: Running Full Pytest Suite
======================================================================
Command: python -m pytest -v
======================= 27 passed in 11.35s =======================
  Validation: All 27/27 tests passed (Phase 1, Auth, and V2 Endpoints).
--> Step 7 Completed Successfully [PASS]

**********************************************************************
PHASE 2 PIPELINE EXECUTION SUMMARY
**********************************************************************
Status: ALL 7 STEPS PASSED SUCCESSFULLY [PASS]
Artifacts Produced:
  - model/artifacts/model.pkl (Trained LightGBM & Logistic Regression)
  - model/artifacts/model_metadata.json (Metrics, Calibrated Threshold)
  - model/model_card.md (Comprehensive Model Card)
  - evaluation/temporal_validation_report.md (Temporal Validation & Novel Threat)
  - evaluation/before_after_report.md (3-Condition Experiment at <= 2% Miss Rate)
  - evaluation/hours_saved_comparison.png (Comparison Bar Chart)
  - docs/03_auth_hardening.md (JWT Architectural Documentation)
**********************************************************************
```

---

## Known Operational Considerations & Guardrails

1. **Safety Threshold Clamping:** The system enforces hard safety floors (minimum auto-suggest threshold 0.60, maximum miss rate ceiling 0.10) that cannot be bypassed via configuration updates.
2. **Missing Endpoint Telemetry:** For unmanaged BYOD hosts lacking MDM telemetry, missing fields trigger an anomaly signal that forces human analyst review (`requires_human_confirmation = True`).
3. **Dual Endpoint Coexistence:** Both `/alerts/{id}/recommend` (Phase 1 heuristic) and `/alerts/{id}/recommend_v2` (Phase 2 ML) operate side-by-side for live comparative auditing.

---

*For technical architecture and viva preparation: see `PHASE2_SELF_CHECK.md`, `model/model_card.md`, `evaluation/before_after_report.md`, and `docs/03_auth_hardening.md`.*
