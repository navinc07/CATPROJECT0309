# SOC False-Positive Reduction Assistant

**Course:** C28 — AI Immersion (Semester 5)  
**Phase:** 1 of 3 (~35% complete)  
**Date:** 2026-09-03

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

| Requirement | Phase 1 Artifact | Status |
|---|---|---|
| 1. Simulate workflow and demonstrate cost/delay/risk | `docs/01_problem_analysis.md §3`, baseline report, synthetic data | ✅ Phase 1 |
| 2. FP-reduction assistant that preserves novel threats | `app/recommendation_engine.py` (F3 path), `tests/test_failure_cases.py::TestF3` | ✅ Phase 1 |
| 3. Before/after experiments with 4 data types | Dataset generated (4 CSVs), baseline computed; "after" experiment is **Phase 2** | 🟡 Partial (before done) |
| 4. Failure-state design (≥3 edge cases) | `tests/failure_cases.md`, `tests/test_failure_cases.py` (4 cases) | ✅ Phase 1 |
| 5. Analyst hours saved at controlled miss rate | Baseline hours computed; controlled miss-rate mechanism designed in config; comparison experiment is **Phase 2** | 🟡 Partial |
| 6. Explainability — rule/evidence behind every recommendation | `RecommendationResult.evidence_summary + evidence_detail + anomaly_flags` (all paths) | ✅ Phase 1 |
| 7. Human confirmation for high-impact actions | `requires_human_confirmation` always True for high-impact; L1 blocked from approving in API | ✅ Phase 1 |
| 8. Override reasons captured | `DispositionRequest.override_reason` (enforced mandatory by Pydantic validator) | ✅ Phase 1 |
| 9. Two organisational roles with different permissions | L1 Analyst / SOC Lead, config-driven permissions, tested | ✅ Phase 1 |
| 10. Configurable rules (YAML/JSON) | `config/rules.yaml`, `app/config_loader.py`, PUT `/config/rules` endpoint | ✅ Phase 1 |

---

## Project Roadmap / Phase Completion

### ✅ Phase 1 — Complete (~35%)
- Problem analysis with quantified cost arithmetic
- User & workflow map with Mermaid diagram and failure state branches
- Synthetic dataset (13,000+ rows, 4 CSVs, engineered FP clusters + novel TP)
- Baseline measurement (before-state analyst hours, FP rates, override rates)
- Rule-based recommendation engine (the legitimate baseline for Phase 2 comparison)
- FastAPI backend with all 6 endpoint groups, role-based access control
- Configurable rules (YAML config, runtime editable)
- 4 failure/edge cases — documented and tested

### 🔲 Phase 2 — Planned (~70%)
- **Trained recommendation model** (gradient-boosted trees or logistic regression) trained on `analyst_decisions` + `recommendations` tables
- **Before/after experiment** at controlled missed-incident rate using `incident_labels.csv` as ground truth
- Precision/recall curves at varying confidence thresholds
- Quantitative comparison: rule-based (Phase 1) vs learned model (Phase 2) on FP hours saved and miss rate
- Temporal cross-validation (train on weeks 1–3, test on week 4)

### 🔲 Phase 3 — Planned (~100%)
- Stakeholder validation session with representative SOC analysts
- 3-minute demo video
- Full evaluation report with regulatory compliance mapping (GDPR Article 32, ISO 27001)
- Production-readiness: PostgreSQL migration, JWT authentication, proper logging
- Dataset: transition from synthetic to anonymised real-world pilot data (if available)

---

## Known Limitations (Phase 1)

1. **Authentication is header-based** (not JWT) — suitable for demonstration, not production.
2. **Synthetic data** — see `data/README_dataset.md §5` for 6 documented limitations.
3. **Rule-based engine only** — no learned model yet; miss rate is estimated, not measured.
4. **Single-process** — SQLite in-memory cache is not distributed; Phase 3 needs Redis.
5. **No time-series alert correlation** — individual alerts are treated independently.

---

*For questions: see `docs/01_problem_analysis.md` for rationale, `tests/failure_cases.md` for edge case design, and `data/README_dataset.md` for dataset assumptions.*
