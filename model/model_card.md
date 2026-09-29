# Model Card: SOC Tier-1 False-Positive Classifier (Phase 2)

**Model Version:** 2.0.0-phase2  
**Framework:** LightGBM (`LGBMClassifier`) with Scikit-Learn Pipeline  
**Baseline Model:** Regularized Logistic Regression (`LogisticRegression`)  
**Training Date:** 2026-09-18T05:38:31.297573+00:00  
**Evaluation Scope:** Semester 5 AI Immersion Project (Code: C28) — Phase 2  

---

## 1. Model Overview

The Phase 2 model is a supervised classifier that predicts the probability that an incoming IDS/SIEM alert is a **False Positive (FP)** vs. a **True Positive / Escalated incident**, based on historical analyst disposition behavior, network segment telemetry, and host endpoint context.

Unlike the Phase 1 heuristic engine (which relied on lookup counts and static threshold rules), this model learns non-linear decision boundaries and feature interactions across multiple data modalities.

### Target Formulation & Ground Truth Separation
- **Training Target ($y$):** Analyst disposition ($y=1$ for `false_positive`, $y=0$ for `true_positive` / `escalated`). The model explicitly learns analyst triage decisions from historical operations.
- **Evaluation Ground Truth:** The `incident_labels.csv` (`confirmed_incident`) table is strictly reserved as an untouchable evaluation oracle. The model never sees confirmation labels during training, preventing label contamination and allowing rigorous safety validation against actual breaches.

---

## 2. Training Data & Temporal Split

- **Data Source:** SQLite database (`data/soc_assistant.db`) consolidating 50,442 rows across `alerts`, `endpoint_context`, `analyst_decisions`, and Phase 1 `recommendations`.
- **Temporal Split Methodology:**
  - **Training Partition:** Days 1 through 24 (2026-07-01 to 2026-07-24) — 9,918 alerts.
  - **Held-Out Temporal Test Partition:** Days 25 through 30 (2026-07-25 to 2026-07-31) — 2,690 alerts.
- **Why Temporal (Not Random) Split:** Random cross-validation leaks future threat campaigns, recurrent IP addresses, and operational drift into the training partition. A forward-in-time temporal split reflects true deployment conditions where the system evaluates unseen future days.

---

## 3. Features & Preprocessing

The model uses 13 base features across four distinct categories:

1. **Alert Telemetry:** `alert_type`, `source_segment`, `severity`, `raw_score`
2. **Host Endpoint Context:** `device_type`, `patch_status`, `is_managed_device_clean`, `known_vuln_count_clean`, `user_type`
3. **Phase 1 Historical Feature Transfer:**
   - `historical_fp_rate`: Carried over from the Phase 1 evidence engine. Computed exclusively over historical training observations to reflect pattern base rates.
4. **Security & Anomaly Signals:**
   - `is_external_dst`: Binary RFC1918 indicator (1 if destination IP is public/external, e.g. 8.8.8.8).
   - `has_missing_context`: Binary flag for missing MDM/asset records.
   - `anomaly_signal_count`: Composite anomaly count (unmanaged, unpatched, high vulnerabilities, external traffic).

### Feature Transformations
- Categorical features are encoded via `OneHotEncoder(handle_unknown='ignore')`.
- Numerical features are normalized via `StandardScaler()`.

---

## 4. Performance Comparison: LightGBM vs. Logistic Regression

Evaluated on the held-out temporal test set (Days 25–30, 2,690 alerts):

| Metric | Logistic Regression (Baseline-of-Baseline) | LightGBM Classifier (Primary Model) | Delta (Improvement) |
|---|---|---|---|
| **ROC-AUC** | 0.9302 | **0.9248** | +-0.0054 |
| **Accuracy** | 0.9342 | **0.9335** | +-0.0007 |
| **Precision** | 0.9333 | **0.9324** | +-0.0009 |
| **Recall (FP)** | 0.9741 | **0.9741** | +0.0000 |
| **F1-Score** | 0.9533 | **0.9528** | +-0.0005 |

---

## 5. Top 10 Contributing Features

Feature importance values extracted from LightGBM:

| Rank | Feature Name | Importance (Splits) |
|---|---|---|
| 1 | `num__raw_score` | 1753.0 |
| 2 | `num__historical_fp_rate` | 634.0 |
| 3 | `num__known_vuln_count_clean` | 497.0 |
| 4 | `num__severity` | 396.0 |
| 5 | `num__anomaly_signal_count` | 196.0 |
| 6 | `cat__device_type_tablet` | 149.0 |
| 7 | `cat__patch_status_fully_patched` | 125.0 |
| 8 | `cat__patch_status_partially_patched` | 123.0 |
| 9 | `cat__device_type_unknown` | 90.0 |
| 10 | `cat__device_type_laptop` | 75.0 |

`historical_fp_rate` (inherited from Phase 1) and endpoint context signals (`patch_status`, `raw_score`, `anomaly_signal_count`) are the top drivers of predictions.

---

## 6. Safety Guardrails & Threshold Calibration

- **Controlled Missed-Incident Ceiling:** $\le 2.0\%$.
- **Calibrated Auto-Suggest Threshold:** `0.97`.
- **Achieved Missed Incident Rate:** `0.97%` across `619` confirmed incidents in the temporal test set.
- Alerts with predicted FP probability $P(\text{FP}) \ge 0.97$ are eligible for `suggest_fp`.
- Borderline alerts or alerts with anomaly signals are routed to human analysts with `requires_human_confirmation = True`.

---

## 7. Known Limitations & Operational Considerations

1. **Concept Drift:** As campus network behavior changes across academic semesters (e.g. exams vs summer breaks), pattern FP rates may shift. Retraining is recommended monthly.
2. **Missing Asset Telemetry:** For unmanaged BYOD devices where asset inventory cannot reach the host, context features default to neutral missing flags, triggering the fallback anomaly safety path.
3. **Dual Endpoint Deployment:** Both `/alerts/{id}/recommend` (Phase 1 rule-based) and `/alerts/{id}/recommend_v2` (Phase 2 ML) operate concurrently to support A/B auditing and viva verification.
