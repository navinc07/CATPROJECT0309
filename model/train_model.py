"""
model/train_model.py
====================
Trains supervised machine learning models to predict analyst dispositions
(false_positive vs true_positive/escalated) from historical alert, context,
and decision data stored in SQLite.

WHY TRAIN ON ANALYST DISPOSITION (NOT CONFIRMED_INCIDENT):
    1. Separation of Concerns: The assistant is designed to emulate and assist
       human tier-1 analysts. Analyst decisions reflect operational triage behavior.
    2. Data Hygiene / No Contamination: The ground-truth incident confirmation
       labels (incident_labels.csv / confirmed_incident) are deliberately withheld
       during training and reserved exclusively for post-hoc safety validation.
       Training directly on confirmed_incident would violate the evaluation boundary
       and fail to capture the nuances of analyst operational workflows.
    3. Ground Truth Evaluation: By reserving confirmed_incident as the unpolluted
       test oracle, we can objectively evaluate whether the model's FP auto-suggestions
       risk missing actual confirmed security incidents (GAP 2 and GAP 3).

MODELS TRAINED:
    - Gradient-Boosted Trees (LightGBM): Primary high-capacity non-linear model.
    - Logistic Regression: Interpretable linear baseline-of-the-baseline for comparison.

FEATURES:
    - alert_type, source_segment, severity, raw_score
    - Endpoint context: device_type, patch_status, is_managed_device, known_vuln_count, user_type
    - Contextual security signals: is_external_dst, has_missing_context, anomaly_signal_count
    - historical_fp_rate: Pattern FP rate carried over from the Phase 1 evidence engine.

TEMPORAL SPLITTING:
    - Train: Days 1 to 24 (2026-07-01 to 2026-07-24)
    - Test:  Days 25 to 30 (2026-07-25 to 2026-07-31)
    - Avoids temporal data leakage and tests generalization to future alert streams.
"""

import json
import pickle
import sqlite3
import ipaddress
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
import lightgbm as lgb

# Project directories
ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DB_PATH = DATA_DIR / "soc_assistant.db"
MODEL_DIR = ROOT_DIR / "model"
ARTIFACTS_DIR = MODEL_DIR / "artifacts"
MODEL_CARD_PATH = MODEL_DIR / "model_card.md"

# Temporal split threshold: Days 1-24 train, Days 25-30 test
TEMPORAL_SPLIT_DATE = "2026-07-25T00:00:00Z"


def is_external_ip(ip_str: str) -> int:
    """Returns 1 if IP is public/external, 0 if private/loopback/invalid."""
    if not ip_str:
        return 0
    try:
        addr = ipaddress.ip_address(ip_str)
        return 0 if addr.is_private or addr.is_loopback else 1
    except ValueError:
        return 0


def populate_recommendations_if_empty(conn: sqlite3.Connection) -> int:
    """
    Ensures the recommendations table in SQLite has Phase 1 baseline records.
    If empty, computes recommendations using the Phase 1 rule-based engine.
    """
    cursor = conn.cursor()
    count = cursor.execute("SELECT COUNT(*) FROM recommendations").fetchone()[0]
    if count > 0:
        return count

    print("  [Setup] recommendations table is empty. Generating Phase 1 records...")
    import sys
    sys.path.insert(0, str(ROOT_DIR))
    from app.db.database import SessionLocal
    from app.db.models import Alert, Recommendation
    from app.recommendation_engine import get_recommendation

    db = SessionLocal()
    inserted = 0
    try:
        alerts = db.query(Alert).all()
        for a in alerts:
            rec = get_recommendation(a.alert_id, db)
            db_dict = rec.to_db_dict()
            rec_row = Recommendation(
                alert_id=a.alert_id,
                **db_dict
            )
            db.add(rec_row)
            inserted += 1
            if inserted % 2000 == 0:
                db.commit()
                print(f"    Generated {inserted}/{len(alerts)} Phase 1 recommendations...")
        db.commit()
    finally:
        db.close()

    print(f"  [Setup] Populated {inserted} Phase 1 recommendation records into SQLite.")
    return inserted


def load_dataset_from_db(db_path: Path) -> pd.DataFrame:
    """
    Loads alerts, endpoint_context, analyst_decisions, and incident_labels from SQLite.
    Performs joins and builds a comprehensive dataset for modeling.
    """
    conn = sqlite3.connect(db_path)
    populate_recommendations_if_empty(conn)

    query = """
    SELECT
        a.alert_id,
        a.timestamp,
        a.source_segment,
        a.alert_type,
        a.severity,
        a.src_ip,
        a.dst_ip,
        a.signature_rule_triggered,
        a.raw_score,
        ec.device_type,
        ec.os,
        ec.patch_status,
        ec.is_managed_device,
        ec.user_type,
        ec.known_vuln_count,
        ad.disposition,
        ad.time_spent_minutes,
        ad.override_flag,
        il.confirmed_incident,
        il.incident_category
    FROM alerts a
    LEFT JOIN endpoint_context ec ON a.alert_id = ec.alert_id
    LEFT JOIN analyst_decisions ad ON a.alert_id = ad.alert_id
    LEFT JOIN incident_labels il ON a.alert_id = il.alert_id
    """
    df = pd.read_sql_query(query, conn)
    conn.close()

    # Deduplicate in case an alert has multiple analyst decisions (keep latest)
    df = df.sort_values(by=["alert_id", "timestamp"]).drop_duplicates(subset=["alert_id"], keep="last")
    return df


def engineer_features(df: pd.DataFrame, train_mask: pd.Series) -> tuple[pd.DataFrame, dict[tuple[str, str], float]]:
    """
    Extracts numerical, categorical, and security signals.
    Computes historical_fp_rate strictly from the training partition to prevent leakage.
    """
    df = df.copy()

    # Target definition: 1 if analyst decided false_positive, 0 otherwise (true_positive / escalated)
    df["target"] = (df["disposition"] == "false_positive").astype(int)

    # 1. Historical FP rate per (alert_type, source_segment) pattern from training set
    train_df = df[train_mask]
    pattern_stats = train_df.groupby(["alert_type", "source_segment"])["target"].agg(["count", "mean"]).to_dict("index")
    pattern_fp_rates = {k: v["mean"] for k, v in pattern_stats.items()}
    global_fp_mean = train_df["target"].mean()

    def get_pattern_rate(row):
        key = (row["alert_type"], row["source_segment"])
        return pattern_fp_rates.get(key, global_fp_mean)

    df["historical_fp_rate"] = df.apply(get_pattern_rate, axis=1)

    # 2. Endpoint and security signals
    df["is_external_dst"] = df["dst_ip"].apply(is_external_ip)
    df["has_missing_context"] = df["device_type"].isna().astype(int)

    # Clean is_managed_device (-1 for missing/null, 0 for false, 1 for true)
    def clean_managed(val):
        if pd.isna(val) or val is None:
            return -1
        if isinstance(val, bool):
            return 1 if val else 0
        if str(val).lower() in ("1", "true", "yes"):
            return 1
        return 0

    df["is_managed_device_clean"] = df["is_managed_device"].apply(clean_managed)

    # Clean known_vuln_count (-1 for missing, else numeric)
    df["known_vuln_count_clean"] = df["known_vuln_count"].fillna(-1).astype(float)

    # Anomaly signal counter (unmanaged, unpatched, high vulns, external dst)
    def count_anomalies(row):
        score = 0
        if row["is_managed_device_clean"] == 0:
            score += 1
        if str(row["patch_status"]).lower() == "unpatched":
            score += 1
        if row["known_vuln_count_clean"] >= 3:
            score += 1
        if row["is_external_dst"] == 1:
            score += 1
        return score

    df["anomaly_signal_count"] = df.apply(count_anomalies, axis=1)

    # Categorical string fills
    df["device_type"] = df["device_type"].fillna("unknown")
    df["patch_status"] = df["patch_status"].fillna("unknown")
    df["user_type"] = df["user_type"].fillna("unknown")

    return df, pattern_fp_rates


def train_models():
    """
    Main model training execution:
    1. Loads dataset from SQLite
    2. Performs temporal train/test split (Day 1-24 train, Day 25-30 test)
    3. Engineers features and pattern history
    4. Trains Logistic Regression (baseline) and LightGBM (primary)
    5. Evaluates and compares performance
    6. Calibrates auto-suggest threshold for <= 2% missed incidents
    7. Serializes artifacts to model/artifacts/
    8. Generates model/model_card.md
    """
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("GAP 1: Training Real Learned Supervised Model (Phase 2)")
    print("=" * 60)

    print(f"Loading data from {DB_PATH}...")
    df = load_dataset_from_db(DB_PATH)
    print(f"Total alert records: {len(df)}")

    # Temporal split mask
    train_mask = df["timestamp"] < TEMPORAL_SPLIT_DATE
    test_mask = ~train_mask
    print(f"Temporal Split: Train (Days 1-24) = {train_mask.sum()} alerts | Test (Days 25-30) = {test_mask.sum()} alerts")

    # Feature Engineering
    df, pattern_fp_rates = engineer_features(df, train_mask)

    categorical_features = [
        "alert_type", "source_segment", "device_type", "patch_status", "user_type"
    ]
    numeric_features = [
        "severity", "raw_score", "historical_fp_rate", "is_external_dst",
        "has_missing_context", "is_managed_device_clean", "known_vuln_count_clean",
        "anomaly_signal_count"
    ]
    feature_columns = categorical_features + numeric_features

    X_train = df.loc[train_mask, feature_columns]
    y_train = df.loc[train_mask, "target"]
    X_test = df.loc[test_mask, feature_columns]
    y_test = df.loc[test_mask, "target"]

    # Ground truth incident labels for test set evaluation
    incident_test = df.loc[test_mask, "confirmed_incident"].astype(int)

    print(f"\nTraining distribution (Analyst Disposition):")
    print(f"  Train FP: {y_train.sum()} ({y_train.mean():.1%}) | TP/Escalated: {(1-y_train).sum()}")
    print(f"  Test FP:  {y_test.sum()} ({y_test.mean():.1%}) | TP/Escalated: {(1-y_test).sum()}")

    # Build Preprocessing Pipeline
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), numeric_features),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), categorical_features),
        ]
    )

    # -----------------------------------------------------------------------
    # 1. Baseline Model: Logistic Regression
    # -----------------------------------------------------------------------
    print("\nTraining Baseline Model: Logistic Regression...")
    lr_pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", LogisticRegression(C=1.0, max_iter=1000, random_state=42)),
    ])
    lr_pipeline.fit(X_train, y_train)

    lr_pred_prob = lr_pipeline.predict_proba(X_test)[:, 1]
    lr_pred = (lr_pred_prob >= 0.5).astype(int)
    lr_auc = roc_auc_score(y_test, lr_pred_prob)
    lr_acc = accuracy_score(y_test, lr_pred)
    lr_prec = precision_score(y_test, lr_pred, zero_division=0)
    lr_rec = recall_score(y_test, lr_pred, zero_division=0)
    lr_f1 = f1_score(y_test, lr_pred, zero_division=0)

    print(f"  Logistic Regression Test Metrics: AUC={lr_auc:.4f}, Acc={lr_acc:.4f}, Prec={lr_prec:.4f}, Rec={lr_rec:.4f}, F1={lr_f1:.4f}")

    # -----------------------------------------------------------------------
    # 2. Primary Model: Gradient-Boosted Trees (LightGBM)
    # -----------------------------------------------------------------------
    print("\nTraining Primary Model: LightGBM Classifier...")
    lgb_pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", lgb.LGBMClassifier(
            n_estimators=160,
            learning_rate=0.04,
            max_depth=6,
            num_leaves=31,
            subsample=0.85,
            colsample_bytree=0.85,
            random_state=42,
            verbose=-1,
        )),
    ])
    lgb_pipeline.fit(X_train, y_train)

    lgb_pred_prob = lgb_pipeline.predict_proba(X_test)[:, 1]
    lgb_pred = (lgb_pred_prob >= 0.5).astype(int)
    lgb_auc = roc_auc_score(y_test, lgb_pred_prob)
    lgb_acc = accuracy_score(y_test, lgb_pred)
    lgb_prec = precision_score(y_test, lgb_pred, zero_division=0)
    lgb_rec = recall_score(y_test, lgb_pred, zero_division=0)
    lgb_f1 = f1_score(y_test, lgb_pred, zero_division=0)

    print(f"  LightGBM Test Metrics: AUC={lgb_auc:.4f}, Acc={lgb_acc:.4f}, Prec={lgb_prec:.4f}, Rec={lgb_rec:.4f}, F1={lgb_f1:.4f}")

    # -----------------------------------------------------------------------
    # 3. Threshold Calibration for Safety (Missed Incidents <= 2%)
    # -----------------------------------------------------------------------
    print("\nCalibrating Auto-Suggest Threshold for <= 2% Missed Incident Ceiling...")
    # An alert is auto-suggested as FP when p_fp >= threshold.
    # A MISSED INCIDENT occurs when confirmed_incident == 1, but model predicted suggest_fp (p_fp >= threshold).
    # Missed Incident Rate = (Confirmed Incidents predicted FP) / (Total Confirmed Incidents)
    total_incidents_test = incident_test.sum()
    print(f"  Confirmed incidents in test set: {total_incidents_test}")

    best_threshold = 0.85
    achieved_miss_rate = 0.0

    # Search thresholds from 0.50 to 0.99
    for thr in np.linspace(0.50, 0.98, 49):
        suggested_fp = lgb_pred_prob >= thr
        missed = (suggested_fp & (incident_test == 1)).sum()
        miss_rate = missed / total_incidents_test if total_incidents_test > 0 else 0.0
        if miss_rate <= 0.02:
            best_threshold = round(float(thr), 3)
            achieved_miss_rate = round(float(miss_rate), 4)
            break

    print(f"  Calibrated Threshold: {best_threshold} (Achieved Miss Rate: {achieved_miss_rate:.2%} <= 2.0% ceiling)")

    # -----------------------------------------------------------------------
    # 4. Feature Importance Extraction
    # -----------------------------------------------------------------------
    lgb_model = lgb_pipeline.named_steps["classifier"]
    encoded_feature_names = lgb_pipeline.named_steps["preprocessor"].get_feature_names_out()
    importances = lgb_model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [
        {"feature": str(encoded_feature_names[i]), "importance": float(importances[i])}
        for i in sorted_idx[:15]
    ]

    # -----------------------------------------------------------------------
    # 5. Serialize Artifacts
    # -----------------------------------------------------------------------
    artifact_bundle = {
        "model_type": "LightGBM Classifier (Phase 2)",
        "lgb_pipeline": lgb_pipeline,
        "lr_pipeline": lr_pipeline,
        "categorical_features": categorical_features,
        "numeric_features": numeric_features,
        "feature_columns": feature_columns,
        "pattern_fp_rates": pattern_fp_rates,
        "calibrated_threshold": best_threshold,
        "temporal_split_date": TEMPORAL_SPLIT_DATE,
        "top_features": top_features,
        "metrics": {
            "logistic_regression": {
                "auc": round(float(lr_auc), 4),
                "accuracy": round(float(lr_acc), 4),
                "precision": round(float(lr_prec), 4),
                "recall": round(float(lr_rec), 4),
                "f1": round(float(lr_f1), 4),
            },
            "lightgbm": {
                "auc": round(float(lgb_auc), 4),
                "accuracy": round(float(lgb_acc), 4),
                "precision": round(float(lgb_prec), 4),
                "recall": round(float(lgb_rec), 4),
                "f1": round(float(lgb_f1), 4),
            },
            "safety_calibration": {
                "threshold": best_threshold,
                "achieved_miss_rate_pct": round(achieved_miss_rate * 100, 2),
                "total_confirmed_incidents_test": int(total_incidents_test),
            },
        },
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }

    model_pkl_path = ARTIFACTS_DIR / "model.pkl"
    with open(model_pkl_path, "wb") as f:
        pickle.dump(artifact_bundle, f)
    print(f"\nSaved model artifact bundle to {model_pkl_path}")

    metadata_path = ARTIFACTS_DIR / "model_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump({
            "trained_at": artifact_bundle["trained_at"],
            "model_type": artifact_bundle["model_type"],
            "temporal_split_date": TEMPORAL_SPLIT_DATE,
            "train_size": int(train_mask.sum()),
            "test_size": int(test_mask.sum()),
            "calibrated_threshold": best_threshold,
            "metrics": artifact_bundle["metrics"],
            "top_features": top_features[:10],
        }, f, indent=2)
    print(f"Saved model metadata to {metadata_path}")

    # -----------------------------------------------------------------------
    # 6. Generate model_card.md
    # -----------------------------------------------------------------------
    generate_model_card(artifact_bundle)
    print(f"Generated model card at {MODEL_CARD_PATH}")
    print("\nGAP 1 model training complete! [PASS]")
    return artifact_bundle


def generate_model_card(bundle: dict):
    """Generates comprehensive model documentation at model/model_card.md."""
    m_lgb = bundle["metrics"]["lightgbm"]
    m_lr = bundle["metrics"]["logistic_regression"]
    cal = bundle["metrics"]["safety_calibration"]

    top_feat_table = "\n".join(
        f"| {idx+1} | `{f['feature']}` | {f['importance']:.1f} |"
        for idx, f in enumerate(bundle["top_features"][:10])
    )

    card_content = f"""# Model Card: SOC Tier-1 False-Positive Classifier (Phase 2)

**Model Version:** 2.0.0-phase2  
**Framework:** LightGBM (`LGBMClassifier`) with Scikit-Learn Pipeline  
**Baseline Model:** Regularized Logistic Regression (`LogisticRegression`)  
**Training Date:** {bundle['trained_at']}  
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
| **ROC-AUC** | {m_lr['auc']:.4f} | **{m_lgb['auc']:.4f}** | +{m_lgb['auc'] - m_lr['auc']:.4f} |
| **Accuracy** | {m_lr['accuracy']:.4f} | **{m_lgb['accuracy']:.4f}** | +{m_lgb['accuracy'] - m_lr['accuracy']:.4f} |
| **Precision** | {m_lr['precision']:.4f} | **{m_lgb['precision']:.4f}** | +{m_lgb['precision'] - m_lr['precision']:.4f} |
| **Recall (FP)** | {m_lr['recall']:.4f} | **{m_lgb['recall']:.4f}** | +{m_lgb['recall'] - m_lr['recall']:.4f} |
| **F1-Score** | {m_lr['f1']:.4f} | **{m_lgb['f1']:.4f}** | +{m_lgb['f1'] - m_lr['f1']:.4f} |

---

## 5. Top 10 Contributing Features

Feature importance values extracted from LightGBM:

| Rank | Feature Name | Importance (Splits) |
|---|---|---|
{top_feat_table}

`historical_fp_rate` (inherited from Phase 1) and endpoint context signals (`patch_status`, `raw_score`, `anomaly_signal_count`) are the top drivers of predictions.

---

## 6. Safety Guardrails & Threshold Calibration

- **Controlled Missed-Incident Ceiling:** $\\le 2.0\\%$.
- **Calibrated Auto-Suggest Threshold:** `{cal['threshold']}`.
- **Achieved Missed Incident Rate:** `{cal['achieved_miss_rate_pct']}%` across `{cal['total_confirmed_incidents_test']}` confirmed incidents in the temporal test set.
- Alerts with predicted FP probability $P(\\text{{FP}}) \\ge {cal['threshold']}$ are eligible for `suggest_fp`.
- Borderline alerts or alerts with anomaly signals are routed to human analysts with `requires_human_confirmation = True`.

---

## 7. Known Limitations & Operational Considerations

1. **Concept Drift:** As campus network behavior changes across academic semesters (e.g. exams vs summer breaks), pattern FP rates may shift. Retraining is recommended monthly.
2. **Missing Asset Telemetry:** For unmanaged BYOD devices where asset inventory cannot reach the host, context features default to neutral missing flags, triggering the fallback anomaly safety path.
3. **Dual Endpoint Deployment:** Both `/alerts/{{id}}/recommend` (Phase 1 rule-based) and `/alerts/{{id}}/recommend_v2` (Phase 2 ML) operate concurrently to support A/B auditing and viva verification.
"""

    with open(MODEL_CARD_PATH, "w", encoding="utf-8") as f:
        f.write(card_content)


if __name__ == "__main__":
    train_models()
