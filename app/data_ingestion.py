"""
app/data_ingestion.py
=====================
Loads the synthetic CSV files into the SQLite database.

WHY A SEPARATE INGESTION SCRIPT (not inline in main.py):
    Keeping ingestion separate from the API server means:
    (a) It can be run independently (e.g., in CI to reset test state).
    (b) It can be extended to support streaming ingestion from a live SIEM
        in Phase 3 without touching the API code.
    (c) The API server startup (lifespan) calls init_db() only, not ingestion —
        ingestion is a one-time or scheduled operation, not per-request.

Usage:
    python app/data_ingestion.py
    (Run AFTER: python data/generate_synthetic_data.py)
"""

import csv
import sys
from pathlib import Path
from datetime import datetime, timezone

# Add project root to path for relative imports when run as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.db.database import SessionLocal, init_db
from app.db.models import Alert, AnalystDecision, EndpointContext, IncidentLabel

DATA_DIR = Path(__file__).parent.parent / "data"


def _safe_bool(val: str) -> bool | None:
    """Parse CSV boolean strings including null values."""
    if val in (None, "", "None", "none"):
        return None
    return val.strip().lower() in ("true", "1", "yes")


def _safe_int(val: str) -> int | None:
    """Parse CSV integer strings including null values."""
    if val in (None, "", "None", "none"):
        return None
    try:
        return int(val)
    except ValueError:
        return None


def _safe_float(val: str) -> float | None:
    """Parse CSV float strings including null values."""
    if val in (None, "", "None", "none"):
        return None
    try:
        return float(val)
    except ValueError:
        return None


def load_alerts(db, filepath: Path) -> int:
    """
    Load alerts.csv into the alerts table.
    Returns the number of rows inserted.
    Skips rows where the alert_id already exists (idempotent).
    """
    count = 0
    with open(filepath, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            existing = db.query(Alert).filter(Alert.alert_id == row["alert_id"]).first()
            if existing:
                continue
            alert = Alert(
                alert_id=row["alert_id"],
                timestamp=row["timestamp"],
                source_segment=row["source_segment"],
                alert_type=row["alert_type"],
                severity=int(row["severity"]),
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                signature_rule_triggered=row["signature_rule_triggered"],
                raw_score=float(row["raw_score"]),
            )
            db.add(alert)
            count += 1
    db.commit()
    return count


def load_analyst_decisions(db, filepath: Path) -> int:
    """
    Load analyst_decisions.csv into the analyst_decisions table.
    Skips rows where the alert_id does not exist in alerts (referential integrity).
    """
    count = 0
    with open(filepath, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            alert_exists = db.query(Alert).filter(
                Alert.alert_id == row["alert_id"]
            ).first()
            if not alert_exists:
                continue
            decision = AnalystDecision(
                alert_id=row["alert_id"],
                analyst_id=row["analyst_id"],
                analyst_role=row["analyst_role"],
                disposition=row["disposition"],
                time_spent_minutes=_safe_int(row["time_spent_minutes"]),
                decision_timestamp=row["decision_timestamp"],
                override_flag=_safe_bool(row["override_flag"]) or False,
                override_reason=row["override_reason"] if row["override_reason"] not in ("None", "", None) else None,
            )
            db.add(decision)
            count += 1
    db.commit()
    return count


def load_endpoint_context(db, filepath: Path) -> int:
    """
    Load endpoint_context.csv into the endpoint_context table.
    Skips if alert_id already has a context record.
    """
    count = 0
    with open(filepath, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            existing = db.query(EndpointContext).filter(
                EndpointContext.alert_id == row["alert_id"]
            ).first()
            if existing:
                continue
            alert_exists = db.query(Alert).filter(
                Alert.alert_id == row["alert_id"]
            ).first()
            if not alert_exists:
                continue
            ctx = EndpointContext(
                alert_id=row["alert_id"],
                device_type=row.get("device_type") or None,
                os=row.get("os") or None,
                patch_status=row.get("patch_status") or None,
                is_managed_device=_safe_bool(row.get("is_managed_device", "")),
                user_type=row.get("user_type") or None,
                known_vuln_count=_safe_int(row.get("known_vuln_count", "")),
            )
            db.add(ctx)
            count += 1
    db.commit()
    return count


def load_incident_labels(db, filepath: Path) -> int:
    """
    Load incident_labels.csv into the incident_labels table.
    Skips if alert_id already has a label record.
    """
    count = 0
    with open(filepath, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            existing = db.query(IncidentLabel).filter(
                IncidentLabel.alert_id == row["alert_id"]
            ).first()
            if existing:
                continue
            alert_exists = db.query(Alert).filter(
                Alert.alert_id == row["alert_id"]
            ).first()
            if not alert_exists:
                continue
            label = IncidentLabel(
                alert_id=row["alert_id"],
                confirmed_incident=_safe_bool(row["confirmed_incident"]) or False,
                incident_category=row.get("incident_category") or None,
                confirmed_by=row.get("confirmed_by") or None,
                confirmation_date=row.get("confirmation_date") or None,
            )
            db.add(label)
            count += 1
    db.commit()
    return count


def run_ingestion(verbose: bool = True) -> dict[str, int]:
    """
    Main ingestion function. Loads all four CSV files in dependency order
    (alerts first, then related tables).
    Returns counts of inserted rows per table.
    """
    init_db()
    db = SessionLocal()

    results = {}
    try:
        for csv_name, loader, table_name in [
            ("alerts.csv", load_alerts, "alerts"),
            ("analyst_decisions.csv", load_analyst_decisions, "analyst_decisions"),
            ("endpoint_context.csv", load_endpoint_context, "endpoint_context"),
            ("incident_labels.csv", load_incident_labels, "incident_labels"),
        ]:
            filepath = DATA_DIR / csv_name
            if not filepath.exists():
                print(f"  WARNING: {csv_name} not found. Skipping.")
                results[table_name] = 0
                continue
            count = loader(db, filepath)
            results[table_name] = count
            if verbose:
                print(f"  {table_name}: {count} rows inserted")

    finally:
        db.close()

    return results


if __name__ == "__main__":
    print("=" * 60)
    print("Data Ingestion — University SOC FP Reduction Assistant")
    print("=" * 60)
    print("\nIngesting CSV files into SQLite database...")
    results = run_ingestion(verbose=True)
    total = sum(results.values())
    print(f"\nIngestion complete. Total rows inserted: {total}")
    print(f"Database: {Path(__file__).parent.parent / 'data' / 'soc_assistant.db'}")
