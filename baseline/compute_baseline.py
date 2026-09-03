"""
compute_baseline.py
===================
Computes the BEFORE state — the current-state baseline metrics from the
synthetic dataset BEFORE any assistant is introduced.

WHY THIS MATTERS:
    Every "efficiency improvement" claim in Phase 2 must be measured against
    a documented, reproducible baseline. Without this script, the before/after
    comparison would be anecdotal. This script produces the denominator for
    all Phase 2 measurements.

WHAT IS MEASURED:
    1. Total analyst-hours spent across all alerts.
    2. FP rate overall and per segment.
    3. Average time-per-alert by segment and by alert type.
    4. Alert volume distribution.
    5. Override rate (signals analyst disagreement — useful for model training).
    6. Confirmed incident rate.
    7. Estimated "wasted" analyst-hours on FPs (opportunity cost).

OUTPUT:
    baseline/baseline_report.md — formatted markdown report with tables
    (also printed to stdout for CI/log capture)

Usage:
    python baseline/compute_baseline.py
    (Run AFTER: python data/generate_synthetic_data.py)
"""

import csv
import os
from collections import defaultdict
from pathlib import Path
from datetime import datetime

DATA_DIR = Path(__file__).parent.parent / "data"
OUTPUT_DIR = Path(__file__).parent
REPORT_PATH = OUTPUT_DIR / "baseline_report.md"

# ---------------------------------------------------------------------------
# CSV loading helpers
# ---------------------------------------------------------------------------

def load_csv(filename: str) -> list[dict]:
    """Load a CSV file from the data directory into a list of dicts."""
    path = DATA_DIR / filename
    if not path.exists():
        raise FileNotFoundError(
            f"Required file not found: {path}\n"
            "Run: python data/generate_synthetic_data.py first."
        )
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def safe_float(val, default=0.0) -> float:
    try:
        return float(val) if val not in (None, "", "None") else default
    except (ValueError, TypeError):
        return default


def safe_int(val, default=0) -> int:
    try:
        return int(val) if val not in (None, "", "None") else default
    except (ValueError, TypeError):
        return default


def safe_bool(val) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes")
    return False


# ---------------------------------------------------------------------------
# Baseline computation functions
# ---------------------------------------------------------------------------

def compute_alert_volume(alerts: list[dict]) -> dict:
    """Count alerts by segment and alert type."""
    by_segment = defaultdict(int)
    by_type = defaultdict(int)
    by_severity = defaultdict(int)

    for a in alerts:
        by_segment[a["source_segment"]] += 1
        by_type[a["alert_type"]] += 1
        by_severity[a["severity"]] += 1

    return {
        "total": len(alerts),
        "by_segment": dict(sorted(by_segment.items(), key=lambda x: -x[1])),
        "by_type": dict(sorted(by_type.items(), key=lambda x: -x[1])),
        "by_severity": dict(sorted(by_severity.items(), key=lambda x: x[0])),
    }


def compute_fp_tp_rates(decisions: list[dict]) -> dict:
    """Compute overall and per-segment FP/TP rates."""
    # Build alert_id → segment map from alerts
    alerts_raw = load_csv("alerts.csv")
    seg_map = {a["alert_id"]: a["source_segment"] for a in alerts_raw}
    type_map = {a["alert_id"]: a["alert_type"] for a in alerts_raw}

    overall = defaultdict(int)
    by_segment: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    by_type: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for d in decisions:
        disp = d["disposition"]
        seg = seg_map.get(d["alert_id"], "unknown")
        atype = type_map.get(d["alert_id"], "unknown")

        overall[disp] += 1
        by_segment[seg][disp] += 1
        by_type[atype][disp] += 1

    return {
        "overall": dict(overall),
        "by_segment": {seg: dict(counts) for seg, counts in by_segment.items()},
        "by_type": {atype: dict(counts) for atype, counts in by_type.items()},
    }


def compute_time_metrics(decisions: list[dict]) -> dict:
    """Compute analyst time metrics."""
    alerts_raw = load_csv("alerts.csv")
    seg_map = {a["alert_id"]: a["source_segment"] for a in alerts_raw}
    type_map = {a["alert_id"]: a["alert_type"] for a in alerts_raw}

    total_minutes = 0
    by_disposition: dict[str, list[int]] = defaultdict(list)
    by_segment: dict[str, list[int]] = defaultdict(list)
    by_type: dict[str, list[int]] = defaultdict(list)
    per_alert_times = []

    for d in decisions:
        mins = safe_int(d["time_spent_minutes"])
        disp = d["disposition"]
        seg = seg_map.get(d["alert_id"], "unknown")
        atype = type_map.get(d["alert_id"], "unknown")

        total_minutes += mins
        per_alert_times.append(mins)
        by_disposition[disp].append(mins)
        by_segment[seg].append(mins)
        by_type[atype].append(mins)

    def avg(lst): return sum(lst) / len(lst) if lst else 0
    def total(lst): return sum(lst)

    return {
        "total_analyst_minutes": total_minutes,
        "total_analyst_hours": round(total_minutes / 60, 2),
        "mean_minutes_per_alert": round(avg(per_alert_times), 2),
        "by_disposition": {
            disp: {
                "count": len(times),
                "total_minutes": total(times),
                "avg_minutes": round(avg(times), 2),
                "total_hours": round(total(times) / 60, 2),
            }
            for disp, times in by_disposition.items()
        },
        "by_segment": {
            seg: {
                "count": len(times),
                "total_minutes": total(times),
                "avg_minutes": round(avg(times), 2),
                "total_hours": round(total(times) / 60, 2),
            }
            for seg, times in by_segment.items()
        },
        "by_type": {
            atype: {
                "count": len(times),
                "total_minutes": total(times),
                "avg_minutes": round(avg(times), 2),
                "total_hours": round(total(times) / 60, 2),
            }
            for atype, times in sorted(by_type.items(), key=lambda x: -sum(x[1]))
        },
    }


def compute_override_metrics(decisions: list[dict]) -> dict:
    """Compute override rate and breakdown."""
    total = len(decisions)
    overrides = [d for d in decisions if safe_bool(d["override_flag"])]
    override_count = len(overrides)

    by_disp: dict[str, int] = defaultdict(int)
    for d in overrides:
        by_disp[d["disposition"]] += 1

    # Count unique override reasons
    reasons = [d["override_reason"] for d in overrides if d["override_reason"]]

    return {
        "total_decisions": total,
        "total_overrides": override_count,
        "override_rate_pct": round(100 * override_count / total, 2) if total else 0,
        "overrides_by_disposition": dict(by_disp),
        "distinct_override_reasons_count": len(set(reasons)),
        "sample_override_reasons": list(set(reasons))[:5],
    }


def compute_incident_metrics(labels: list[dict]) -> dict:
    """Compute confirmed incident rate and category breakdown."""
    total = len(labels)
    confirmed = [l for l in labels if safe_bool(l["confirmed_incident"])]

    by_category: dict[str, int] = defaultdict(int)
    for l in confirmed:
        cat = l.get("incident_category") or "uncategorised"
        by_category[cat] += 1

    return {
        "total_alerts": total,
        "confirmed_incidents": len(confirmed),
        "incident_rate_pct": round(100 * len(confirmed) / total, 2) if total else 0,
        "by_category": dict(sorted(by_category.items(), key=lambda x: -x[1])),
    }


def compute_wasted_hours(time_metrics: dict, fp_tp_rates: dict) -> dict:
    """
    Compute analyst-hours 'wasted' on false positives.
    
    This is the primary denominator for the Phase 2 efficiency improvement
    claim. Wasted hours = total hours spent on alerts ultimately dispositioned
    as false_positive. These are hours that COULD have been saved with perfect
    FP automation (the theoretical maximum improvement).
    """
    fp_data = time_metrics["by_disposition"].get("false_positive", {})
    total_hours = time_metrics["total_analyst_hours"]
    fp_hours = fp_data.get("total_hours", 0)
    fp_count = fp_data.get("count", 0)

    # Theoretical maximum: if FP automation saves all FP time
    max_savings_hours = fp_hours
    max_savings_pct = round(100 * fp_hours / total_hours, 2) if total_hours else 0

    # Conservative estimate: 60% FP automation efficiency (realistic target)
    conservative_savings = round(fp_hours * 0.60, 2)

    # Per week extrapolation (dataset covers 30 days = ~4.3 weeks)
    days = 30
    weeks = days / 7
    hours_per_week_fp = round(fp_hours / weeks, 2)
    conservative_savings_per_week = round(conservative_savings / weeks, 2)

    return {
        "total_analyst_hours_in_dataset": total_hours,
        "hours_on_false_positives": fp_hours,
        "false_positive_alert_count": fp_count,
        "fp_time_share_pct": max_savings_pct,
        "theoretical_max_savings_hours_30d": max_savings_hours,
        "conservative_savings_60pct_efficiency_30d": conservative_savings,
        "fp_analyst_hours_per_week": hours_per_week_fp,
        "conservative_savings_per_week": conservative_savings_per_week,
        "fte_equivalent_per_week": round(conservative_savings_per_week / 40, 3),
        "note": (
            "FTE equivalent = weekly savings / 40 hours; represents the "
            "analyst capacity freed by 60% FP automation efficiency. "
            "Phase 2 will measure the achieved rate against this ceiling."
        ),
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def build_report(
    volume: dict,
    fp_rates: dict,
    time_metrics: dict,
    override_metrics: dict,
    incident_metrics: dict,
    waste: dict,
    dataset_days: int = 30,
) -> str:
    """Build the baseline_report.md content as a string."""

    lines = [
        "# Baseline Report — Before Assistant Introduction",
        "",
        f"**Project:** C28 — AI Immersion (Semester 5)  ",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Dataset period:** {dataset_days} days (2026-07-01 to 2026-07-30)  ",
        f"**Data source:** Synthetic dataset (seed=42); see `data/README_dataset.md`",
        "",
        "> **Purpose:** This document establishes the BEFORE-state metrics. All",
        "> Phase 2 efficiency improvements will be measured against these numbers.",
        "> Any claim of 'X% FP reduction' or 'Y analyst-hours saved' is only",
        "> meaningful relative to this documented baseline.",
        "",
        "---",
        "",
        "## 1. Alert Volume",
        "",
        f"**Total alerts (30 days):** {volume['total']:,}  ",
        f"**Average per day:** {volume['total'] / dataset_days:.1f}",
        "",
        "### By Network Segment",
        "",
        "| Segment | Alert Count | % of Total | Alerts/Day |",
        "|---|---|---|---|",
    ]
    for seg, count in sorted(volume["by_segment"].items(), key=lambda x: -x[1]):
        pct = 100 * count / volume["total"]
        per_day = count / dataset_days
        lines.append(f"| {seg} | {count:,} | {pct:.1f}% | {per_day:.1f} |")

    lines += [
        "",
        "### By Alert Type",
        "",
        "| Alert Type | Count | % of Total | Alerts/Day |",
        "|---|---|---|---|",
    ]
    for atype, count in list(volume["by_type"].items())[:10]:
        pct = 100 * count / volume["total"]
        per_day = count / dataset_days
        lines.append(f"| {atype} | {count:,} | {pct:.1f}% | {per_day:.1f} |")

    lines += [
        "",
        "---",
        "",
        "## 2. False Positive / True Positive Breakdown",
        "",
        "### Overall Disposition Rates",
        "",
        "| Disposition | Count | % of Total |",
        "|---|---|---|",
    ]
    total_decisions = sum(fp_rates["overall"].values())
    for disp, count in sorted(fp_rates["overall"].items(), key=lambda x: -x[1]):
        pct = 100 * count / total_decisions if total_decisions else 0
        lines.append(f"| {disp} | {count:,} | {pct:.1f}% |")

    lines += [
        "",
        "### FP Rate by Network Segment",
        "",
        "| Segment | FP Count | TP Count | Escalated | FP Rate |",
        "|---|---|---|---|---|",
    ]
    for seg in ["guest", "student", "lab", "admin"]:
        counts = fp_rates["by_segment"].get(seg, {})
        fp = counts.get("false_positive", 0)
        tp = counts.get("true_positive", 0)
        esc = counts.get("escalated", 0)
        total_seg = fp + tp + esc
        fp_rate = 100 * fp / total_seg if total_seg else 0
        lines.append(f"| {seg} | {fp:,} | {tp:,} | {esc:,} | {fp_rate:.1f}% |")

    lines += [
        "",
        "**Observation:** Guest segment has the highest FP rate, confirming the",
        "problem statement. Admin segment has the lowest, confirming that admin",
        "alerts deserve more investigative attention per alert.",
        "",
        "---",
        "",
        "## 3. Analyst Time Metrics",
        "",
        f"**Total analyst-hours across 30-day dataset:** {time_metrics['total_analyst_hours']:,.2f} hours  ",
        f"**Mean minutes per alert:** {time_metrics['mean_minutes_per_alert']:.2f} min",
        "",
        "### Time by Disposition",
        "",
        "| Disposition | Alert Count | Avg Min/Alert | Total Hours | % of Time |",
        "|---|---|---|---|---|",
    ]
    for disp, data in sorted(time_metrics["by_disposition"].items(), key=lambda x: -x[1]["total_hours"]):
        pct = 100 * data["total_hours"] / time_metrics["total_analyst_hours"]
        lines.append(
            f"| {disp} | {data['count']:,} | {data['avg_minutes']} | "
            f"{data['total_hours']:.2f} | {pct:.1f}% |"
        )

    lines += [
        "",
        "### Average Time Per Alert by Segment",
        "",
        "| Segment | Alert Count | Avg Min/Alert | Total Hours |",
        "|---|---|---|---|",
    ]
    for seg in ["guest", "student", "lab", "admin"]:
        data = time_metrics["by_segment"].get(seg, {})
        if data:
            lines.append(
                f"| {seg} | {data['count']:,} | {data['avg_minutes']} | {data['total_hours']:.2f} |"
            )

    lines += [
        "",
        "### Top 5 Alert Types by Total Analyst Hours",
        "",
        "| Alert Type | Count | Avg Min/Alert | Total Hours |",
        "|---|---|---|---|",
    ]
    sorted_types = sorted(
        time_metrics["by_type"].items(),
        key=lambda x: -x[1]["total_hours"]
    )[:5]
    for atype, data in sorted_types:
        lines.append(
            f"| {atype} | {data['count']:,} | {data['avg_minutes']} | {data['total_hours']:.2f} |"
        )

    lines += [
        "",
        "---",
        "",
        "## 4. Analyst Override Analysis",
        "",
        f"**Total decisions:** {override_metrics['total_decisions']:,}  ",
        f"**Total overrides:** {override_metrics['total_overrides']:,}  ",
        f"**Override rate:** {override_metrics['override_rate_pct']:.2f}%",
        "",
        "| Disposition After Override | Count |",
        "|---|---|",
    ]
    for disp, count in override_metrics["overrides_by_disposition"].items():
        lines.append(f"| {disp} | {count:,} |")

    lines += [
        "",
        f"**Distinct override reason phrases:** {override_metrics['distinct_override_reasons_count']}",
        "",
        "Sample override reasons (signals analyst frustration points):",
    ]
    for r in override_metrics["sample_override_reasons"]:
        if r:
            lines.append(f"- *\"{r}\"*")

    lines += [
        "",
        "**Observation:** Override rate in Phase 1 is the baseline. If the Phase 2",
        "assistant recommendations are better calibrated, the override rate should",
        "decrease. A persistently high override rate signals poor recommendation quality.",
        "",
        "---",
        "",
        "## 5. Confirmed Incident Metrics",
        "",
        f"**Total alerts:** {incident_metrics['total_alerts']:,}  ",
        f"**Confirmed incidents:** {incident_metrics['confirmed_incidents']:,}  ",
        f"**Incident rate:** {incident_metrics['incident_rate_pct']:.2f}%",
        "",
        "### Incidents by Category",
        "",
        "| Category | Count |",
        "|---|---|",
    ]
    for cat, count in incident_metrics["by_category"].items():
        lines.append(f"| {cat} | {count:,} |")

    lines += [
        "",
        "---",
        "",
        "## 6. Wasted Analyst-Hours on False Positives",
        "",
        "> This section quantifies the *opportunity cost* of the current workflow —",
        "> the analyst time spent on alerts that were ultimately false positives.",
        "> These are the hours the FP Reduction Assistant aims to reclaim.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total analyst-hours in 30-day dataset | {waste['total_analyst_hours_in_dataset']:,.2f} h |",
        f"| Hours spent on FP alerts | {waste['hours_on_false_positives']:,.2f} h |",
        f"| FP alert count | {waste['false_positive_alert_count']:,} |",
        f"| FP time as % of total analyst time | {waste['fp_time_share_pct']:.2f}% |",
        f"| Theoretical max savings (100% automation) | {waste['theoretical_max_savings_hours_30d']:,.2f} h |",
        f"| Conservative savings (60% efficiency) | {waste['conservative_savings_60pct_efficiency_30d']:,.2f} h |",
        f"| FP hours per week (annualised rate) | {waste['fp_analyst_hours_per_week']:,.2f} h/week |",
        f"| Conservative savings per week | {waste['conservative_savings_per_week']:,.2f} h/week |",
        f"| FTE equivalent saved per week | {waste['fte_equivalent_per_week']:.3f} FTE |",
        "",
        f"> *{waste['note']}*",
        "",
        "### Arithmetic Verification",
        "",
        "```",
        f"FP analyst-hours in dataset   = {waste['hours_on_false_positives']:,.2f} h",
        f"Dataset duration              = {dataset_days} days",
        f"FP hours per week             = {waste['fp_analyst_hours_per_week']:,.2f} h/week",
        f"At 60% automation efficiency  = {waste['fp_analyst_hours_per_week']:,.2f} × 0.60",
        f"                              = {waste['conservative_savings_per_week']:,.2f} h/week saved",
        f"FTE equivalent                = {waste['conservative_savings_per_week']:,.2f} / 40 h",
        f"                              = {waste['fte_equivalent_per_week']:.3f} FTE",
        "```",
        "",
        "---",
        "",
        "## 7. Baseline Summary Table",
        "",
        "| Metric | Baseline (Before Assistant) |",
        "|---|---|",
        f"| Total alerts (30 days) | {volume['total']:,} |",
        f"| Alerts per day | {volume['total']/dataset_days:.0f} |",
        f"| Overall FP rate | {100 * fp_rates['overall'].get('false_positive', 0) / total_decisions:.1f}% |",
        f"| Total analyst-hours (30 days) | {time_metrics['total_analyst_hours']:,.2f} h |",
        f"| Avg time per alert | {time_metrics['mean_minutes_per_alert']:.2f} min |",
        f"| Hours lost to FPs | {waste['hours_on_false_positives']:,.2f} h ({waste['fp_time_share_pct']:.1f}% of total) |",
        f"| Override rate | {override_metrics['override_rate_pct']:.2f}% |",
        f"| Confirmed incident rate | {incident_metrics['incident_rate_pct']:.2f}% |",
        "",
        "---",
        "",
        "## 8. What This Baseline Enables",
        "",
        "**Phase 2 comparisons will measure:**",
        "- FP hours saved by the rule-based (Phase 1) and ML (Phase 2) assistants vs this baseline.",
        "- Override rate change (lower = better assistant calibration).",
        "- Missed-incident rate at each automation confidence threshold — compared against the `max_allowed_miss_rate` ceiling in `config/rules.yaml`.",
        "",
        "**Phase 2 must NOT cherry-pick its comparison point.**",
        "The comparison must use the full 30-day dataset, same metric definitions, same FP/TP ground truth from `incident_labels.csv`.",
        "",
        "---",
        "",
        "*End of Baseline Report — generated by `baseline/compute_baseline.py`*",
    ]

    return "\n".join(lines)


def main():
    print("=" * 60)
    print("Baseline Computation — University SOC FP Reduction")
    print("=" * 60)

    print("\nLoading data files...")
    alerts = load_csv("alerts.csv")
    decisions = load_csv("analyst_decisions.csv")
    labels = load_csv("incident_labels.csv")

    print(f"  Alerts: {len(alerts):,}")
    print(f"  Decisions: {len(decisions):,}")
    print(f"  Incident labels: {len(labels):,}")

    print("\nComputing metrics...")
    volume = compute_alert_volume(alerts)
    fp_rates = compute_fp_tp_rates(decisions)
    time_metrics = compute_time_metrics(decisions)
    override_metrics = compute_override_metrics(decisions)
    incident_metrics = compute_incident_metrics(labels)
    waste = compute_wasted_hours(time_metrics, fp_rates)

    print("\n--- KEY BASELINE NUMBERS ---")
    print(f"Total alerts:             {volume['total']:,}")
    print(f"Overall FP rate:          {100 * fp_rates['overall'].get('false_positive', 0) / sum(fp_rates['overall'].values()):.1f}%")
    print(f"Total analyst-hours:      {time_metrics['total_analyst_hours']:,.2f} h")
    print(f"Hours on FPs:             {waste['hours_on_false_positives']:,.2f} h ({waste['fp_time_share_pct']:.1f}% of total)")
    print(f"Savings at 60% efficiency: {waste['conservative_savings_60pct_efficiency_30d']:,.2f} h")
    print(f"FTE equivalent/week:      {waste['fte_equivalent_per_week']:.3f}")
    print(f"Override rate:            {override_metrics['override_rate_pct']:.2f}%")
    print(f"Confirmed incidents:      {incident_metrics['confirmed_incidents']} ({incident_metrics['incident_rate_pct']:.2f}%)")

    print("\nGenerating report...")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    report = build_report(volume, fp_rates, time_metrics, override_metrics, incident_metrics, waste)

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\nReport written to: {REPORT_PATH}")
    print("\nBaseline computation complete.")
    print("This report is the BEFORE state. Keep it unchanged once committed —")
    print("Phase 2 experiment results will reference these numbers.")


if __name__ == "__main__":
    main()
