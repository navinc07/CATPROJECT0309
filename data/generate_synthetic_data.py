"""
generate_synthetic_data.py
==========================
Generates realistic synthetic data for the False-Positive Reduction Assistant
(University SOC) project.

WHY SYNTHETIC DATA:
    Real SOC alert data is highly sensitive (contains live IP addresses,
    incident details, potential PII). Generating synthetic data with a fixed
    random seed allows:
    (a) full reproducibility for experiments and peer review,
    (b) deliberate engineering of edge cases that may not appear in a real
        dataset of tractable size (e.g., the rare novel-TP-masquerading-as-FP),
    (c) public sharing without security/privacy concerns.

DESIGN DECISIONS:
    - Fixed seed (SEED = 42) throughout for full reproducibility.
    - Four CSV files joined on alert_id covering all required data types.
    - Three FP clusters are deliberately over-represented (mimicking the
      real-world repetitive-FP problem).
    - One novel TP is engineered to superficially match the largest FP cluster
      but carry distinguishing endpoint signals — this is the critical test
      case for the "preserves novel threats" requirement.
    - Alert volume and FP/TP split calibrated to match the quantified baseline
      in docs/01_problem_analysis.md (400 alerts/day, 75% FP).
    - Generation covers 30 days of simulated data (~12,000 total alerts).

OUTPUT FILES:
    data/alerts.csv
    data/analyst_decisions.csv
    data/endpoint_context.csv
    data/incident_labels.csv

Usage:
    python data/generate_synthetic_data.py
"""

import csv
import random
import os
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration constants (NOT business thresholds — those live in rules.yaml)
# ---------------------------------------------------------------------------
SEED = 42
DAYS = 30
ALERTS_PER_DAY = 400
FP_RATE_OVERALL = 0.75        # 75% of alerts are false positives
OUTPUT_DIR = Path(__file__).parent  # data/ directory

random.seed(SEED)

# ---------------------------------------------------------------------------
# Network segment definitions with their distinct FP base rates
# (matches docs/02_workflow_map.md segment table)
# ---------------------------------------------------------------------------
SEGMENTS = {
    "student": {
        "weight": 0.375,      # ~150 alerts/day of 400
        "fp_base_rate": 0.90, # 90% of student alerts are FP
        "ip_prefix": "10.1.",
        "user_types": ["student"],
        "device_types": ["laptop", "smartphone", "tablet"],
    },
    "guest": {
        "weight": 0.500,      # ~200 alerts/day
        "fp_base_rate": 0.95, # 95% FP — highest noise segment
        "ip_prefix": "10.2.",
        "user_types": ["guest"],
        "device_types": ["smartphone", "laptop", "unknown"],
    },
    "lab": {
        "weight": 0.075,      # ~30 alerts/day
        "fp_base_rate": 0.80, # 80% FP — legitimate research tools trigger IDS
        "ip_prefix": "10.3.",
        "user_types": ["faculty", "lab_admin"],
        "device_types": ["workstation", "server", "raspberry_pi"],
    },
    "admin": {
        "weight": 0.050,      # ~20 alerts/day
        "fp_base_rate": 0.40, # 40% FP — low noise, high fidelity
        "ip_prefix": "10.4.",
        "user_types": ["faculty", "lab_admin"],
        "device_types": ["workstation", "laptop"],
    },
}

# ---------------------------------------------------------------------------
# Alert type definitions mapped to segments and their typical characteristics
# Each entry: (alert_type, severity_range, rule_name, typical_segments)
# ---------------------------------------------------------------------------
ALERT_TYPES = {
    "DHCP_EXHAUSTION": {
        "segments": ["guest"],
        "severity_range": (1, 3),
        "rule": "IDS-DHCP-001",
        "typical_fp": True,  # almost always FP on guest network
    },
    "DNS_FLOOD": {
        "segments": ["student", "guest"],
        "severity_range": (2, 4),
        "rule": "IDS-DNS-007",
        "typical_fp": True,
    },
    "PORT_SCAN": {
        "segments": ["student", "lab", "admin"],
        "severity_range": (3, 7),
        "rule": "IDS-SCAN-003",
        "typical_fp": True,  # FP for student/lab, TP for admin
    },
    "FAILED_AUTH": {
        "segments": ["student", "admin"],
        "severity_range": (2, 5),
        "rule": "AUTH-FAIL-002",
        "typical_fp": True,
    },
    "LATERAL_MOVE": {
        "segments": ["student", "lab", "admin"],
        "severity_range": (6, 9),
        "rule": "THREAT-LAT-010",
        "typical_fp": False,  # usually TP when it fires
    },
    "DATA_EXFIL": {
        "segments": ["lab", "admin"],
        "severity_range": (7, 10),
        "rule": "THREAT-EXFIL-005",
        "typical_fp": False,
    },
    "MALWARE_CALLBACK": {
        "segments": ["student", "guest", "admin"],
        "severity_range": (7, 10),
        "rule": "THREAT-C2-001",
        "typical_fp": False,
    },
    "ARP_SPOOF": {
        "segments": ["guest", "student"],
        "severity_range": (3, 6),
        "rule": "IDS-ARP-002",
        "typical_fp": True,  # captive portal behaviour on guest
    },
    "POLICY_VIOLATION": {
        "segments": ["student", "lab"],
        "severity_range": (2, 5),
        "rule": "POLICY-001",
        "typical_fp": True,
    },
    "BRUTE_FORCE": {
        "segments": ["student", "admin"],
        "severity_range": (4, 8),
        "rule": "AUTH-BRUTE-003",
        "typical_fp": True,  # FP for student (misconfigured clients), TP for admin
    },
}

OS_OPTIONS = ["Windows 10", "Windows 11", "Ubuntu 22.04", "macOS 13", "Android 13", "iOS 16", "Unknown"]
PATCH_STATUSES = ["fully_patched", "partially_patched", "unpatched", "unknown"]
ANALYST_IDS = ["ana_001", "ana_002", "ana_003", "ana_004"]
ANALYST_ROLES = {"ana_001": "l1_analyst", "ana_002": "l1_analyst",
                 "ana_003": "l1_analyst", "ana_004": "soc_lead"}

START_DATE = datetime(2026, 7, 1, 8, 0, 0)

# ---------------------------------------------------------------------------
# The three primary FP clusters (engineered noise, matching problem statement)
# ---------------------------------------------------------------------------
# Cluster 1: Guest DHCP Exhaustion — fires hundreds of times, always FP
# Cluster 2: Student/Guest DNS Flood — high volume, nearly always FP
# Cluster 3: Lab Port Scan — automated tools, nearly always FP

# ---------------------------------------------------------------------------
# Novel TP Engineering (critical test case)
# ---------------------------------------------------------------------------
# Alert type: DNS_FLOOD (same as Cluster 2)
# Source segment: guest (same as Cluster 2)
# BUT: device is UNMANAGED, known_vuln_count > 0, device_type = unknown
# This represents DNS-tunnelling C2 on a compromised guest device.
# The recommendation engine MUST NOT suppress this despite the FP cluster match.
NOVEL_TP_COUNT = 8  # small number to simulate rarity

def random_ip(prefix: str) -> str:
    """Generate a plausible IP address for a given subnet prefix."""
    return f"{prefix}{random.randint(1,254)}.{random.randint(1,254)}"

def random_timestamp(base: datetime, day_offset: int) -> str:
    """Generate a realistic alert timestamp (weighted to business hours)."""
    # Business hours (08:00-18:00) are more active for admin/lab
    # Guest/student segments spike evenings too
    hour = random.choices(
        population=list(range(0, 24)),
        weights=[1,1,1,1,1,1,2,3,5,6,7,7,6,6,7,7,7,8,8,6,5,4,3,2],
        k=1
    )[0]
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = base + timedelta(days=day_offset, hours=hour, minutes=minute, seconds=second)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")

def generate_alerts() -> list[dict]:
    """
    Generate the alerts.csv dataset.
    
    Strategy:
    - Generate DAYS * ALERTS_PER_DAY base alerts proportionally across segments.
    - Engineer the three FP clusters with boosted counts.
    - Inject NOVEL_TP_COUNT novel TP alerts that superficially match Cluster 2.
    """
    alerts = []
    alert_id_counter = 1

    segment_names = list(SEGMENTS.keys())
    segment_weights = [SEGMENTS[s]["weight"] for s in segment_names]

    for day in range(DAYS):
        for _ in range(ALERTS_PER_DAY):
            seg_name = random.choices(segment_names, weights=segment_weights, k=1)[0]
            seg = SEGMENTS[seg_name]

            # Pick an alert type valid for this segment
            valid_types = [t for t, cfg in ALERT_TYPES.items()
                           if seg_name in cfg["segments"]]
            alert_type = random.choice(valid_types)
            type_cfg = ALERT_TYPES[alert_type]

            severity = random.randint(*type_cfg["severity_range"])
            src_ip = random_ip(seg["ip_prefix"])
            dst_ip = random_ip("10.0.")  # university core infrastructure
            raw_score = round(random.uniform(0.1, 1.0), 4)

            alerts.append({
                "alert_id": f"ALT-{alert_id_counter:06d}",
                "timestamp": random_timestamp(START_DATE, day),
                "source_segment": seg_name,
                "alert_type": alert_type,
                "severity": severity,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "signature_rule_triggered": type_cfg["rule"],
                "raw_score": raw_score,
            })
            alert_id_counter += 1

    # -----------------------------------------------------------------------
    # FP Cluster 1: Guest DHCP Exhaustion — 300 extra instances
    # These are the repetitive alerts that consume analyst time daily.
    # They are always dispositioned FP by analysts (100% FP rate in history).
    # -----------------------------------------------------------------------
    for day in range(DAYS):
        for _ in range(10):  # 10 per day × 30 days = 300 total
            alerts.append({
                "alert_id": f"ALT-{alert_id_counter:06d}",
                "timestamp": random_timestamp(START_DATE, day),
                "source_segment": "guest",
                "alert_type": "DHCP_EXHAUSTION",
                "severity": random.randint(1, 3),
                "src_ip": random_ip("10.2."),
                "dst_ip": "10.0.1.1",       # DHCP server
                "signature_rule_triggered": "IDS-DHCP-001",
                "raw_score": round(random.uniform(0.1, 0.4), 4),
                "_cluster": "FP_CLUSTER_1",  # internal annotation, stripped on write
            })
            alert_id_counter += 1

    # -----------------------------------------------------------------------
    # FP Cluster 2: Student/Guest DNS Flood — 200 extra instances
    # High-frequency alert from captive portal DNS lookups.
    # -----------------------------------------------------------------------
    for day in range(DAYS):
        for _ in range(7):  # ~7/day
            seg = random.choice(["student", "guest"])
            alerts.append({
                "alert_id": f"ALT-{alert_id_counter:06d}",
                "timestamp": random_timestamp(START_DATE, day),
                "source_segment": seg,
                "alert_type": "DNS_FLOOD",
                "severity": random.randint(2, 4),
                "src_ip": random_ip(SEGMENTS[seg]["ip_prefix"]),
                "dst_ip": "10.0.1.2",       # DNS server
                "signature_rule_triggered": "IDS-DNS-007",
                "raw_score": round(random.uniform(0.2, 0.5), 4),
                "_cluster": "FP_CLUSTER_2",
            })
            alert_id_counter += 1

    # -----------------------------------------------------------------------
    # FP Cluster 3: Lab Port Scan — 90 extra instances
    # Automated research scanners (Nmap, Masscan) trigger IDS signatures.
    # -----------------------------------------------------------------------
    for day in range(DAYS):
        for _ in range(3):  # 3/day
            alerts.append({
                "alert_id": f"ALT-{alert_id_counter:06d}",
                "timestamp": random_timestamp(START_DATE, day),
                "source_segment": "lab",
                "alert_type": "PORT_SCAN",
                "severity": random.randint(3, 5),
                "src_ip": random_ip("10.3."),
                "dst_ip": random_ip("10.3."),  # intra-lab scan
                "signature_rule_triggered": "IDS-SCAN-003",
                "raw_score": round(random.uniform(0.3, 0.6), 4),
                "_cluster": "FP_CLUSTER_3",
            })
            alert_id_counter += 1

    # -----------------------------------------------------------------------
    # NOVEL TP: DNS_FLOOD on guest segment — looks like FP Cluster 2
    # but device is unmanaged, has known vulnerabilities.
    # This is a DNS-tunnelling C2 channel. The assistant must NOT suppress it.
    # Distinguishing signals (absent in FP Cluster 2):
    #   - is_managed_device = False
    #   - known_vuln_count >= 3
    #   - device_type = unknown
    # -----------------------------------------------------------------------
    for i in range(NOVEL_TP_COUNT):
        day_offset = random.randint(10, 28)  # injected mid-to-late dataset
        alerts.append({
            "alert_id": f"ALT-{alert_id_counter:06d}",
            "timestamp": random_timestamp(START_DATE, day_offset),
            "source_segment": "guest",
            "alert_type": "DNS_FLOOD",
            "severity": random.randint(3, 5),  # slightly higher severity
            "src_ip": random_ip("10.2."),
            "dst_ip": "8.8.8.8",  # external IP — unusual for captive-portal DNS
            "signature_rule_triggered": "IDS-DNS-007",  # SAME rule as FP cluster 2
            "raw_score": round(random.uniform(0.5, 0.8), 4),  # higher score
            "_cluster": "NOVEL_TP",
            "_is_novel_tp": True,  # internal annotation
        })
        alert_id_counter += 1

    # Shuffle to prevent ordering artefacts
    random.shuffle(alerts)

    # Assign sequential IDs after shuffle (preserve cluster annotations internally)
    for idx, alert in enumerate(alerts, start=1):
        alert["alert_id"] = f"ALT-{idx:06d}"

    return alerts


def generate_endpoint_context(alerts: list[dict]) -> list[dict]:
    """
    Generate endpoint_context.csv.
    
    Each alert gets endpoint context. The critical engineering:
    - FP Cluster 1/2/3 alerts: managed devices, patched, appropriate user_type.
    - Novel TP alerts: unmanaged, unpatched, known_vuln_count >= 3, user_type=guest.
    - ~10% of alerts deliberately have missing/incomplete context (failure case F1).
    """
    contexts = []
    for alert in alerts:
        cluster = alert.get("_cluster", "")
        is_novel_tp = alert.get("_is_novel_tp", False)
        seg = alert["source_segment"]
        seg_cfg = SEGMENTS[seg]

        # Simulate ~10% missing context (failure case F1)
        if random.random() < 0.10 and not is_novel_tp:
            # Missing context: only alert_id, everything else null/unknown
            contexts.append({
                "alert_id": alert["alert_id"],
                "device_type": "unknown",
                "os": "unknown",
                "patch_status": "unknown",
                "is_managed_device": None,
                "user_type": "unknown",
                "known_vuln_count": None,
                "_context_missing": True,
            })
            continue

        if is_novel_tp:
            # Novel TP: deliberately anomalous endpoint context
            contexts.append({
                "alert_id": alert["alert_id"],
                "device_type": "unknown",
                "os": "Unknown",
                "patch_status": "unpatched",
                "is_managed_device": False,
                "user_type": "guest",
                "known_vuln_count": random.randint(3, 8),
                "_context_missing": False,
            })
        elif cluster == "FP_CLUSTER_1":
            # DHCP exhaustion on guest — managed-ish devices, no vulns
            contexts.append({
                "alert_id": alert["alert_id"],
                "device_type": random.choice(["smartphone", "laptop", "tablet"]),
                "os": random.choice(["iOS 16", "Android 13", "Windows 10"]),
                "patch_status": random.choice(["fully_patched", "partially_patched"]),
                "is_managed_device": random.choice([True, False]),
                "user_type": "guest",
                "known_vuln_count": random.randint(0, 1),
                "_context_missing": False,
            })
        elif cluster == "FP_CLUSTER_2":
            # DNS flood on student/guest — patched devices, 0 known vulns
            seg_c = alert["source_segment"]
            user_type = "student" if seg_c == "student" else "guest"
            contexts.append({
                "alert_id": alert["alert_id"],
                "device_type": random.choice(["laptop", "smartphone"]),
                "os": random.choice(["Windows 10", "Windows 11", "macOS 13", "iOS 16"]),
                "patch_status": random.choice(["fully_patched", "partially_patched"]),
                "is_managed_device": True,
                "user_type": user_type,
                "known_vuln_count": 0,  # key signal: FP cluster has 0 vulns
                "_context_missing": False,
            })
        elif cluster == "FP_CLUSTER_3":
            # Lab port scan — managed lab devices, patched
            contexts.append({
                "alert_id": alert["alert_id"],
                "device_type": random.choice(["workstation", "server"]),
                "os": random.choice(["Ubuntu 22.04", "Windows 11"]),
                "patch_status": "fully_patched",
                "is_managed_device": True,
                "user_type": random.choice(["faculty", "lab_admin"]),
                "known_vuln_count": 0,
                "_context_missing": False,
            })
        else:
            # General alert — random endpoint context appropriate to segment
            contexts.append({
                "alert_id": alert["alert_id"],
                "device_type": random.choice(seg_cfg["device_types"]),
                "os": random.choice(OS_OPTIONS),
                "patch_status": random.choices(
                    PATCH_STATUSES,
                    weights=[0.5, 0.3, 0.15, 0.05],
                    k=1
                )[0],
                "is_managed_device": seg != "guest",
                "user_type": random.choice(seg_cfg["user_types"]),
                "known_vuln_count": random.randint(0, 5),
                "_context_missing": False,
            })

    return contexts


def generate_analyst_decisions(alerts: list[dict], endpoint_contexts: dict) -> list[dict]:
    """
    Generate analyst_decisions.csv.
    
    Disposition logic mirrors what a trained L1 analyst would do:
    - FP clusters → almost always false_positive disposition.
    - Novel TP → true_positive / escalated.
    - A small number of decisions are overrides (analyst disagrees with expected
      recommendation) to create the conflicting-evidence failure case.
    - Conflict case: 5 alerts of the same type/segment are deliberately
      dispositioned as both FP AND TP by different analysts.
    """
    decisions = []
    conflict_alert_ids = set()

    # Pick 5 random general port-scan alerts from student segment to be conflict cases
    conflict_candidates = [
        a["alert_id"] for a in alerts
        if a["alert_type"] == "PORT_SCAN"
        and a["source_segment"] == "student"
        and not a.get("_is_novel_tp", False)
        and a.get("_cluster", "") == ""
    ]
    random.shuffle(conflict_candidates)
    conflict_alert_ids = set(conflict_candidates[:10])  # 10 alerts will get conflicts

    analyst_pool = list(ANALYST_IDS[:3])  # L1 analysts only make initial decisions

    for alert in alerts:
        cluster = alert.get("_cluster", "")
        is_novel_tp = alert.get("_is_novel_tp", False)
        seg = alert["source_segment"]
        alert_type = alert["alert_type"]
        ctx_missing = endpoint_contexts.get(alert["alert_id"], {}).get("_context_missing", False)

        # Determine the "true" ground-truth disposition for this alert
        if is_novel_tp:
            ground_truth = "true_positive"
        elif cluster in ("FP_CLUSTER_1", "FP_CLUSTER_2", "FP_CLUSTER_3"):
            ground_truth = "false_positive"
        elif ALERT_TYPES[alert_type]["typical_fp"]:
            # Segment-specific adjustment
            fp_rate = SEGMENTS[seg]["fp_base_rate"]
            ground_truth = "false_positive" if random.random() < fp_rate else "true_positive"
        else:
            # High-severity alert types
            ground_truth = "true_positive" if random.random() < 0.7 else "escalated"

        analyst_id = random.choice(analyst_pool)
        override_flag = False
        override_reason = None
        time_spent = random.randint(4, 8) if ground_truth == "false_positive" else random.randint(8, 20)

        if ctx_missing:
            time_spent += 5  # extra time for missing context lookup

        # Conflict case: same alert gets two conflicting decisions
        if alert["alert_id"] in conflict_alert_ids:
            # First analyst says FP
            decisions.append({
                "alert_id": alert["alert_id"],
                "analyst_id": analyst_pool[0],
                "analyst_role": ANALYST_ROLES[analyst_pool[0]],
                "disposition": "false_positive",
                "time_spent_minutes": random.randint(5, 10),
                "decision_timestamp": alert["timestamp"],  # same day
                "override_flag": False,
                "override_reason": None,
            })
            # Second analyst says TP (conflict!)
            decisions.append({
                "alert_id": alert["alert_id"],
                "analyst_id": analyst_pool[1],
                "analyst_role": ANALYST_ROLES[analyst_pool[1]],
                "disposition": "true_positive",
                "time_spent_minutes": random.randint(12, 20),
                "decision_timestamp": alert["timestamp"],
                "override_flag": True,
                "override_reason": "Observed suspicious process spawned after connection; not typical DHCP noise",
            })
            continue

        # Occasional override: analyst disagrees with what the assistant would suggest
        # (10% of general FP decisions are overridden, 5% of TP)
        if ground_truth == "false_positive" and random.random() < 0.10:
            override_flag = True
            override_reason = random.choice([
                "Device is not on expected VLAN for this alert type",
                "Timing suggests coordinated scan, not random DHCP churn",
                "User has prior incident history; increasing caution",
                "Similar alert flagged as TP last week; not comfortable auto-closing",
            ])
        elif ground_truth == "true_positive" and random.random() < 0.05:
            # Analyst incorrectly dispositions TP as FP (analyst error — creates
            # training noise for Phase 2 model — realistic!)
            ground_truth = "false_positive"
            override_flag = True
            override_reason = "Pattern matches usual captive-portal noise; closing as FP"

        decisions.append({
            "alert_id": alert["alert_id"],
            "analyst_id": analyst_id,
            "analyst_role": ANALYST_ROLES[analyst_id],
            "disposition": ground_truth,
            "time_spent_minutes": time_spent,
            "decision_timestamp": alert["timestamp"],
            "override_flag": override_flag,
            "override_reason": override_reason,
        })

    return decisions


def generate_incident_labels(alerts: list[dict], decisions: list[dict]) -> list[dict]:
    """
    Generate incident_labels.csv.
    
    Only alerts dispositioned as true_positive or escalated get a confirmed
    incident label. The SOC Lead (ana_004) confirms incidents.
    Novel TPs are all confirmed incidents.
    """
    labels = []
    # Build a map of alert_id to disposition
    disp_map: dict[str, list[str]] = {}
    for d in decisions:
        disp_map.setdefault(d["alert_id"], []).append(d["disposition"])

    incident_categories = [
        "malware_infection", "data_exfiltration", "lateral_movement",
        "brute_force_intrusion", "policy_violation_confirmed",
        "dns_tunnelling", "unauthorised_access",
    ]

    for alert in alerts:
        dispositions = disp_map.get(alert["alert_id"], [])
        is_novel_tp = alert.get("_is_novel_tp", False)

        if is_novel_tp:
            # All novel TPs are confirmed incidents (by design)
            labels.append({
                "alert_id": alert["alert_id"],
                "confirmed_incident": True,
                "incident_category": "dns_tunnelling",
                "confirmed_by": "ana_004",
                "confirmation_date": (START_DATE + timedelta(days=random.randint(1, 3))).strftime("%Y-%m-%d"),
            })
        elif "true_positive" in dispositions or "escalated" in dispositions:
            # TP or escalated — SOC Lead confirms
            confirmed = random.random() < 0.75  # 75% of TPs actually confirmed as incidents
            labels.append({
                "alert_id": alert["alert_id"],
                "confirmed_incident": confirmed,
                "incident_category": random.choice(incident_categories) if confirmed else None,
                "confirmed_by": "ana_004" if confirmed else None,
                "confirmation_date": (
                    START_DATE + timedelta(days=random.randint(0, 5))
                ).strftime("%Y-%m-%d") if confirmed else None,
            })
        else:
            # FP — no incident label
            labels.append({
                "alert_id": alert["alert_id"],
                "confirmed_incident": False,
                "incident_category": None,
                "confirmed_by": None,
                "confirmation_date": None,
            })

    return labels


def write_csv(filepath: Path, rows: list[dict], exclude_keys: list[str] = None):
    """Write rows to CSV, excluding internal annotation keys."""
    if not rows:
        return
    exclude = set(exclude_keys or [])
    all_keys = [k for k in rows[0].keys() if k not in exclude]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_keys)
        writer.writeheader()
        for row in rows:
            filtered = {k: v for k, v in row.items() if k not in exclude}
            writer.writerow(filtered)
    print(f"  Written: {filepath} ({len(rows)} rows)")


def main():
    print("=" * 60)
    print("Synthetic Data Generation — University SOC FP Reduction")
    print(f"Seed: {SEED} | Days: {DAYS} | Base alerts/day: {ALERTS_PER_DAY}")
    print("=" * 60)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("\n[1/4] Generating alerts...")
    alerts = generate_alerts()
    print(f"      Total alerts generated: {len(alerts)}")
    print(f"      FP Cluster 1 (DHCP_EXHAUSTION/guest): {sum(1 for a in alerts if a.get('_cluster') == 'FP_CLUSTER_1')}")
    print(f"      FP Cluster 2 (DNS_FLOOD/student-guest): {sum(1 for a in alerts if a.get('_cluster') == 'FP_CLUSTER_2')}")
    print(f"      FP Cluster 3 (PORT_SCAN/lab): {sum(1 for a in alerts if a.get('_cluster') == 'FP_CLUSTER_3')}")
    print(f"      Novel TPs (DNS_FLOOD masquerading): {sum(1 for a in alerts if a.get('_is_novel_tp', False))}")

    print("\n[2/4] Generating endpoint context...")
    contexts = generate_endpoint_context(alerts)
    ctx_map = {c["alert_id"]: c for c in contexts}
    missing_ctx = sum(1 for c in contexts if c.get("_context_missing", False))
    print(f"      Total context records: {len(contexts)}")
    print(f"      Records with missing/incomplete context: {missing_ctx} ({100*missing_ctx/len(contexts):.1f}%)")

    print("\n[3/4] Generating analyst decisions...")
    decisions = generate_analyst_decisions(alerts, ctx_map)
    fp_count = sum(1 for d in decisions if d["disposition"] == "false_positive")
    tp_count = sum(1 for d in decisions if d["disposition"] == "true_positive")
    esc_count = sum(1 for d in decisions if d["disposition"] == "escalated")
    override_count = sum(1 for d in decisions if d["override_flag"])
    print(f"      Total decisions: {len(decisions)}")
    print(f"      False Positives: {fp_count} ({100*fp_count/len(decisions):.1f}%)")
    print(f"      True Positives: {tp_count} ({100*tp_count/len(decisions):.1f}%)")
    print(f"      Escalated: {esc_count} ({100*esc_count/len(decisions):.1f}%)")
    print(f"      Override flags set: {override_count}")

    print("\n[4/4] Generating incident labels...")
    labels = generate_incident_labels(alerts, decisions)
    confirmed = sum(1 for l in labels if l["confirmed_incident"])
    print(f"      Total label records: {len(labels)}")
    print(f"      Confirmed incidents: {confirmed}")

    print("\nWriting CSV files...")
    write_csv(OUTPUT_DIR / "alerts.csv", alerts,
              exclude_keys=["_cluster", "_is_novel_tp"])
    write_csv(OUTPUT_DIR / "analyst_decisions.csv", decisions)
    write_csv(OUTPUT_DIR / "endpoint_context.csv", contexts,
              exclude_keys=["_context_missing"])
    write_csv(OUTPUT_DIR / "incident_labels.csv", labels)

    print("\nGeneration complete.")
    print(f"Output directory: {OUTPUT_DIR.resolve()}")
    print("\nIMPORTANT: The novel TP alerts (DNS_FLOOD on guest with unmanaged,")
    print("unpatched devices) are the critical test case for the recommendation")
    print("engine. See data/README_dataset.md for full documentation.")


if __name__ == "__main__":
    main()
