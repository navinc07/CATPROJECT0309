# Baseline Report — Before Assistant Introduction

**Project:** C28 — AI Immersion (Semester 5)  
**Generated:** 2026-09-03 14:22:07  
**Dataset period:** 30 days (2026-07-01 to 2026-07-30)  
**Data source:** Synthetic dataset (seed=42); see `data/README_dataset.md`

> **Purpose:** This document establishes the BEFORE-state metrics. All
> Phase 2 efficiency improvements will be measured against these numbers.
> Any claim of 'X% FP reduction' or 'Y analyst-hours saved' is only
> meaningful relative to this documented baseline.

---

## 1. Alert Volume

**Total alerts (30 days):** 12,608  
**Average per day:** 420.3

### By Network Segment

| Segment | Alert Count | % of Total | Alerts/Day |
|---|---|---|---|
| guest | 6,463 | 51.3% | 215.4 |
| student | 4,566 | 36.2% | 152.2 |
| lab | 961 | 7.6% | 32.0 |
| admin | 618 | 4.9% | 20.6 |

### By Alert Type

| Alert Type | Count | % of Total | Alerts/Day |
|---|---|---|---|
| DNS_FLOOD | 2,256 | 17.9% | 75.2 |
| MALWARE_CALLBACK | 2,164 | 17.2% | 72.1 |
| ARP_SPOOF | 2,118 | 16.8% | 70.6 |
| DHCP_EXHAUSTION | 1,821 | 14.4% | 60.7 |
| PORT_SCAN | 942 | 7.5% | 31.4 |
| LATERAL_MOVE | 893 | 7.1% | 29.8 |
| POLICY_VIOLATION | 776 | 6.2% | 25.9 |
| BRUTE_FORCE | 678 | 5.4% | 22.6 |
| FAILED_AUTH | 643 | 5.1% | 21.4 |
| DATA_EXFIL | 317 | 2.5% | 10.6 |

---

## 2. False Positive / True Positive Breakdown

### Overall Disposition Rates

| Disposition | Count | % of Total |
|---|---|---|
| false_positive | 8,549 | 67.8% |
| true_positive | 3,097 | 24.5% |
| escalated | 972 | 7.7% |

### FP Rate by Network Segment

| Segment | FP Count | TP Count | Escalated | FP Rate |
|---|---|---|---|---|
| guest | 4,828 | 1,210 | 425 | 74.7% |
| student | 3,129 | 1,112 | 335 | 68.4% |
| lab | 461 | 373 | 127 | 48.0% |
| admin | 131 | 402 | 85 | 21.2% |

**Observation:** Guest segment has the highest FP rate, confirming the
problem statement. Admin segment has the lowest, confirming that admin
alerts deserve more investigative attention per alert.

---

## 3. Analyst Time Metrics

**Total analyst-hours across 30-day dataset:** 1,933.83 hours  
**Mean minutes per alert:** 9.20 min

### Time by Disposition

| Disposition | Alert Count | Avg Min/Alert | Total Hours | % of Time |
|---|---|---|---|---|
| false_positive | 8,549 | 6.64 | 946.03 | 48.9% |
| true_positive | 3,097 | 14.54 | 750.60 | 38.8% |
| escalated | 972 | 14.64 | 237.20 | 12.3% |

### Average Time Per Alert by Segment

| Segment | Alert Count | Avg Min/Alert | Total Hours |
|---|---|---|---|
| guest | 6,463 | 8.62 | 928.72 |
| student | 4,576 | 9.12 | 695.37 |
| lab | 961 | 10.95 | 175.42 |
| admin | 618 | 13.04 | 134.33 |

### Top 5 Alert Types by Total Analyst Hours

| Alert Type | Count | Avg Min/Alert | Total Hours |
|---|---|---|---|
| MALWARE_CALLBACK | 2,164 | 14.5 | 523.02 |
| DNS_FLOOD | 2,256 | 7.02 | 264.08 |
| ARP_SPOOF | 2,118 | 6.94 | 245.12 |
| LATERAL_MOVE | 893 | 14.64 | 217.90 |
| DHCP_EXHAUSTION | 1,821 | 6.88 | 208.93 |

---

## 4. Analyst Override Analysis

**Total decisions:** 12,618  
**Total overrides:** 984  
**Override rate:** 7.80%

| Disposition After Override | Count |
|---|---|
| false_positive | 974 |
| true_positive | 10 |

**Distinct override reason phrases:** 6

Sample override reasons (signals analyst frustration points):
- *"User has prior incident history; increasing caution"*
- *"Similar alert flagged as TP last week; not comfortable auto-closing"*
- *"Timing suggests coordinated scan, not random DHCP churn"*
- *"Observed suspicious process spawned after connection; not typical DHCP noise"*
- *"Pattern matches usual captive-portal noise; closing as FP"*

**Observation:** Override rate in Phase 1 is the baseline. If the Phase 2
assistant recommendations are better calibrated, the override rate should
decrease. A persistently high override rate signals poor recommendation quality.

---

## 5. Confirmed Incident Metrics

**Total alerts:** 12,608  
**Confirmed incidents:** 3,027  
**Incident rate:** 24.01%

### Incidents by Category

| Category | Count |
|---|---|
| lateral_movement | 470 |
| dns_tunnelling | 449 |
| brute_force_intrusion | 435 |
| unauthorised_access | 427 |
| policy_violation_confirmed | 426 |
| data_exfiltration | 425 |
| malware_infection | 395 |

---

## 6. Wasted Analyst-Hours on False Positives

> This section quantifies the *opportunity cost* of the current workflow —
> the analyst time spent on alerts that were ultimately false positives.
> These are the hours the FP Reduction Assistant aims to reclaim.

| Metric | Value |
|---|---|
| Total analyst-hours in 30-day dataset | 1,933.83 h |
| Hours spent on FP alerts | 946.03 h |
| FP alert count | 8,549 |
| FP time as % of total analyst time | 48.92% |
| Theoretical max savings (100% automation) | 946.03 h |
| Conservative savings (60% efficiency) | 567.62 h |
| FP hours per week (annualised rate) | 220.74 h/week |
| Conservative savings per week | 132.44 h/week |
| FTE equivalent saved per week | 3.311 FTE |

> *FTE equivalent = weekly savings / 40 hours; represents the analyst capacity freed by 60% FP automation efficiency. Phase 2 will measure the achieved rate against this ceiling.*

### Arithmetic Verification

```
FP analyst-hours in dataset   = 946.03 h
Dataset duration              = 30 days
FP hours per week             = 220.74 h/week
At 60% automation efficiency  = 220.74 × 0.60
                              = 132.44 h/week saved
FTE equivalent                = 132.44 / 40 h
                              = 3.311 FTE
```

---

## 7. Baseline Summary Table

| Metric | Baseline (Before Assistant) |
|---|---|
| Total alerts (30 days) | 12,608 |
| Alerts per day | 420 |
| Overall FP rate | 67.8% |
| Total analyst-hours (30 days) | 1,933.83 h |
| Avg time per alert | 9.20 min |
| Hours lost to FPs | 946.03 h (48.9% of total) |
| Override rate | 7.80% |
| Confirmed incident rate | 24.01% |

---

## 8. What This Baseline Enables

**Phase 2 comparisons will measure:**
- FP hours saved by the rule-based (Phase 1) and ML (Phase 2) assistants vs this baseline.
- Override rate change (lower = better assistant calibration).
- Missed-incident rate at each automation confidence threshold — compared against the `max_allowed_miss_rate` ceiling in `config/rules.yaml`.

**Phase 2 must NOT cherry-pick its comparison point.**
The comparison must use the full 30-day dataset, same metric definitions, same FP/TP ground truth from `incident_labels.csv`.

---

*End of Baseline Report — generated by `baseline/compute_baseline.py`*