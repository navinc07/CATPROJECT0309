# Temporal Validation & Novel-Threat Preservation Report

**Course Code:** C28 — AI Immersion (Semester 5)  
**Deliverable:** GAP 2 — Time-Series / Temporal Validation Report  
**Generated:** 2026-09-18 11:08:59  
**Evaluation Scope:** Days 25 to 30 Held-Out Temporal Partition  
**Ground Truth Source:** `incident_labels.csv` (`confirmed_incident`)  

---

## 1. Split Methodology & Anti-Leakage Rationale

In real-world Security Operations Centers (SOC), alert triage occurs in a continuous forward-in-time sequence. 

### Why Random Cross-Validation Fails for SOC Triage:
1. **Temporal Leakage:** Random k-fold splitting mixes future alerts with past alerts. An ongoing cyber campaign (e.g. multi-day port sweep or persistent C2 beaconing) would leak destination IPs, subnet heuristics, and attacker behavior into the training fold.
2. **Artificial Baseline Inflation:** Models evaluated on randomly split time-series data exhibit artificially elevated precision and recall because the classifier merely memorizes contemporaneous IP traffic rather than generalizing forward in time.
3. **Causal Integrity:** To evaluate how the assistant performs when deployed on Day 25 facing unseen alerts from Days 25–30, we enforce a strict temporal boundary:
   - **Training Window:** Days 1–24 (2026-07-01 08:18 to 2026-07-24 23:59) — **9,918 alerts (78.7%)**
   - **Test Window:** Days 25–30 (2026-07-25 00:00 to 2026-07-31 07:56) — **2,690 alerts (21.3%)**

---

## 2. Standard Evaluation Metrics (Against Ground Truth Incidents)

> **Important Separation of Targets:** The model was trained to emulate Tier-1 analyst triage dispositions (`false_positive`). However, this evaluation step tests the model against **`incident_labels.csv` (`confirmed_incident`)**, which was strictly withheld during training.

| Metric | Measured Value | Operational Meaning |
|---|---|---|
| **Incident Recall** | **99.68%** | Percentage of real confirmed incidents successfully caught and routed to analysts |
| **Missed-Incident Rate** | **0.32%** | Percentage of real incidents incorrectly auto-closed as FP (Safety Ceiling: $\le 2.0\%$) |
| **Incident Precision** | **24.7%** | Precision of alerts escalated to human analysts |
| **F1-Score** | **0.3959** | Harmonic balance between security safety and triage precision |
| **Overall Accuracy** | **30.0%** | Overall decision accuracy across all 2,690 test alerts |
| **FP Auto-Closure Rate** | **9.17%** | Percentage of benign false positives safely auto-closed without human review |

---

## 3. Confusion Matrix (Temporal Test Split)

| | Predicted Benign (Auto-Closed FP) | Predicted Incident (Routed to Analyst) | Total Actual |
|---|---|---|---|
| **Actual Incident (`confirmed_incident=True`)** | **FN: 2** *(Missed)* | **TP: 617** *(Caught)* | **619** |
| **Actual Benign (`confirmed_incident=False`)** | **TN: 190** *(Reclaimed)* | **FP: 1881** *(Manual Review)* | **2071** |
| **Total Predicted** | **192** | **2498** | **2690** |

### Observations:
- Out of 619 confirmed incidents occurring during Days 25–30, the model successfully escalated **617**, yielding a **missed-incident rate of 0.32%**, strictly satisfying the $\le 2.0\%$ safety ceiling.
- 190 benign false positives were safely auto-closed without requiring human analyst investigation.

---

## 4. Measured Novel-Threat Preservation (Explicit Numbered Metric)

In Phase 1's synthetic dataset design (`data/README_dataset.md §4.4`), a targeted threat was engineered: **DNS-tunnelling Command & Control (C2) traffic** on the guest subnet masquerading as routine captive-portal DNS noise. 

While a naïve pattern-matcher would observe high historical FP counts for `(DNS_FLOOD, guest)` and auto-close the alert, the assistant must inspect endpoint context (unmanaged host, unpatched, high vulnerability count, external destination IP) and escalate.

### Numbered Primary Evaluation Metric:
> ### **novel-threat recall = 1/1 caught** (Temporal Test Partition)
> ### **novel-threat recall = 8/8 caught** (100.0% Across Entire Dataset)

### Detailed Breakdown of All Engineered Novel Threat Alerts:

| Alert ID | Timestamp | Partition | Recommendation Produced | Model Confidence | Status |
|---|---|---|---|---|---|
| `ALT-003655` | 2026-07-12 | Train (Day 1-24) | `anomaly_signal_detected` | 0.75 | **CAUGHT (Escalated)** |
| `ALT-010198` | 2026-07-13 | Train (Day 1-24) | `anomaly_signal_detected` | 0.89 | **CAUGHT (Escalated)** |
| `ALT-011647` | 2026-07-13 | Train (Day 1-24) | `anomaly_signal_detected` | 0.91 | **CAUGHT (Escalated)** |
| `ALT-000484` | 2026-07-19 | Train (Day 1-24) | `anomaly_signal_detected` | 0.88 | **CAUGHT (Escalated)** |
| `ALT-007309` | 2026-07-20 | Train (Day 1-24) | `anomaly_signal_detected` | 0.90 | **CAUGHT (Escalated)** |
| `ALT-010393` | 2026-07-23 | Train (Day 1-24) | `anomaly_signal_detected` | 0.88 | **CAUGHT (Escalated)** |
| `ALT-003255` | 2026-07-24 | Train (Day 1-24) | `anomaly_signal_detected` | 0.79 | **CAUGHT (Escalated)** |
| `ALT-004950` | 2026-07-26 | Test (Day 25-30) | `anomaly_signal_detected` | 0.78 | **CAUGHT (Escalated)** |

### Findings:
1. Every engineered DNS-tunnelling alert was successfully recognized by the anomaly detection layer and escalated with `requires_human_confirmation = True`.
2. **Zero novel threat instances were suppressed as false positives.**
3. The combination of endpoint context features (`is_managed_device=False`, `known_vuln_count >= 3`, `is_external_dst=True`) successfully overrode the historical high FP rate of the guest DNS flood cluster.
