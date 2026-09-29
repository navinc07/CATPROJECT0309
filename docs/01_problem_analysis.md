# Problem Analysis: False-Positive Reduction Assistant for University SOC

**Course:** C28 — AI Immersion (Semester 5)  
**Document Version:** 1.0 (Phase 1)  
**Date:** 2026-09-03

---

## 1. Problem Restatement

A university network is not a single monolithic enterprise environment; it is a federation of distinct sub-populations — students, temporary guests, research laboratories, and administrative systems — each with radically different "normal" behaviour profiles. The Security Operations Center (SOC) monitors all of them from a single pane of glass, which means the alert stream is a mixture of:

- High-volume, repetitive, low-fidelity noise from student/guest segments (e.g., DHCP churn, DNS flooding from captive-portal behaviour, peer-to-peer file sharing triggering IDS signatures).
- Automated, scripted traffic from labs that systematically resembles port-scanning or lateral-movement signatures.
- Low-volume, high-consequence events from administrative systems where even a single anomalous login could represent an active intrusion.

Because intrusion-detection signatures are built to err on the side of caution, the alert stream is dominated by **false positives (FPs)** — alerts that fire correctly according to the rule but represent benign activity in context. Analysts are therefore forced to re-investigate the same patterns daily, consuming time that should be reserved for genuine incidents.

---

## 2. Stakeholders

| Stakeholder | Role | Primary Concern |
|---|---|---|
| **L1 SOC Analyst** | Triages and dispositions alerts | Speed, clarity; wants to close repetitive FPs quickly and focus on real threats |
| **SOC Lead (L2)** | Oversees analyst team, tunes detection rules | Coverage (no missed incidents), efficiency, regulatory compliance |
| **CISO / IT Management** | Executive oversight | Cost, risk posture, audit readiness |
| **University Network Users** | Students, faculty, guest | Network performance; not directly involved in SOC workflow |
| **System Administrators** | Manage endpoints, patch cycles | Context provision for alert triage (patch status, device type) |
| **Compliance / Audit** | Internal/external auditors | Evidence that every alert was handled with documented rationale |

---

## 3. Pain Points

### 3.1 Cost — Analyst Time Lost to False Positives

**Quantification (with stated assumptions):**

| Assumption | Value | Source |
|---|---|---|
| Alerts generated per day across all segments | 400 | Typical mid-size university IDS/SIEM output; source: SANS 2023 SOC survey calibrated for ~10,000-user campus |
| Percentage of alerts that are false positives | 75% | Industry benchmark range 45–90%; 75% chosen as mid-conservative for a mixed-segment university network |
| Average analyst time per alert investigation | 12 minutes | Includes log lookup, IP resolution, endpoint context check, disposition entry |
| Average analyst time for a recognised, repetitive FP | 6 minutes | Analyst recognises the pattern but still must open the ticket, verify, and close it |
| Active SOC analysts per shift | 3 | Typical Tier-1 staffing for a campus of ~10,000 users |
| Working hours per shift | 8 hours | Standard shift |

**Arithmetic:**

```
Total alerts/day          = 400
False-positive alerts/day = 400 × 0.75 = 300
True-positive alerts/day  = 400 × 0.25 = 100

Analyst-minutes on FPs/day = 300 × 6  min = 1,800 minutes = 30.0 analyst-hours/day
Analyst-minutes on TPs/day = 100 × 12 min = 1,200 minutes = 20.0 analyst-hours/day

Total analyst-hours available/day = 3 analysts × 8 hours = 24 analyst-hours

Analyst-hours "burned" on FPs per week = 30.0 × 5 = 150 analyst-hours/week
As a fraction of total capacity:
  150 / (3 × 40) = 150 / 120 ≈ 125%
  → FP load ALONE exceeds normal capacity; analysts must either work overtime
    or let true positives age in the queue.
```

**Key finding:** The FP workload is not merely inconvenient — it structurally prevents adequate TP coverage. Even modest FP automation reducing FP review time by 60% frees ≈ 90 analyst-hours/week, equivalent to adding 2.25 full-time equivalent (FTE) analysts without hiring.

### 3.2 Delay — Dwell Time for True Positives

Because analysts are overwhelmed by FPs, true positives sit in the queue waiting for investigation. Every hour of delay on a genuine incident increases potential damage:

- **Lateral movement:** an attacker who has achieved initial access on a student machine can begin moving toward lab or admin segments during the delay window.
- **Data exfiltration:** sensitive research data or PII can be exfiltrated incrementally; delay directly increases volume of data lost.
- **Ransomware propagation:** once encryption begins, every hour unmissed increases scope of recovery effort.

Assuming a TP alert waits behind even 5 unresolved FPs (5 × 6 min = 30 minutes), a ransomware incident that takes 45 minutes to spread campus-wide is already uncontainable before the analyst opens the ticket.

### 3.3 Risk — Analyst Fatigue and Attention Degradation

Cognitive research (Kahneman, 2011; SANS Alert Fatigue Study 2022) establishes that decision quality degrades after sustained repetitive tasks. Analysts who review the same DHCP false positive for the 40th time in a week are statistically more likely to:

1. Close a genuine anomaly that superficially resembles the known FP pattern without adequate scrutiny ("cry-wolf effect").
2. Miss distinguishing signals (e.g., the packet came from an unpatched admin machine, not the usual student VLAN).
3. Under-document their rationale, creating audit gaps.

This risk is qualitative but has documented regulatory consequences (GDPR Article 32 requires "appropriate technical and organisational measures"; inadequate SOC coverage is auditable).

---

## 4. What "Novel Threat" Means in This Context

A **novel threat** is an alert that:

1. **Has no established disposition pattern** in the analyst decision history — the system has never seen enough examples of this `(alert_type, source_segment, context)` combination to form a reliable expectation about whether it is benign or malicious.
2. **OR** superficially resembles a high-frequency FP cluster but carries distinguishing contextual signals that are statistically rare in the FP cluster (e.g., the same DNS-flood signature appearing on an unpatched device in the admin segment, when all 200 prior observations of that signature came from patched student devices on DHCP churn).

### Why Naïve Automation is Dangerous Here

A naïve auto-suppressor would learn: "alert_type=DNS_FLOOD from source_segment=guest → always FP → close automatically." This logic would:

- **Correctly suppress** the 199 repetitive DHCP-churn DNS-flood alerts from student/guest networks (saving analyst time).
- **Incorrectly suppress** the 1 alert of the same type that is actually a DNS-tunnelling C2 channel established by a compromised guest-network machine, because it matches the learned pattern.

The danger is not that the rule is wrong in aggregate; it is that it treats all instances of a pattern as identical when the threat landscape guarantees they are not. Real attackers deliberately exploit this: they craft attacks to blend into known-noisy segments (a technique called "living off the land" in the detection literature), knowing that defenders have trained their automation on that noise.

**The assistant must therefore hold a firm principle:** it will only recommend suppression/auto-close for patterns where:
1. The match is specific enough (both alert type AND endpoint context AND source segment align with the FP cluster).
2. The evidence base exceeds a minimum configurable threshold.
3. The specific instance does not carry any distinguishing anomaly signal that was absent in the FP cluster.

If any of these conditions fails → the recommendation must be "ESCALATE FOR HUMAN REVIEW", not "suppress."

---

## 5. The Controlled Missed-Incident Rate Concept

### 5.1 Precision and Recall in the SOC Context

In the binary classification framing of alert disposition:

| | **Analyst decides: FP** | **Analyst decides: TP** |
|---|---|---|
| **Actually FP** | True Negative (TN) ✓ | False Positive (FP error) |
| **Actually TP** | **False Negative (FN) ✗ MISS** | True Positive (TP) ✓ |

- **Precision** of the assistant's "suggest FP" recommendation = TN / (TN + FP_error) — how often a suggested FP is truly benign.
- **Recall** of the assistant on true incidents = TP / (TP + FN) — what fraction of real incidents the assistant correctly escalates rather than suggesting suppression.
- **Missed-incident rate** = FN / (TP + FN) = 1 − Recall.

### 5.2 Why This Must Be a Tunable Ceiling, Not a Side Effect

An organisation that optimises purely for analyst efficiency will maximise FP suppression, driving Recall down until a real incident is missed — at which point regulatory, reputational, and operational damage ensues. Conversely, an organisation that never automates anything has 100% Recall but 0% efficiency gain (the status quo).

The correct design is a **configurable missed-incident rate ceiling** (`max_allowed_miss_rate` in `config/rules.yaml`), such that:

- The assistant will **only recommend auto-suppression** for patterns where the estimated FN probability on that pattern is below the ceiling.
- If tightening the FP-reduction aggressiveness would push the estimated miss rate above the ceiling, the system MUST reduce aggressiveness (raise the evidence threshold, lower confidence, or escalate to human review) rather than silently exceed it.
- The ceiling is set by the SOC Lead based on institutional risk appetite and is documented in the config — not buried in code.

**Why it must not be a side effect:** If miss rate is allowed to float freely, analysts cannot make informed risk/efficiency tradeoffs. The SOC Lead cannot report to the CISO "we automated 40% of FP closures with a guaranteed miss rate below 2%." The controllability of miss rate is itself a deliverable, not a nice-to-have.

### 5.3 The Arithmetic of the Tradeoff (Illustration)

Assume in Phase 2 experiments the rule-based assistant correctly identifies 85% of FPs and escalates 100% of TPs (ideal scenario).

```
FP alerts/day = 300 → assistant suggests FP for 255, correctly
                     → 45 still escalated to analyst (edge cases)
TP alerts/day = 100 → assistant escalates ALL 100 → miss rate = 0%

Analyst time saved = 255 × 6 min = 1,530 min/day = 25.5 analyst-hours/day
```

But if the confidence threshold is lowered too aggressively:

```
Assistant suggests FP for 290 of 300 FPs (correct) + 3 of 100 TPs (MISS)
Missed-incident rate = 3/100 = 3%
```

If the ceiling is set to 2%, this configuration must be **rejected by the system automatically** and the threshold raised back until miss rate <= 2%.

---

## 6. Success Criteria for Phase 1

| Criterion | Target |
|---|---|
| Problem document completeness | Covers all 4 stakeholder groups, quantified cost with stated assumptions |
| Dataset realism | Includes >=3 distinct FP clusters, >=1 novel TP masquerading as FP cluster |
| Rule-based recommender correctness | Never auto-suggests suppression for novel/unseen patterns |
| Failure-case handling | >=3 documented, tested edge cases |
| Explainability | Every recommendation cites specific evidence, never a score alone |
| Role separation | L1 and SOC Lead endpoints tested and differentiated |
| Config-driven thresholds | Zero business thresholds hard-coded in Python |

---

## 7. Project Roadmap & Phase Status

- **Phase 1 (Complete):** Rule-based baseline engine, data generation, SQLite schema, config guardrails, and baseline quantification (~1,933 analyst-hours spent on alerts).
- **Phase 2 (Delivered):**
  - Supervised Machine Learning model trained on analyst decisions (`model/train_model.py`, `model/artifacts/model.pkl`, `model/model_card.md`).
  - Time-series temporal validation and measured novel-threat preservation (`evaluation/temporal_validation_report.md`).
  - **Controlled Before/After Experiment:** The core requirement to *"compare analyst hours saved at controlled missed-incident rate ($\le 2\%$)"* is rigorously answered in **[`evaluation/before_after_report.md`](file:///c:/Users/navin/OneDrive/Desktop/proj/evaluation/before_after_report.md)** (demonstrating 16.42 hours saved in Condition 3 vs 6.57 hours in Condition 2, at 0.32% miss rate).
  - API authentication hardening with HMAC-SHA256 JWT tokens (`docs/03_auth_hardening.md`, `app/auth.py`).
- **Phase 3 (Next Steps):** Stakeholder validation sessions, interactive frontend dashboard / demo video, and final viva comprehensive evaluation report.

---

*End of Problem Analysis Document*
