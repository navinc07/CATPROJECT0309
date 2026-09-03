# Failure Cases — SOC False-Positive Reduction Assistant

**Course:** C28 — AI Immersion (Semester 5)  
**Document Version:** 1.0 (Phase 1)  
**Date:** 2026-09-03

---

## Overview

This document describes the 4 failure/edge cases designed into the system, the rationale for each, and how the corresponding test code (`tests/test_failure_cases.py`) verifies them.

These failure cases are not afterthoughts — they are designed INTO the system before the happy path, because in a security context, the failure mode of an automated tool is often more consequential than its average-case behaviour.

---

## Failure Case F1: Missing / Incomplete Endpoint Context

### Description
An analyst requests a recommendation for an alert where the endpoint context record is absent or contains null values for critical fields (`is_managed_device`, `known_vuln_count`). This simulates guest-network BYOD devices that are not enrolled in the university MDM system.

### Why This Matters
The recommendation engine uses endpoint context to detect anomaly signals (unpatched device, unmanaged device, high vulnerability count). Without context, the engine CANNOT distinguish between a routine guest-network DNS flood (FP) and a DNS-tunnelling C2 channel from an unmanaged device (TP). Guessing "FP" without context risks missing an incident. Crashing is obviously unacceptable.

### Required Behaviour
- The engine must **NOT** crash.
- The engine must **NOT** auto-suggest FP (no context = no anomaly check = unknown risk).
- The recommendation type must be `insufficient_evidence`.
- The confidence tier must be `INSUFFICIENT_EVIDENCE`.
- `requires_human_confirmation` must be `True`.
- The `anomaly_flags` list must include a `MISSING_ENDPOINT_CONTEXT` flag.
- The evidence_detail must explain WHY context is required (for audit).

### What Would Be Wrong
- Returning `suggest_fp` with `confidence=0.9` because the pattern historically matches FP — this ignores that we can't verify the device state.
- Returning HTTP 500.
- Silently returning a recommendation with empty anomaly_flags.

---

## Failure Case F2: Conflicting Analyst History

### Description
The same `(alert_type, source_segment)` pattern has been dispositioned as both `false_positive` AND `true_positive` by different analysts in the historical data, with the TP count exceeding the `conflict_threshold` in `config/rules.yaml`.

This is engineered into `data/analyst_decisions.csv`: 10 `PORT_SCAN` / `student` alerts each have two conflicting decisions from different analysts.

### Why This Matters
If the pattern history contains both FP and TP decisions, the FP rate is misleadingly high in aggregate but individual instances may be genuine incidents. Auto-suggesting suppression based on the aggregate FP rate could cause the system to auto-close an alert that a different analyst correctly identified as a real incident.

### Required Behaviour
- The recommendation type must be `conflicting_evidence`.
- `requires_human_confirmation` must be `True`.
- The engine must **NOT** suggest FP suppression.
- The evidence_detail must include the conflict counts (FP count and TP count).
- The SOC Lead should be notified to review the pattern (surfaced via the evidence detail).

### What Would Be Wrong
- Returning `suggest_fp` because the aggregate FP rate is above threshold.
- Ignoring the TP minority in the history.
- Returning `suggest_tp` without evidence (also wrong — it's ambiguous).

---

## Failure Case F3: Novel TP Masquerading as Known FP Cluster

### Description
An alert of type `DNS_FLOOD` from the `guest` segment statistically matches FP Cluster 2 (same `alert_type`, same `source_segment`, same `signature_rule_triggered`). However, the endpoint context shows:
- `is_managed_device = False` (unregistered device)
- `known_vuln_count >= 3` (high vulnerability count)
- `patch_status = unpatched`
- `dst_ip = 8.8.8.8` (external, not internal DNS server)

These signals were absent in all historical FP Cluster 2 cases (which had managed, patched devices with 0 vulns and internal dst_ips).

### Why This Matters
This is the attack scenario described in `docs/01_problem_analysis.md §4`. An attacker establishes a DNS-tunnelling C2 channel from a compromised guest-network device, knowing that DNS_FLOOD alerts from the guest network are routinely auto-closed. A naïve pattern-matcher would suppress this alert. The system must detect the distinguishing signals and escalate.

### Required Behaviour
- The recommendation type must be `anomaly_signal_detected` (NOT `suggest_fp`).
- `requires_human_confirmation` must be `True`.
- `anomaly_flags` must include at minimum:
  - `UNMANAGED_DEVICE`
  - `HIGH_VULN_COUNT`
  - `UNPATCHED_DEVICE`
  - `EXTERNAL_DST_IP`
- The evidence_summary must explain that the pattern matches the FP cluster BUT the anomaly signals override the suggestion.
- confidence_tier must be `LOW` (not HIGH or MEDIUM).

### What Would Be Wrong
- Returning `suggest_fp` because FP rate for `DNS_FLOOD::guest` is 95%.
- Returning recommendation with empty anomaly_flags.
- Returning `HIGH` confidence — this is a borderline case and should be LOW.

---

## Failure Case F4: Extreme Config Values — Safety Ceiling and Floor

### Description
The SOC Lead (or a misconfigured rules.yaml file) sets `auto_suggest_threshold` below the hard floor (0.60) or `max_allowed_miss_rate` above the hard ceiling (0.10). 

### Why This Matters
A `auto_suggest_threshold` below 0.60 means the assistant would auto-suggest FP suppression even when only 60% of historical cases were FP — i.e., 40% of the time it would suggest closing a real incident. A `max_allowed_miss_rate` above 10% means the system accepts missing more than 1 in 10 real incidents. Both are unacceptable for a security tool.

These guardrails are deliberately NOT configurable — if they were in `rules.yaml`, an admin error (or a compromised config file) could disable them silently.

### Required Behaviour
- When the engine loads config with `auto_suggest_threshold < 0.60`:
  - It must log a `CONFIG_REJECTED` warning.
  - It must use the floor value (0.60) instead of the configured value.
  - The recommendation response must include the warning in `evidence_detail.config_warnings`.
  - It must **NOT** raise an exception or refuse to operate.
- When the engine loads config with `max_allowed_miss_rate > 0.10`:
  - Same: log warning, use ceiling (0.10), include in evidence_detail.
  - Must **NOT** crash.
- The PUT `/config/rules` endpoint must accept the update (so the SOC Lead can intentionally experiment) but the guardrails kick in at recommendation time.

### What Would Be Wrong
- Silently accepting the extreme value and using it.
- Raising HTTP 500 when the config is extreme.
- Crashing the application on startup.

---

## Summary Matrix

| Case | Trigger | Wrong Behaviour | Required Behaviour |
|---|---|---|---|
| F1 | Missing endpoint context | Return `suggest_fp` / crash | Return `insufficient_evidence`, human review required |
| F2 | Conflicting analyst history (FP+TP for same pattern) | Return `suggest_fp` based on aggregate FP rate | Return `conflicting_evidence`, escalate |
| F3 | Novel TP with anomaly signals matching FP cluster | Return `suggest_fp` (naïve pattern match) | Return `anomaly_signal_detected`, escalate |
| F4 | Config threshold below safety floor / above ceiling | Use unsafe value silently | Clamp to guardrail, log warning, include in response |

---

*See `tests/test_failure_cases.py` for the corresponding test code.*
