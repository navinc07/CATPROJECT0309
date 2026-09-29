#!/usr/bin/env bash
# =============================================================================
# scripts/run_phase2_pipeline.sh
# =============================================================================
# Bash wrapper for running the Phase 2 reproducible pipeline in POSIX / Linux
# environments.
#
# Usage:
#   bash scripts/run_phase2_pipeline.sh
# =============================================================================

set -e

echo "Starting University SOC FP Reduction Assistant Phase 2 Pipeline..."
python scripts/run_phase2_pipeline.py
