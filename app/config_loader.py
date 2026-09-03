"""
app/config_loader.py
====================
Loads and validates config/rules.yaml at runtime.

WHY A DEDICATED CONFIG LOADER (not just yaml.safe_load inline):
    (a) Centralises the load logic so tests and the API use the same path.
    (b) Allows the PUT /config/rules endpoint to write changes back and
        invalidate an in-memory cache so the next request sees the new config.
    (c) The validation step ensures that a corrupted config file does not
        silently produce wrong recommendations — it raises clearly.

CACHING STRATEGY:
    The config is cached in module-level state (_cached_config).
    The cache is invalidated by calling invalidate_config_cache().
    This is called by the PUT /config/rules endpoint after writing the file.
    A production system would use a file-watcher or Redis pub/sub;
    in-memory cache is sufficient for Phase 1 single-process deployment.
"""

import yaml
import threading
from pathlib import Path
from typing import Any

CONFIG_PATH = Path(__file__).parent.parent / "config" / "rules.yaml"

_cached_config: dict | None = None
_cache_lock = threading.Lock()


def get_config() -> dict:
    """
    Load config/rules.yaml, using the in-memory cache if available.
    Thread-safe via a lock.
    """
    global _cached_config
    with _cache_lock:
        if _cached_config is None:
            _cached_config = _load_and_validate()
        return _cached_config


def invalidate_config_cache() -> None:
    """
    Force the next get_config() call to re-read from disk.
    Called by the PUT /config/rules endpoint after writing changes.
    """
    global _cached_config
    with _cache_lock:
        _cached_config = None


def _load_and_validate() -> dict:
    """
    Read config/rules.yaml from disk and perform structural validation.
    Raises ValueError with a descriptive message if required keys are missing.
    """
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Config file not found: {CONFIG_PATH}\n"
            "Expected at: config/rules.yaml relative to project root."
        )

    with open(CONFIG_PATH, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    if not isinstance(cfg, dict):
        raise ValueError("rules.yaml must be a YAML mapping at the top level.")

    # Required top-level keys
    required_keys = [
        "evidence",
        "conflict",
        "anomaly_signals",
        "auto_suggest_threshold",
        "max_allowed_miss_rate",
        "high_impact_actions",
        "role_permissions",
    ]
    missing = [k for k in required_keys if k not in cfg]
    if missing:
        raise ValueError(
            f"rules.yaml is missing required keys: {missing}. "
            "Check config/rules.yaml against the expected schema."
        )

    # Required evidence sub-keys
    required_evidence = [
        "min_evidence_count",
        "min_fp_rate_for_suggestion",
        "high_confidence_fp_threshold",
        "lookback_window",
    ]
    missing_ev = [k for k in required_evidence if k not in cfg.get("evidence", {})]
    if missing_ev:
        raise ValueError(
            f"rules.yaml evidence section is missing keys: {missing_ev}."
        )

    return cfg


def update_config(updates: dict[str, Any]) -> dict:
    """
    Merge updates into the current config and write back to disk.
    Returns the updated config dict.

    Only SOC Lead (L2) role may call this — enforced at the API layer.
    This function performs no role check itself (separation of concerns).
    """
    current = get_config()

    # Deep merge: only update keys that are explicitly provided
    updated = _deep_merge(current, updates)

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.dump(updated, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    invalidate_config_cache()
    return updated


def _deep_merge(base: dict, overrides: dict) -> dict:
    """Recursively merge overrides into base."""
    result = dict(base)
    for key, value in overrides.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
