"""
model_registry.py — Save and load model artifacts.

Artifacts saved:
  - model.ubj               — XGBoost model in UBJ (binary JSON) format
  - feature_schema.json     — feature names, order, types, fallback values
  - threshold_config.json   — classification thresholds from val-set tuning
  - metadata.json           — version, training date, dataset info, hyperparams
  - eval_results.json       — actual measured metrics (never paper metrics)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _json_serialisable(obj: Any) -> Any:
    """Recursively convert numpy types to Python natives for JSON serialisation."""
    if isinstance(obj, dict):
        return {k: _json_serialisable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_serialisable(v) for v in obj]
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_json_serialisable(data), f, indent=2)
    logger.info("Saved %s", path)


def _load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# Model save / load
# ─────────────────────────────────────────────────────────────────────────────


def save_model(model: Any, artifacts_dir: str | Path) -> Path:
    """Save an XGBClassifier to ``artifacts_dir/model.ubj``."""
    artifacts_dir = Path(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    model_path = artifacts_dir / "model.ubj"
    model.save_model(str(model_path))
    logger.info("Model saved to %s (%.1f KB)", model_path, model_path.stat().st_size / 1024)
    return model_path


def load_model(artifacts_dir: str | Path) -> Any:
    """Load an XGBClassifier from ``artifacts_dir/model.ubj``."""
    from xgboost import XGBClassifier

    model_path = Path(artifacts_dir) / "model.ubj"
    if not model_path.exists():
        raise FileNotFoundError(
            f"Model file not found: {model_path}\n"
            "Run 'python -m src.train' to train the model first."
        )
    model = XGBClassifier()
    model.load_model(str(model_path))
    logger.info("Model loaded from %s", model_path)
    return model


# ─────────────────────────────────────────────────────────────────────────────
# Feature schema
# ─────────────────────────────────────────────────────────────────────────────


def save_feature_schema(
    artifacts_dir: str | Path,
    feature_names: list[str],
    fallback_values: dict[str, float],
    median_nameservers: float,
) -> Path:
    """
    Persist the feature schema so inference can validate its input vector.

    Parameters
    ----------
    feature_names:
        Ordered list of feature names (FEATURE_NAMES).
    fallback_values:
        Dict mapping feature_name → fallback float used when network is off.
    median_nameservers:
        Median qty_nameservers from the training set (used as fallback).
    """
    schema = {
        "feature_names": feature_names,
        "feature_count": len(feature_names),
        "feature_types": {name: "float32" for name in feature_names},
        "fallback_values": fallback_values,
        "network_dependent_features": [],
        "median_nameservers": median_nameservers,
    }
    path = Path(artifacts_dir) / "feature_schema.json"
    _save_json(path, schema)
    return path


def load_feature_schema(artifacts_dir: str | Path) -> dict:
    path = Path(artifacts_dir) / "feature_schema.json"
    if not path.exists():
        raise FileNotFoundError(f"Feature schema not found: {path}")
    return _load_json(path)


# ─────────────────────────────────────────────────────────────────────────────
# Threshold config
# ─────────────────────────────────────────────────────────────────────────────


def save_threshold_config(
    artifacts_dir: str | Path,
    suspicious_threshold: float,
    dangerous_threshold: float,
    optimal_f1_threshold: float,
    val_metrics: dict[str, float],
) -> Path:
    """Save thresholds derived from val-set optimisation."""
    config = {
        "suspicious_threshold": suspicious_threshold,
        "dangerous_threshold": dangerous_threshold,
        "optimal_f1_threshold": optimal_f1_threshold,
        "val_metrics_at_optimal_threshold": val_metrics,
        "selection_criterion": "maximize_f1_on_validation_set",
    }
    path = Path(artifacts_dir) / "threshold_config.json"
    _save_json(path, config)
    return path


def load_threshold_config(artifacts_dir: str | Path) -> dict:
    path = Path(artifacts_dir) / "threshold_config.json"
    if not path.exists():
        raise FileNotFoundError(f"Threshold config not found: {path}")
    return _load_json(path)


def save_calibration(
    artifacts_dir: str | Path, slope: float, intercept: float
) -> Path:
    """Persist Platt-scaling parameters for the URL-model score."""
    path = Path(artifacts_dir) / "calibration.json"
    _save_json(
        path,
        {
            "method": "platt",
            "slope": float(slope),
            "intercept": float(intercept),
        },
    )
    return path


def load_calibration(artifacts_dir: str | Path) -> dict:
    path = Path(artifacts_dir) / "calibration.json"
    if not path.exists():
        raise FileNotFoundError(f"Calibration not found: {path}")
    return _load_json(path)


# ─────────────────────────────────────────────────────────────────────────────
# Metadata
# ─────────────────────────────────────────────────────────────────────────────


def save_metadata(
    artifacts_dir: str | Path,
    model_version: str,
    dataset_info: dict[str, Any],
    best_hyperparams: dict[str, Any],
    training_duration_seconds: float,
    is_synthetic: bool,
    feature_count: int = 8,
) -> Path:
    meta = {
        "model_version": model_version,
        "training_date_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_info": dataset_info,
        "best_hyperparams": best_hyperparams,
        "training_duration_seconds": round(training_duration_seconds, 2),
        "is_synthetic_data": is_synthetic,
        "framework": "xgboost",
        "feature_count": feature_count,
    }
    path = Path(artifacts_dir) / "metadata.json"
    _save_json(path, meta)
    return path


def load_metadata(artifacts_dir: str | Path) -> dict:
    path = Path(artifacts_dir) / "metadata.json"
    if not path.exists():
        raise FileNotFoundError(f"Metadata not found: {path}")
    return _load_json(path)


# ─────────────────────────────────────────────────────────────────────────────
# Evaluation results
# ─────────────────────────────────────────────────────────────────────────────


def save_eval_results(
    artifacts_dir: str | Path,
    results: dict[str, Any],
) -> Path:
    path = Path(artifacts_dir) / "eval_results.json"
    _save_json(path, results)
    return path


def load_eval_results(artifacts_dir: str | Path) -> dict:
    path = Path(artifacts_dir) / "eval_results.json"
    if not path.exists():
        raise FileNotFoundError(f"Eval results not found: {path}")
    return _load_json(path)
