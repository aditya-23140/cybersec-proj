"""
calibrate.py — Platt and Isotonic calibration with realistic-prior reweighting.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional, Tuple

import joblib
import numpy as np
from sklearn.isotonic import IsotonicRegression

from ml.v2.training.dataset import PhishDataset

logger = logging.getLogger(__name__)


def compute_ece(
    y_true: np.ndarray,
    probs: np.ndarray,
    sample_weight: Optional[np.ndarray] = None,
    n_bins: int = 10,
) -> Tuple[float, list[dict[str, Any]]]:
    """
    Computes Expected Calibration Error (ECE) and bin reliability data.
    """
    if sample_weight is None:
        sample_weight = np.ones_like(y_true, dtype=np.float64)
    else:
        sample_weight = np.asarray(sample_weight, dtype=np.float64)

    total_weight = np.sum(sample_weight)
    if total_weight <= 0:
        return 0.0, []

    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    reliability_bins: list[dict[str, Any]] = []

    for i in range(n_bins):
        low, high = bin_edges[i], bin_edges[i + 1]
        if i == n_bins - 1:
            mask = (probs >= low) & (probs <= high)
        else:
            mask = (probs >= low) & (probs < high)

        bin_weight = np.sum(sample_weight[mask])
        if bin_weight > 0:
            avg_prob = float(np.sum(sample_weight[mask] * probs[mask]) / bin_weight)
            fraction_pos = float(np.sum(sample_weight[mask] * y_true[mask]) / bin_weight)
            bin_ece = abs(avg_prob - fraction_pos)
            weight_ratio = bin_weight / total_weight
            ece += weight_ratio * bin_ece

            reliability_bins.append({
                "bin_low": round(float(low), 3),
                "bin_high": round(float(high), 3),
                "avg_prob": round(avg_prob, 4),
                "fraction_positive": round(fraction_pos, 4),
                "weight_fraction": round(float(weight_ratio), 4),
                "count": int(np.sum(mask)),
            })
        else:
            reliability_bins.append({
                "bin_low": round(float(low), 3),
                "bin_high": round(float(high), 3),
                "avg_prob": round(float((low + high) / 2.0), 4),
                "fraction_positive": 0.0,
                "weight_fraction": 0.0,
                "count": 0,
            })

    return float(ece), reliability_bins


def choose_thresholds(
    y_true: np.ndarray,
    probs: np.ndarray,
    sample_weight: Optional[np.ndarray] = None,
    target_fpr_phishing: float = 0.005,   # 0.5% FPR
    target_fpr_suspicious: float = 0.02,  # 2.0% FPR
) -> Tuple[float, float]:
    """
    Find thresholds on calibrated probabilities:
    - t_phishing: lowest threshold where FPR <= 0.5%
    - t_suspicious: lowest threshold where FPR <= 2.0%
    """
    if sample_weight is None:
        sample_weight = np.ones_like(y_true, dtype=np.float64)

    neg_mask = (y_true == 0)
    if not np.any(neg_mask):
        return 0.85, 0.50

    neg_probs = probs[neg_mask]
    neg_weights = sample_weight[neg_mask]
    total_neg_weight = np.sum(neg_weights)

    # Sort thresholds from 0 to 1
    candidate_thresholds = np.unique(np.concatenate([
        np.linspace(0.0, 1.0, 1001),
        neg_probs,
    ]))
    candidate_thresholds.sort()

    t_phishing = 0.90
    t_suspicious = 0.60
    found_phishing = False
    found_suspicious = False

    for t in candidate_thresholds:
        fpr = float(np.sum(neg_weights[neg_probs >= t]) / total_neg_weight)
        if not found_suspicious and fpr <= target_fpr_suspicious:
            t_suspicious = float(t)
            found_suspicious = True
        if not found_phishing and fpr <= target_fpr_phishing:
            t_phishing = float(t)
            found_phishing = True
            break

    # Guardrails
    if t_suspicious > t_phishing:
        t_suspicious = min(t_phishing * 0.7, t_phishing - 0.05)
    t_suspicious = max(0.05, min(0.95, t_suspicious))
    t_phishing = max(t_suspicious + 0.05, min(0.99, t_phishing))

    return round(float(t_phishing), 4), round(float(t_suspicious), 4)


def calibrate(
    model_or_path: Any,
    val_parquets: list[str],
    schema_path: Optional[str] = None,
    *,
    realistic_phishing_rate: float = 0.005,  # 0.5% prior in realistic browsing
    output_path: Optional[str] = None,
) -> dict:
    """
    Calibrate model predictions using Isotonic Regression with realistic prior reweighting.
    """
    if isinstance(model_or_path, (str, Path)):
        model = joblib.load(str(model_or_path))
    else:
        model = model_or_path

    # Load validation data
    ds = PhishDataset(val_parquets, extractor=schema_path)
    X_val, y_val, _ = ds.load()

    if len(y_val) == 0:
        raise ValueError("Validation set is empty for calibration")

    # Get raw predicted probabilities
    if hasattr(model, "predict_proba"):
        raw_probs = model.predict_proba(X_val)[:, 1]
    elif hasattr(model, "decision_function"):
        scores = model.decision_function(X_val)
        raw_probs = 1.0 / (1.0 + np.exp(-scores))
    else:
        raw_probs = model.predict(X_val).astype(np.float64)

    # Compute realistic sample weights
    n_pos = np.sum(y_val == 1)
    n_neg = np.sum(y_val == 0)

    sample_weights = np.ones_like(y_val, dtype=np.float64)
    if n_pos > 0 and n_neg > 0:
        pos_weight = realistic_phishing_rate / n_pos
        neg_weight = (1.0 - realistic_phishing_rate) / n_neg
        sample_weights[y_val == 1] = pos_weight
        sample_weights[y_val == 0] = neg_weight
        sample_weights /= np.mean(sample_weights)

    # Fit Isotonic Regression calibrator
    calibrator = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    calibrator.fit(raw_probs, y_val, sample_weight=sample_weights)
    calibrated_probs = calibrator.predict(raw_probs)

    # Compute thresholds & ECE
    t_phishing, t_suspicious = choose_thresholds(
        y_val, calibrated_probs, sample_weight=sample_weights
    )
    ece, reliability_data = compute_ece(
        y_val, calibrated_probs, sample_weight=sample_weights
    )

    if ece > 0.05:
        logger.warning(
            "CALIBRATION WARNING: ECE on realistic-prior val is %.4f (> 0.05 target)", ece
        )

    result = {
        "calibrator": calibrator,
        "t_phishing": t_phishing,
        "t_suspicious": t_suspicious,
        "ece": round(ece, 5),
        "realistic_rate": realistic_phishing_rate,
        "reliability_bins": reliability_data,
        "val_size": len(y_val),
    }

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(result, out_p)
        logger.info("Saved calibration bundle to %s", out_p)

    return result
