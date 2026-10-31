"""
evaluate.py — Evaluation and threshold selection for the phishing detector.

Run after training to compute metrics on the held-out test set.
Saves results to reports/evaluation_report.json.

Usage (standalone):
    cd ml
    python -m src.evaluate --artifacts-dir artifacts/ --reports-dir reports/
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Threshold selection
# ─────────────────────────────────────────────────────────────────────────────


def select_threshold_by_f1(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    thresholds: np.ndarray | None = None,
) -> tuple[float, dict[str, float]]:
    """
    Scan candidate thresholds and return the one that maximises F1.

    Returns
    -------
    (best_threshold, metrics_at_best_threshold)
    """
    if thresholds is None:
        thresholds = np.linspace(0.1, 0.9, 81)

    best_f1 = -1.0
    best_thresh = 0.5
    best_metrics: dict[str, float] = {}

    for thresh in thresholds:
        y_pred = (y_prob >= thresh).astype(int)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_thresh = float(thresh)
            best_metrics = _compute_metrics(y_true, y_pred, y_prob)

    return best_thresh, best_metrics


# ─────────────────────────────────────────────────────────────────────────────
# Metrics helpers
# ─────────────────────────────────────────────────────────────────────────────


def _compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray,
) -> dict[str, float]:
    """Compute a comprehensive set of classification metrics."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    n_total = len(y_true)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    try:
        auc = float(roc_auc_score(y_true, y_prob))
    except ValueError:
        auc = float("nan")

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": auc,
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "false_positive_rate": round(fpr, 6),
        "false_negative_rate": round(fnr, 6),
        "n_samples": n_total,
    }


def evaluate_on_split(
    model: Any,
    X: np.ndarray,
    y: np.ndarray,
    threshold: float,
    split_name: str = "test",
) -> dict[str, Any]:
    """
    Run the model on *X* with *threshold* and return a metrics dict.
    """
    y_prob = model.predict_proba(X)[:, 1]
    y_pred = (y_prob >= threshold).astype(int)
    metrics = _compute_metrics(y, y_pred, y_prob)
    metrics["split"] = split_name
    metrics["threshold_used"] = threshold

    _print_metrics(metrics, split_name)
    return metrics


def _print_metrics(m: dict, split: str) -> None:
    sep = "─" * 55
    logger.info(sep)
    logger.info("Evaluation on %s set", split.upper())
    logger.info(sep)
    logger.info("  Accuracy            : %.4f", m["accuracy"])
    logger.info("  Precision           : %.4f", m["precision"])
    logger.info("  Recall              : %.4f", m["recall"])
    logger.info("  F1 Score            : %.4f", m["f1"])
    logger.info("  ROC-AUC             : %.4f", m.get("roc_auc", float("nan")))
    logger.info("  Threshold used      : %.4f", m["threshold_used"])
    logger.info("  TP=%d  TN=%d  FP=%d  FN=%d", m["tp"], m["tn"], m["fp"], m["fn"])
    logger.info("  False Positive Rate : %.4f", m["false_positive_rate"])
    logger.info("  False Negative Rate : %.4f", m["false_negative_rate"])
    logger.info(sep)


# ─────────────────────────────────────────────────────────────────────────────
# Standalone CLI
# ─────────────────────────────────────────────────────────────────────────────


def _save_report(reports_dir: Path, report: dict) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / "evaluation_report.json"
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Evaluation report saved to %s", path)
    return path


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Evaluate phishing detection model")
    parser.add_argument("--artifacts-dir", default="artifacts/")
    parser.add_argument("--reports-dir", default="reports/")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    from . import model_registry

    eval_path = Path(args.artifacts_dir) / "eval_results.json"
    if not eval_path.exists():
        logger.error("eval_results.json not found. Run training first.")
        sys.exit(1)

    results = model_registry.load_eval_results(args.artifacts_dir)
    report_path = _save_report(Path(args.reports_dir), results)
    logger.info("Done. Report at %s", report_path)


if __name__ == "__main__":
    main()
