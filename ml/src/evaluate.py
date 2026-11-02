"""
evaluate.py — Evaluation and threshold selection for the phishing detector.

Computes comprehensive classification metrics:
- Confusion matrix
- Accuracy, Precision, Recall, F1
- False Positive Rate (FPR), False Negative Rate (FNR)
- ROC-AUC, PR-AUC
- Operating thresholds and subset evaluations
- False-positive and false-negative CSV export
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
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
) -> tuple[float, dict[str, Any]]:
    """
    Scan candidate thresholds on validation set and return the one that maximises F1.
    """
    if thresholds is None:
        thresholds = np.linspace(0.1, 0.9, 81)

    best_f1 = -1.0
    best_thresh = 0.5
    best_metrics: dict[str, Any] = {}

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
) -> dict[str, Any]:
    """Compute a comprehensive set of classification metrics."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    n_total = len(y_true)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    try:
        roc_auc = float(roc_auc_score(y_true, y_prob))
    except ValueError:
        roc_auc = float("nan")

    try:
        pr_auc = float(average_precision_score(y_true, y_prob))
    except ValueError:
        pr_auc = float("nan")

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "false_positive_rate": round(fpr, 6),
        "false_negative_rate": round(fnr, 6),
        "n_samples": n_total,
    }


def export_error_cases(
    urls: list[str] | np.ndarray,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray,
    X: np.ndarray,
    feature_names: list[str],
    reports_dir: str | Path,
) -> tuple[Path, Path]:
    """
    Export false positive and false negative diagnostics into CSV files.
    """
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    df_base = pd.DataFrame(
        {
            "url": urls,
            "ground_truth_label": y_true,
            "predicted_label": y_pred,
            "model_score": np.round(y_prob, 6),
        }
    )

    feat_df = pd.DataFrame(X, columns=feature_names)
    full_df = pd.concat([df_base, feat_df], axis=1)

    fp_df = full_df[(full_df["ground_truth_label"] == 0) & (full_df["predicted_label"] == 1)]
    fn_df = full_df[(full_df["ground_truth_label"] == 1) & (full_df["predicted_label"] == 0)]

    fp_path = reports_dir / "false_positives.csv"
    fn_path = reports_dir / "false_negatives.csv"

    fp_df.to_csv(fp_path, index=False)
    fn_df.to_csv(fn_path, index=False)

    logger.info("Exported %d false positives to %s", len(fp_df), fp_path)
    logger.info("Exported %d false negatives to %s", len(fn_df), fn_path)

    return fp_path, fn_path


def evaluate_subsets(
    urls: list[str] | np.ndarray,
    y_true: np.ndarray,
    y_prob: np.ndarray,
    threshold: float,
) -> dict[str, Any]:
    """
    Evaluate performance on relevant subsets:
    - Legitimate popular domains
    - URLs on shared/free hosting platforms (firebaseapp, web.app, github.io, weebly, etc.)
    - URLs with brand/security tokens
    """
    y_pred = (y_prob >= threshold).astype(int)
    urls_arr = np.asarray(urls, dtype=str)

    subsets = {}

    # Subset 1: Shared hosting / app platforms
    shared_hosts = ("firebaseapp.com", "web.app", "github.io", "weeblysite.com", "blogspot.com", "pages.dev")
    mask_shared = np.array([any(sh in u.lower() for sh in shared_hosts) for u in urls_arr])
    if mask_shared.sum() > 0:
        subsets["shared_hosting_platforms"] = _compute_metrics(
            y_true[mask_shared], y_pred[mask_shared], y_prob[mask_shared]
        )

    # Subset 2: URLs with sensitive/auth words in path
    auth_words = ("login", "signin", "verify", "account", "update", "banking")
    mask_auth = np.array([any(aw in u.lower() for aw in auth_words) for u in urls_arr])
    if mask_auth.sum() > 0:
        subsets["auth_keyword_urls"] = _compute_metrics(
            y_true[mask_auth], y_pred[mask_auth], y_prob[mask_auth]
        )

    # Subset 3: IP address URLs
    mask_ip = np.array([bool("://" in u and u.split("://")[1].split("/")[0].replace(".", "").isdigit()) for u in urls_arr])
    if mask_ip.sum() > 0:
        subsets["ip_address_hostnames"] = _compute_metrics(
            y_true[mask_ip], y_pred[mask_ip], y_prob[mask_ip]
        )

    return subsets


def evaluate_on_split(
    model: Any,
    X: np.ndarray,
    y: np.ndarray,
    threshold: float,
    split_name: str = "test",
) -> dict[str, Any]:
    """Run model prediction and compute metrics on split."""
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
    logger.info("  PR-AUC              : %.4f", m.get("pr_auc", float("nan")))
    logger.info("  Threshold used      : %.4f", m.get("threshold_used", float("nan")))
    logger.info("  TP=%d  TN=%d  FP=%d  FN=%d", m["tp"], m["tn"], m["fp"], m["fn"])
    logger.info("  False Positive Rate : %.4f (%.2f%%)", m["false_positive_rate"], m["false_positive_rate"] * 100)
    logger.info("  False Negative Rate : %.4f (%.2f%%)", m["false_negative_rate"], m["false_negative_rate"] * 100)
    logger.info(sep)


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
