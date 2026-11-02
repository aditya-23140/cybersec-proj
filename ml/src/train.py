"""
train.py — Training entry point for the URL phishing detection model.

Usage:
    cd ml
    python -m src.train [--data-path data/phiusiil.csv] [--output-dir artifacts/] [--seed 42]

Features:
- Validates and normalizes PhiUSIIL labels (1=phishing, 0=legitimate)
- Removes duplicates and near-duplicates
- Extracts 21 URL-observable features with zero training/inference discrepancy
- Uses domain-disjoint splitting to prevent cross-split leakage
- Fits Platt scaling calibrator on validation split
- Selects optimal decision threshold on validation set (maximising F1)
- Evaluates complete metrics and relevant subsets on held-out test set
- Exports false-positive and false-negative diagnostics to CSV
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import numpy as np

# ── Ensure we can import sibling modules when run as __main__ ──────────────
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    __package__ = "src"

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Grid search helpers
# ─────────────────────────────────────────────────────────────────────────────


def _grid_search(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    param_grid: dict,
    scale_pos_weight: float,
    seed: int,
) -> tuple[object, dict, float]:
    """
    Grid search over param_grid using F1 on the val set as selection criterion.
    """
    from itertools import product
    from sklearn.metrics import f1_score
    from xgboost import XGBClassifier

    keys = list(param_grid.keys())
    values = list(param_grid.values())

    best_model = None
    best_params: dict = {}
    best_val_f1 = -1.0

    combos = list(product(*values))
    logger.info("Grid search: %d hyperparameter combinations.", len(combos))

    for combo in combos:
        params = dict(zip(keys, combo))
        logger.info("  Trying: %s", params)

        model = XGBClassifier(
            **params,
            scale_pos_weight=scale_pos_weight,
            random_state=seed,
            eval_metric="logloss",
            tree_method="hist",
            verbosity=0,
        )
        model.fit(
            X_train,
            y_train,
            eval_set=[(X_val, y_val)],
            verbose=False,
        )

        y_val_pred = model.predict(X_val)
        val_f1 = f1_score(y_val, y_val_pred, zero_division=0)
        logger.info("  Val F1: %.4f", val_f1)

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_model = model
            best_params = params

    logger.info("Best hyperparams: %s  (val F1=%.4f)", best_params, best_val_f1)
    return best_model, best_params, best_val_f1  # type: ignore[return-value]


# ─────────────────────────────────────────────────────────────────────────────
# Main training routine
# ─────────────────────────────────────────────────────────────────────────────


def train(
    data_path: str | Path | None,
    output_dir: str | Path,
    reports_dir: str | Path,
    seed: int,
    force_synthetic: bool = False,
) -> None:
    """
    Full training pipeline.
    """
    import config
    from .data_loader import (
        load_dataset,
        load_multi_source_dataset,
        load_phiusiil,
    )
    from .data_validation import deduplicate, validate_dataset
    from .evaluate import (
        _compute_metrics,
        evaluate_subsets,
        export_error_cases,
        select_threshold_by_f1,
    )
    from .feature_extractor import FEATURE_NAMES
    from .model_registry import (
        save_calibration,
        save_eval_results,
        save_feature_schema,
        save_metadata,
        save_model,
        save_threshold_config,
    )
    from .preprocessing import domain_grouped_split, extract_feature_matrix

    t_start = time.time()
    output_dir = Path(output_dir)
    reports_dir = Path(reports_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. Load dataset ───────────────────────────────────────────────────
    if force_synthetic:
        df, is_synthetic = load_dataset(
            config.DATA_DIR, config.PHIUSIIL_URL, config.DOWNLOAD_TIMEOUT, True
        )
    else:
        phiusiil_path = (
            Path(data_path)
            if data_path and Path(data_path).exists()
            else Path(config.DATA_DIR) / "phiusiil.csv"
        )
        if not phiusiil_path.exists():
            from .data_loader import download_phiusiil

            phiusiil_path = download_phiusiil(
                config.PHIUSIIL_URL, config.DATA_DIR, config.DOWNLOAD_TIMEOUT
            )
        try:
            df, is_synthetic = load_multi_source_dataset(
                phiusiil_path,
                config.PHIUSIIL_URL,
                config.OPENPHISH_FEED_URL,
                config.TRANCO_URL,
                config.DATA_DIR,
                config.DOWNLOAD_TIMEOUT,
                config.MULTI_SOURCE_MAX_ROWS,
            )
        except Exception as exc:
            logger.warning("Multi-source loading encountered error (%s); falling back to PhiUSIIL file directly.", exc)
            df = load_phiusiil(phiusiil_path)
            is_synthetic = False

    if is_synthetic:
        logger.warning(
            "═══════════════════════════════════════════════════════\n"
            "  SYNTHETIC DATA IN USE — metrics are NOT representative\n"
            "  of real-world phishing detection performance.\n"
            "═══════════════════════════════════════════════════════"
        )

    # ── 2. Validate and deduplicate ───────────────────────────────────────
    val_report = validate_dataset(df, is_synthetic=is_synthetic)
    df = deduplicate(df)

    # ── 3. Extract features ───────────────────────────────────────────────
    logger.info("Extracting features for %d URLs …", len(df))
    X, y, valid_idx = extract_feature_matrix(df, show_progress=True)

    # ── 4. Domain-grouped split ───────────────────────────────────────────
    valid_urls = df.iloc[valid_idx]["url"].to_numpy()
    (
        X_train, X_val, X_test,
        y_train, y_val, y_test,
        urls_train, urls_val, urls_test,
    ) = domain_grouped_split(
        X,
        y,
        valid_urls,
        test_size=config.TEST_SIZE,
        val_size=config.VAL_SIZE,
        random_state=seed,
    )

    # ── 5. Class balance for weighting ────────────────────────────────────
    n_neg = int((y_train == 0).sum())
    n_pos = int((y_train == 1).sum())
    scale_pos_weight = n_neg / n_pos if n_pos > 0 else 1.0
    logger.info(
        "Class balance (train): legitimate=%d, phishing=%d → scale_pos_weight=%.4f",
        n_neg, n_pos, scale_pos_weight,
    )

    # ── 6. Grid search ────────────────────────────────────────────────────
    best_model, best_params, best_val_f1 = _grid_search(
        X_train, y_train,
        X_val, y_val,
        config.PARAM_GRID,
        scale_pos_weight=scale_pos_weight,
        seed=seed,
    )

    # ── 7. Probability calibration & threshold selection on val set ───────
    y_val_prob_raw = best_model.predict_proba(X_val)[:, 1]
    from sklearn.linear_model import LogisticRegression

    raw_val_logit = np.log(
        np.clip(y_val_prob_raw, 1e-6, 1 - 1e-6)
        / np.clip(1 - y_val_prob_raw, 1e-6, 1)
    ).reshape(-1, 1)

    calibrator = LogisticRegression(solver="lbfgs")
    calibrator.fit(raw_val_logit, y_val)
    slope = float(calibrator.coef_[0, 0])
    intercept = float(calibrator.intercept_[0])

    y_val_prob = 1.0 / (1.0 + np.exp(-(slope * raw_val_logit[:, 0] + intercept)))
    opt_threshold, val_metrics = select_threshold_by_f1(y_val, y_val_prob)
    logger.info("Optimal threshold (max val F1): %.4f", opt_threshold)

    # Risk-level thresholds: suspicious = opt*0.7, dangerous = min(0.90, opt + 0.15)
    suspicious_thresh = round(max(0.20, opt_threshold * 0.7), 4)
    dangerous_thresh = round(min(0.90, max(0.65, opt_threshold + 0.15)), 4)

    # ── 8. Evaluate on test set ───────────────────────────────────────────
    raw_test_prob = best_model.predict_proba(X_test)[:, 1]
    raw_test_logit = np.log(
        np.clip(raw_test_prob, 1e-6, 1 - 1e-6)
        / np.clip(1 - raw_test_prob, 1e-6, 1)
    )
    test_prob = 1.0 / (1.0 + np.exp(-(slope * raw_test_logit + intercept)))
    test_pred = (test_prob >= opt_threshold).astype(int)

    test_metrics = _compute_metrics(y_test, test_pred, test_prob)
    test_metrics["split"] = "test"
    test_metrics["threshold_used"] = opt_threshold

    # Subset evaluations
    subsets_metrics = evaluate_subsets(urls_test, y_test, test_prob, opt_threshold)

    # Export false positives and false negatives to CSV
    fp_path, fn_path = export_error_cases(
        urls_test, y_test, test_pred, test_prob, X_test, FEATURE_NAMES, reports_dir
    )

    t_elapsed = time.time() - t_start

    # ── 9. Save artifacts ─────────────────────────────────────────────────
    save_model(best_model, output_dir)
    save_calibration(output_dir, slope, intercept)
    save_feature_schema(output_dir, FEATURE_NAMES, {}, 0.0)

    save_threshold_config(
        output_dir,
        suspicious_threshold=suspicious_thresh,
        dangerous_threshold=dangerous_thresh,
        optimal_f1_threshold=opt_threshold,
        val_metrics=val_metrics,
    )

    dataset_info = {
        "is_synthetic": is_synthetic,
        "n_total": val_report["row_count"],
        "n_unique": val_report["unique_url_count"],
        "n_phishing": val_report["n_phishing"],
        "n_legitimate": val_report["n_legitimate"],
        "duplicate_count": val_report["duplicate_count"],
        "train_size": len(X_train),
        "val_size": len(X_val),
        "test_size": len(X_test),
        "source_counts": df["source"].value_counts().to_dict()
        if "source" in df.columns
        else {},
        "training_sources": sorted(df["source"].unique())
        if "source" in df.columns
        else [],
    }

    save_metadata(
        output_dir,
        model_version=config.MODEL_VERSION,
        dataset_info=dataset_info,
        best_hyperparams=best_params,
        training_duration_seconds=t_elapsed,
        is_synthetic=is_synthetic,
        feature_count=len(FEATURE_NAMES),
    )

    eval_results = {
        "test_metrics": test_metrics,
        "val_metrics_at_optimal_threshold": val_metrics,
        "optimal_threshold": opt_threshold,
        "suspicious_threshold": suspicious_thresh,
        "dangerous_threshold": dangerous_thresh,
        "best_hyperparams": best_params,
        "is_synthetic_data": is_synthetic,
        "training_duration_seconds": round(t_elapsed, 2),
        "dataset_info": dataset_info,
        "subset_metrics": subsets_metrics,
        "error_case_paths": {
            "false_positives": str(fp_path),
            "false_negatives": str(fn_path),
        },
    }
    save_eval_results(output_dir, eval_results)

    # ── 10. Save human-readable evaluation report ─────────────────────────
    report_path = reports_dir / "evaluation_report.json"
    with open(report_path, "w") as f:
        json.dump(eval_results, f, indent=2, default=str)
    logger.info("Evaluation report saved to %s", report_path)

    # ── Done ──────────────────────────────────────────────────────────────
    logger.info("")
    logger.info("══════════════════════════════════════════")
    logger.info("  Training complete in %.1f seconds.", t_elapsed)
    logger.info("  Test Accuracy : %.4f", test_metrics["accuracy"])
    logger.info("  Test Precision: %.4f", test_metrics["precision"])
    logger.info("  Test Recall   : %.4f", test_metrics["recall"])
    logger.info("  Test F1       : %.4f", test_metrics["f1"])
    logger.info("  Test ROC-AUC  : %.4f", test_metrics["roc_auc"])
    logger.info("  Test PR-AUC   : %.4f", test_metrics["pr_auc"])
    logger.info("  Test FPR      : %.4f (%.2f%%)", test_metrics["false_positive_rate"], test_metrics["false_positive_rate"] * 100)
    logger.info("  Test FNR      : %.4f (%.2f%%)", test_metrics["false_negative_rate"], test_metrics["false_negative_rate"] * 100)
    logger.info("  Artifacts in  : %s/", output_dir)
    logger.info("  Reports in    : %s/", reports_dir)
    logger.info("══════════════════════════════════════════")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train the XGBoost phishing URL detection model."
    )
    parser.add_argument(
        "--data-path",
        default=None,
        help="Path to PhiUSIIL CSV. If omitted, auto-downloaded or synthetic used.",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/",
        help="Directory to save model artifacts.",
    )
    parser.add_argument(
        "--reports-dir",
        default="reports/",
        help="Directory to save evaluation reports.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed (default: 42).",
    )
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="Force use of the synthetic fallback dataset (for testing).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    train(
        data_path=args.data_path,
        output_dir=args.output_dir,
        reports_dir=args.reports_dir,
        seed=args.seed,
        force_synthetic=args.synthetic,
    )


if __name__ == "__main__":
    main()
