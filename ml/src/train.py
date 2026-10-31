"""
train.py — Training entry point for the URL phishing detection model.

Usage:
    cd ml
    python -m src.train [--data-path data/phiusiil.csv] [--output-dir artifacts/] [--seed 42]

If --data-path is omitted or the file does not exist, the script attempts
to download the PhiUSIIL dataset and falls back to a synthetic dataset if
the download fails.
"""

from __future__ import annotations

import argparse
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
    Manual grid search over param_grid using F1 on the val set as the
    selection criterion.

    Returns
    -------
    (best_model, best_params, best_val_f1)
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

    logger.info(
        "Best hyperparams: %s  (val F1=%.4f)", best_params, best_val_f1
    )
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

    1. Load / download dataset
    2. Validate and deduplicate
    3. Extract features
    4. Split into train / val / test
    5. Grid-search XGBoost hyper-parameters
    6. Select threshold on val set (maximise F1)
    7. Evaluate on test set
    8. Save all artefacts
    """
    import sys

    import config
    from .data_loader import load_dataset, load_phiusiil
    from .data_validation import deduplicate, validate_dataset
    from .evaluate import evaluate_on_split, select_threshold_by_f1
    from .feature_extractor import FEATURE_NAMES, set_network_fallbacks
    from .model_registry import (
        save_eval_results,
        save_feature_schema,
        save_metadata,
        save_model,
        save_threshold_config,
    )
    from .preprocessing import extract_feature_matrix, stratified_split

    t_start = time.time()
    output_dir = Path(output_dir)
    reports_dir = Path(reports_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. Load dataset ───────────────────────────────────────────────────
    if data_path and Path(data_path).exists():
        logger.info("Loading dataset from %s", data_path)
        try:
            df = load_phiusiil(data_path)
            is_synthetic = False
        except Exception as exc:
            logger.error("Failed to load %s: %s. Trying download/fallback.", data_path, exc)
            df, is_synthetic = load_dataset(
                config.DATA_DIR,
                config.PHIUSIIL_URL,
                config.DOWNLOAD_TIMEOUT,
                force_synthetic,
            )
    else:
        df, is_synthetic = load_dataset(
            config.DATA_DIR,
            config.PHIUSIIL_URL,
            config.DOWNLOAD_TIMEOUT,
            force_synthetic,
        )

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
    X, y, _ = extract_feature_matrix(df, show_progress=True)

    # Compute median nameservers from training data for fallback override
    ns_idx = FEATURE_NAMES.index("qty_nameservers")
    median_ns = float(np.median(X[:, ns_idx]))
    set_network_fallbacks(median_nameservers=median_ns)
    logger.info("Median qty_nameservers in dataset: %.2f", median_ns)

    # ── 4. Split ──────────────────────────────────────────────────────────
    X_train, X_val, X_test, y_train, y_val, y_test = stratified_split(
        X, y,
        test_size=config.TEST_SIZE,
        val_size=config.VAL_SIZE,
        random_state=seed,
    )

    # ── 5. Class weight for imbalance ─────────────────────────────────────
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

    # ── 7. Threshold selection on val set ─────────────────────────────────
    y_val_prob = best_model.predict_proba(X_val)[:, 1]
    opt_threshold, val_metrics = select_threshold_by_f1(y_val, y_val_prob)
    logger.info("Optimal threshold (max val F1): %.4f", opt_threshold)

    # Risk-level thresholds: suspicious = opt*0.6, dangerous = opt + 0.15 (clamped)
    suspicious_thresh = round(max(0.2, opt_threshold * 0.6), 4)
    dangerous_thresh = round(min(0.95, opt_threshold + 0.15), 4)

    # ── 8. Evaluate on test set ───────────────────────────────────────────
    test_metrics = evaluate_on_split(
        best_model, X_test, y_test, threshold=opt_threshold, split_name="test"
    )

    t_elapsed = time.time() - t_start

    # ── 9. Save artifacts ─────────────────────────────────────────────────
    save_model(best_model, output_dir)

    fallback_values = {
        "qty_nameservers": median_ns,
        "is_spf_domain": 0.0,
        "time_domain_activation": -1.0,
    }
    save_feature_schema(output_dir, FEATURE_NAMES, fallback_values, median_ns)

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
    }
    save_eval_results(output_dir, eval_results)

    # ── 10. Save human-readable evaluation report ─────────────────────────
    import json
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "evaluation_report.json"
    with open(report_path, "w") as f:
        json.dump(eval_results, f, indent=2, default=str)
    logger.info("Evaluation report saved to %s", report_path)

    # ── Done ──────────────────────────────────────────────────────────────
    logger.info("")
    logger.info("══════════════════════════════════════════")
    logger.info("  Training complete in %.1f seconds.", t_elapsed)
    logger.info("  Test Accuracy : %.4f", test_metrics["accuracy"])
    logger.info("  Test F1       : %.4f", test_metrics["f1"])
    logger.info("  Test ROC-AUC  : %.4f", test_metrics["roc_auc"])
    logger.info("  Artifacts in  : %s/", output_dir)
    if is_synthetic:
        logger.warning("  ⚠  Synthetic data used — see dataset note above.")
    logger.info("══════════════════════════════════════════")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────


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
