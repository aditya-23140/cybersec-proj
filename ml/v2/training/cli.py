"""
cli.py — Command-line interfaces for training, evaluation, and single-URL prediction.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Optional

import numpy as np

from ml.v2.training.bundle import ModelBundle
from ml.v2.training.calibrate import calibrate
from ml.v2.training.evaluate import evaluate_gates
from ml.v2.training.train import train

logger = logging.getLogger(__name__)


def cmd_train(args: argparse.Namespace) -> int:
    """CLI handler for training model bundle."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    logger.info("Starting FihhGuard v2 model training...")

    train_parquets = args.train_parquets
    val_parquets = args.val_parquets
    schema_path = args.schema
    output_dir = args.output_dir
    n_iter = args.n_iter
    seed = args.seed

    # 1. Train base model
    train_report = train(
        train_parquets=train_parquets,
        val_parquets=val_parquets,
        schema_path=schema_path,
        output_dir=output_dir,
        n_iter=n_iter,
        seed=seed,
    )
    logger.info("Training complete: Val PR-AUC: %.4f", train_report["val_prauc"])

    # 2. Calibrate model
    xgb_model_path = Path(output_dir) / "xgboost_model.joblib"
    calib_res = calibrate(
        model_or_path=xgb_model_path,
        val_parquets=val_parquets,
        schema_path=schema_path,
        realistic_phishing_rate=args.realistic_prior,
        output_path=Path(output_dir) / "calibration_bundle.joblib",
    )
    logger.info(
        "Calibration complete: t_phish=%.3f, t_susp=%.3f, ECE=%.4f",
        calib_res["t_phishing"],
        calib_res["t_suspicious"],
        calib_res["ece"],
    )

    # 3. Save full ModelBundle
    import joblib
    base_model = joblib.load(xgb_model_path)
    bundle = ModelBundle(
        model=base_model,
        calibrator=calib_res["calibrator"],
        schema_version="2.0.0-dev",
        model_version="2.0.0",
        training_cutoff=train_report.get("timestamp", ""),
        data_card_version="v2.0",
        t_phishing=calib_res["t_phishing"],
        t_suspicious=calib_res["t_suspicious"],
        metrics={**train_report, "ece": calib_res["ece"]},
    )
    bundle_path = Path(output_dir) / "model_bundle.pkl.gz"
    bundle.save(bundle_path)
    print(f"[SUCCESS] Model bundle saved to {bundle_path}")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    """CLI handler for running gate evaluation."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    bundle_path = args.bundle
    output_dir = args.output_dir

    frozen_sets = {}
    if args.frozen_sets_json:
        with open(args.frozen_sets_json, "r") as f:
            frozen_sets = json.load(f)
    elif args.stubs_dir:
        stubs_p = Path(args.stubs_dir)
        for p in stubs_p.glob("*.parquet"):
            frozen_sets[p.stem] = str(p)

    report = evaluate_gates(
        bundle_path=bundle_path,
        frozen_sets=frozen_sets,
        output_dir=output_dir,
    )

    print(json.dumps(report["GATE_SUMMARY"], indent=2))
    print(f"[INFO] Full evaluation report written to {output_dir}/evaluation_report.json")
    return 0 if report.get("overall_status") == "PASS" else 1


def cmd_predict(args: argparse.Namespace) -> int:
    """
    CLI handler for single URL prediction.
    Outputs JSON result with label, score, mode, and top features.
    """
    bundle_path = args.bundle
    url = args.url
    html = None
    if args.html_file:
        with open(args.html_file, "r", encoding="utf-8", errors="ignore") as f:
            html = f.read()

    bundle = ModelBundle.load(bundle_path)

    # Extract features using FeatureExtractor
    try:
        from ml.v2.features import FeatureExtractor
        extractor = FeatureExtractor()
    except Exception:
        from ml.v2.training.dataset import _MockExtractor
        extractor = _MockExtractor()

    mode = "full" if html else "url-only"
    if hasattr(extractor, "get_mode"):
        mode = extractor.get_mode(html=html)

    try:
        feat_arr = extractor.extract_as_array(url, html=html)
    except TypeError:
        feat_arr = extractor.extract_as_array({"url": url, "html": html})

    feat_matrix = np.asarray(feat_arr, dtype=np.float32).reshape(1, -1)
    score = float(bundle.predict_proba(feat_matrix)[0])
    label = bundle.predict_label(score)

    top_features = []
    feature_names = bundle.features or getattr(extractor, "feature_names", [])
    if hasattr(bundle.model, "feature_importances_"):
        imps = bundle.model.feature_importances_
        sorted_idx = np.argsort(imps)[::-1][:5]
        for idx in sorted_idx:
            fname = feature_names[idx] if idx < len(feature_names) else f"feature_{idx}"
            fval = float(feat_matrix[0, idx]) if idx < feat_matrix.shape[1] else 0.0
            top_features.append({"feature": fname, "value": round(fval, 3), "importance": round(float(imps[idx]), 3)})

    result = {
        "url": url,
        "score": round(score, 4),
        "label": label,
        "mode": mode,
        "thresholds": {
            "t_phishing": bundle.t_phishing,
            "t_suspicious": bundle.t_suspicious,
        },
        "top_features": top_features,
    }

    print(json.dumps(result, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="FihhGuard v2 ML CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # train
    p_train = subparsers.add_parser("train", help="Train model bundle")
    p_train.add_argument("--train-parquets", nargs="+", required=True)
    p_train.add_argument("--val-parquets", nargs="+", required=True)
    p_train.add_argument("--schema", default=None)
    p_train.add_argument("--output-dir", default="ml/artifacts")
    p_train.add_argument("--n-iter", type=int, default=50)
    p_train.add_argument("--seed", type=int, default=42)
    p_train.add_argument("--realistic-prior", type=float, default=0.005)
    p_train.set_defaults(func=cmd_train)

    # evaluate
    p_eval = subparsers.add_parser("evaluate", help="Evaluate model against gates")
    p_eval.add_argument("--bundle", required=True)
    p_eval.add_argument("--frozen-sets-json", default=None)
    p_eval.add_argument("--stubs-dir", default=None)
    p_eval.add_argument("--output-dir", default="ml/reports")
    p_eval.set_defaults(func=cmd_evaluate)

    # predict
    p_pred = subparsers.add_parser("predict", help="Predict phishing score for a URL")
    p_pred.add_argument("--bundle", required=True)
    p_pred.add_argument("--url", required=True)
    p_pred.add_argument("--html-file", default=None)
    p_pred.set_defaults(func=cmd_predict)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


def fihhguard_train() -> None:
    parser = build_parser()
    args = parser.parse_args(["train"] + sys.argv[1:])
    sys.exit(cmd_train(args))


def fihhguard_evaluate() -> None:
    parser = build_parser()
    args = parser.parse_args(["evaluate"] + sys.argv[1:])
    sys.exit(cmd_evaluate(args))


def fihhguard_predict() -> None:
    parser = build_parser()
    args = parser.parse_args(["predict"] + sys.argv[1:])
    sys.exit(cmd_predict(args))


if __name__ == "__main__":
    main()
