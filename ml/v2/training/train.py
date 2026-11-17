"""
train.py — Train XGBoost model and LogisticRegression baseline with hyperparameter search.
"""

from __future__ import annotations

import datetime
import json
import logging
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import GroupKFold, KFold, RandomizedSearchCV
from scipy.stats import uniform, randint

try:
    import xgboost as xgb
    _HAS_XGB = True
except ImportError:
    xgb = None  # type: ignore
    _HAS_XGB = False

from ml.v2.training.dataset import PhishDataset

logger = logging.getLogger(__name__)


def train(
    train_parquets: list[str],
    val_parquets: list[str],
    schema_path: Optional[str] = None,
    *,
    output_dir: str = "ml/artifacts",
    n_iter: int = 50,
    seed: int = 42,
) -> dict[str, Any]:
    """
    Main model training routine.

    Trains:
    1. XGBoost with RandomizedSearchCV (GroupKFold by registered_domain, PR-AUC scoring)
    2. LogisticRegression baseline (C in [0.01, 0.1, 1, 10])

    Saves:
    - xgboost_model.joblib
    - logistic_regression_baseline.joblib
    - training_report.json
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load datasets
    train_ds = PhishDataset(train_parquets, extractor=schema_path)
    X_train_raw, y_train, train_meta = train_ds.load()

    val_ds = PhishDataset(val_parquets, extractor=schema_path)
    X_val, y_val, val_meta = val_ds.load()

    if len(y_train) == 0 or len(y_val) == 0:
        raise ValueError("Train or val dataset is empty")

    # 2. Feature-group dropout during training (p=0.3)
    X_train = train_ds.apply_feature_group_dropout(
        X_train_raw,
        groups=["page_content", "reputation", "redirect"],
        drop_prob=0.3,
        seed=seed,
    )

    feature_names = train_ds.feature_names
    feature_count = len(feature_names)

    # 3. Setup Cross-Validation
    domains = train_meta.get("registered_domain", train_meta.get("url", np.arange(len(y_train))))
    unique_domains = np.unique(domains)
    n_groups = len(unique_domains)
    n_splits = min(5, n_groups)

    if n_splits >= 2:
        cv = GroupKFold(n_splits=n_splits)
        cv_groups = domains
    else:
        cv = KFold(n_splits=min(3, len(y_train)), shuffle=True, random_state=seed)
        cv_groups = None

    # 4. Train XGBoost
    best_xgb = None
    best_xgb_params = {}
    if _HAS_XGB and xgb is not None:
        param_dist = {
            "max_depth": randint(2, 7),               # [2, 6]
            "n_estimators": randint(100, 501),        # [100, 500]
            "learning_rate": uniform(0.01, 0.29),     # [0.01, 0.30]
            "subsample": uniform(0.6, 0.4),           # [0.6, 1.0]
            "colsample_bytree": uniform(0.5, 0.5),    # [0.5, 1.0]
            "min_child_weight": randint(1, 21),       # [1, 20]
            "reg_alpha": uniform(0.0, 2.0),           # [0.0, 2.0]
            "reg_lambda": uniform(0.0, 2.0),          # [0.0, 2.0]
        }
        base_xgb = xgb.XGBClassifier(
            objective="binary:logistic",
            eval_metric="logloss",
            random_state=seed,
            n_jobs=1,  # Keep single thread per fit for stable parallel CV
        )
        # Cap iterations if small dataset to keep tests and fast runs responsive
        actual_iter = min(n_iter, 50)
        search = RandomizedSearchCV(
            base_xgb,
            param_distributions=param_dist,
            n_iter=actual_iter,
            scoring="average_precision",
            cv=cv,
            random_state=seed,
            n_jobs=-1,
            refit=True,
            error_score="raise",
        )
        search.fit(X_train, y_train, groups=cv_groups)
        best_xgb = search.best_estimator_
        best_xgb_params = {
            k: (float(v) if isinstance(v, (np.floating, float)) else int(v) if isinstance(v, (np.integer, int)) else v)
            for k, v in search.best_params_.items()
        }
    else:
        logger.warning("XGBoost not available; using GradientBoostingClassifier fallback")
        from sklearn.ensemble import GradientBoostingClassifier
        best_xgb = GradientBoostingClassifier(random_state=seed)
        best_xgb.fit(X_train, y_train)

    # 5. Train Logistic Regression baseline
    lr_c_candidates = [0.01, 0.1, 1.0, 10.0]
    best_lr = None
    best_lr_score = -1.0
    for c_val in lr_c_candidates:
        lr_model = LogisticRegression(C=c_val, max_iter=1000, random_state=seed)
        lr_model.fit(X_train, y_train)
        lr_val_preds = lr_model.predict_proba(X_val)[:, 1]
        score = average_precision_score(y_val, lr_val_preds) if len(np.unique(y_val)) > 1 else 0.5
        if score > best_lr_score:
            best_lr_score = score
            best_lr = lr_model

    # 6. Evaluation metrics on train and val
    def _get_metrics(model: Any) -> tuple[float, float, float]:
        val_probs = model.predict_proba(X_val)[:, 1]
        train_probs = model.predict_proba(X_train)[:, 1]

        val_prauc = float(average_precision_score(y_val, val_probs)) if len(np.unique(y_val)) > 1 else 0.5
        val_rocauc = float(roc_auc_score(y_val, val_probs)) if len(np.unique(y_val)) > 1 else 0.5
        train_rocauc = float(roc_auc_score(y_train, train_probs)) if len(np.unique(y_train)) > 1 else 0.5
        return val_prauc, val_rocauc, train_rocauc

    val_prauc, val_rocauc, train_rocauc = _get_metrics(best_xgb)
    auc_gap = float(train_rocauc - val_rocauc)
    overfitting_flag = bool(auc_gap > 0.05)

    if overfitting_flag:
        logger.warning(
            "OVERFITTING WARNING: Train ROC-AUC (%.4f) - Val ROC-AUC (%.4f) = %.4f (> 0.05)",
            train_rocauc, val_rocauc, auc_gap,
        )

    lr_val_prauc, lr_val_rocauc, lr_train_rocauc = _get_metrics(best_lr)

    # 7. Save model artifacts
    xgb_path = out_dir / "xgboost_model.joblib"
    lr_path = out_dir / "logistic_regression_baseline.joblib"
    joblib.dump(best_xgb, xgb_path)
    joblib.dump(best_lr, lr_path)

    # 8. Training report
    report = {
        "model": "xgboost",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "val_prauc": round(val_prauc, 5),
        "val_rocauc": round(val_rocauc, 5),
        "train_rocauc": round(train_rocauc, 5),
        "gap": round(auc_gap, 5),
        "overfitting_flag": overfitting_flag,
        "n_train": int(len(y_train)),
        "n_val": int(len(y_val)),
        "feature_count": int(feature_count),
        "hyperparams": best_xgb_params,
        "baseline_logistic_regression": {
            "val_prauc": round(lr_val_prauc, 5),
            "val_rocauc": round(lr_val_rocauc, 5),
            "train_rocauc": round(lr_train_rocauc, 5),
            "gap": round(lr_train_rocauc - lr_val_rocauc, 5),
        },
    }

    report_path = out_dir / "training_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info("Saved training report to %s", report_path)
    return report
