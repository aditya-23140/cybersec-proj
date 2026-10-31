"""
tests/test_training.py — Tests for model_registry and artifact save/load.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pytest


def test_feature_schema_round_trip():
    """Save and reload a feature schema; verify contents."""
    from src.feature_extractor import FEATURE_NAMES
    from src.model_registry import load_feature_schema, save_feature_schema

    with tempfile.TemporaryDirectory() as tmpdir:
        fallbacks = {
            "qty_nameservers": 2.5,
            "is_spf_domain": 0.0,
            "time_domain_activation": -1.0,
        }
        save_feature_schema(tmpdir, FEATURE_NAMES, fallbacks, median_nameservers=2.5)
        schema = load_feature_schema(tmpdir)

        assert schema["feature_names"] == FEATURE_NAMES
        assert schema["feature_count"] == len(FEATURE_NAMES)
        assert schema["fallback_values"]["qty_nameservers"] == 2.5


def test_threshold_config_round_trip():
    from src.model_registry import load_threshold_config, save_threshold_config

    with tempfile.TemporaryDirectory() as tmpdir:
        val_metrics = {"f1": 0.85, "accuracy": 0.88}
        save_threshold_config(
            tmpdir,
            suspicious_threshold=0.3,
            dangerous_threshold=0.7,
            optimal_f1_threshold=0.45,
            val_metrics=val_metrics,
        )
        cfg = load_threshold_config(tmpdir)

        assert cfg["suspicious_threshold"] == 0.3
        assert cfg["dangerous_threshold"] == 0.7
        assert cfg["optimal_f1_threshold"] == 0.45


def test_metadata_round_trip():
    from src.model_registry import load_metadata, save_metadata

    with tempfile.TemporaryDirectory() as tmpdir:
        save_metadata(
            tmpdir,
            model_version="1.0.0",
            dataset_info={"n_total": 1000, "is_synthetic": True},
            best_hyperparams={"max_depth": 5, "n_estimators": 100},
            training_duration_seconds=42.0,
            is_synthetic=True,
        )
        meta = load_metadata(tmpdir)
        assert meta["model_version"] == "1.0.0"
        assert meta["is_synthetic_data"] is True


def test_missing_artifacts_raise_clearly():
    """Missing artifact files should raise FileNotFoundError, not AttributeError."""
    from src.model_registry import load_feature_schema, load_model, load_threshold_config

    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(FileNotFoundError):
            load_model(tmpdir)
        with pytest.raises(FileNotFoundError):
            load_feature_schema(tmpdir)
        with pytest.raises(FileNotFoundError):
            load_threshold_config(tmpdir)


def test_xgboost_small_training_cycle():
    """
    End-to-end mini training: fit XGBoost on 100 rows, save, reload, predict.
    Checks the full artifact save/load cycle without requiring real data.
    """
    pytest.importorskip("xgboost")
    from xgboost import XGBClassifier
    from src.model_registry import load_model, save_model

    rng = np.random.default_rng(42)
    X = rng.random((100, 8)).astype(np.float32)
    y = rng.integers(0, 2, 100)

    model = XGBClassifier(n_estimators=10, max_depth=3, random_state=42, verbosity=0)
    model.fit(X, y)

    with tempfile.TemporaryDirectory() as tmpdir:
        save_model(model, tmpdir)
        loaded = load_model(tmpdir)
        preds = loaded.predict_proba(X[:5])
        assert preds.shape == (5, 2)
        assert all(0.0 <= p <= 1.0 for p in preds[:, 1])
