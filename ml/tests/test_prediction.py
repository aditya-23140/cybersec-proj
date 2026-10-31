"""
tests/test_prediction.py — Tests for the inference module (predict.py).
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pytest


def _make_trained_artifacts(tmpdir: str) -> None:
    """Create real trained artifacts in tmpdir using synthetic data."""
    from xgboost import XGBClassifier
    from src.feature_extractor import FEATURE_NAMES
    from src.model_registry import (
        save_feature_schema,
        save_metadata,
        save_model,
        save_threshold_config,
    )

    rng = np.random.default_rng(42)
    X = rng.random((200, len(FEATURE_NAMES))).astype(np.float32)
    y = rng.integers(0, 2, 200)

    model = XGBClassifier(n_estimators=10, max_depth=3, random_state=42, verbosity=0)
    model.fit(X, y)

    save_model(model, tmpdir)
    save_feature_schema(
        tmpdir,
        FEATURE_NAMES,
        {"qty_nameservers": 2.0, "is_spf_domain": 0.0, "time_domain_activation": -1.0},
        median_nameservers=2.0,
    )
    save_threshold_config(
        tmpdir,
        suspicious_threshold=0.3,
        dangerous_threshold=0.7,
        optimal_f1_threshold=0.5,
        val_metrics={},
    )
    save_metadata(
        tmpdir,
        model_version="test-1.0",
        dataset_info={},
        best_hyperparams={},
        training_duration_seconds=1.0,
        is_synthetic=True,
    )


@pytest.fixture(scope="module")
def predictor():
    pytest.importorskip("xgboost")
    from src.predict import PhishingPredictor

    with tempfile.TemporaryDirectory() as tmpdir:
        _make_trained_artifacts(tmpdir)
        yield PhishingPredictor(artifacts_dir=tmpdir, enable_dns=False)


def test_predict_returns_correct_keys(predictor):
    result = predictor.predict("https://example.com")
    required_keys = {
        "request_id", "url", "prediction", "risk_level",
        "phishing_probability", "model_version", "warnings", "explanation",
    }
    assert required_keys.issubset(result.keys())


def test_predict_probability_in_range(predictor):
    result = predictor.predict("https://example.com")
    assert 0.0 <= result["phishing_probability"] <= 1.0


def test_predict_valid_prediction_values(predictor):
    result = predictor.predict("https://example.com")
    assert result["prediction"] in ("phishing", "benign")


def test_predict_valid_risk_level(predictor):
    result = predictor.predict("https://example.com")
    assert result["risk_level"] in ("safe", "suspicious", "dangerous")


def test_predict_request_id_unique(predictor):
    r1 = predictor.predict("https://example.com")
    r2 = predictor.predict("https://example.com")
    assert r1["request_id"] != r2["request_id"]


def test_predict_url_preserved(predictor):
    url = "https://example.com/path?q=test"
    result = predictor.predict(url)
    assert result["url"] == url


def test_predict_invalid_scheme_raises(predictor):
    with pytest.raises(ValueError):
        predictor.predict("javascript:alert(1)")


def test_predict_empty_url_raises(predictor):
    with pytest.raises(ValueError):
        predictor.predict("")


def test_predict_high_risk_url_flags_brand(predictor):
    """A URL with a brand keyword should at least not crash."""
    result = predictor.predict("http://paypal-verify-secure.xyz/login")
    assert "phishing_probability" in result


def test_missing_artifacts_raises_file_error():
    pytest.importorskip("xgboost")
    from src.predict import PhishingPredictor

    with tempfile.TemporaryDirectory() as empty_dir:
        with pytest.raises(FileNotFoundError):
            PhishingPredictor(artifacts_dir=empty_dir)


def test_explanation_contains_disclaimer(predictor):
    result = predictor.predict("https://example.com")
    assert "statistical assessment" in result["explanation"].lower()


def test_explanation_describes_probability_and_features(predictor):
    result = predictor.predict("https://paypal-verify-secure.example.com/login")
    explanation = result["explanation"].lower()
    assert "probability" in explanation
    assert "indicator" in explanation or "features" in explanation
    assert "statistical assessment" in explanation
