"""
test_bundle.py — Tests for ModelBundle lifecycle, schema protection, and end-to-end smoke test.
"""

from pathlib import Path
import json
import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression

from ml.v2.training.bundle import ModelBundle
from ml.v2.training.calibrate import calibrate
from ml.v2.training.evaluate import evaluate_gates
from ml.v2.training.train import train

_REPO_ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture
def dummy_bundle() -> ModelBundle:
    """Creates a simple trained LogisticRegression ModelBundle."""
    X = np.array([[1.0, 0.0], [0.0, 1.0], [2.0, 1.0], [0.5, 2.0]], dtype=np.float32)
    y = np.array([0, 1, 0, 1], dtype=np.int32)
    model = LogisticRegression().fit(X, y)

    bundle = ModelBundle(
        model=model,
        schema_version="2.0.0-dev",
        model_version="2.0.0",
        training_cutoff="2024-01-01T00:00:00Z",
        data_card_version="v2.0",
        t_phishing=0.80,
        t_suspicious=0.40,
        features=["feat_a", "feat_b"],
        metrics={"prauc": 0.95},
    )
    return bundle


def test_bundle_save_load_roundtrip(dummy_bundle: ModelBundle, tmp_path: Path):
    """Assert bundle saves to .pkl.gz and loads back with all properties intact."""
    bundle_path = tmp_path / "test_model_bundle.pkl.gz"
    dummy_bundle.save(bundle_path)

    assert bundle_path.exists()
    loaded = ModelBundle.load(bundle_path)

    assert loaded.schema_version == dummy_bundle.schema_version
    assert loaded.model_version == dummy_bundle.model_version
    assert loaded.t_phishing == dummy_bundle.t_phishing
    assert loaded.t_suspicious == dummy_bundle.t_suspicious
    assert loaded.features == dummy_bundle.features
    assert loaded.metrics == dummy_bundle.metrics

    # Test prediction equivalence
    test_X = np.array([[1.0, 0.5]], dtype=np.float32)
    p_orig = dummy_bundle.predict_proba(test_X)
    p_loaded = loaded.predict_proba(test_X)
    np.testing.assert_allclose(p_orig, p_loaded, rtol=1e-5)


def test_schema_version_mismatch(dummy_bundle: ModelBundle, tmp_path: Path):
    """Assert schema version mismatch raises ValueError."""
    bundle_path = tmp_path / "bundle_mismatch.pkl.gz"
    dummy_bundle.save(bundle_path)

    # Correct schema should not raise
    ModelBundle.load(bundle_path, expected_schema_version="2.0.0-dev")

    # Mismatched schema must raise ValueError
    with pytest.raises(ValueError, match="Schema version mismatch"):
        ModelBundle.load(bundle_path, expected_schema_version="3.0.0-incompatible")


def test_predict_label(dummy_bundle: ModelBundle):
    """Assert predict_label returns correct string for scores 0.1, 0.5, 0.9."""
    assert dummy_bundle.predict_label(0.1) == "safe"
    assert dummy_bundle.predict_label(0.5) == "suspicious"
    assert dummy_bundle.predict_label(0.9) == "phishing"


def test_e2e_smoke(tmp_path: Path):
    """
    End-to-end smoke test:
    Trains on tiny stub data, calibrates, saves bundle, and runs gate evaluation.
    Asserts the pipeline runs without crashing and produces a valid evaluation_report.json.
    """
    stubs_dir = _REPO_ROOT / "ml" / "v2" / "data" / "stubs"
    if not stubs_dir.exists():
        stubs_dir = Path("ml/v2/data/stubs")

    train_parquet = str(stubs_dir / "phreshphish_train.parquet")
    val_parquet = str(stubs_dir / "phreshphish_val.parquet")
    test_parquet = str(stubs_dir / "phreshphish_test.parquet")

    # If stubs not present, create a synthetic mini-parquet
    if not Path(train_parquet).exists():
        import pandas as pd
        mini_df = pd.DataFrame({
            "url": ["https://a.com", "https://b.com", "https://c.org", "https://d.xyz"],
            "label": [0, 1, 0, 1],
            "registered_domain": ["a.com", "b.com", "c.org", "d.xyz"],
            "source": ["phreshphish", "phreshphish", "phreshphish", "phreshphish"],
            "collected_at": ["2024-01-01", "2024-01-02", "2024-01-03", "2024-01-04"],
        })
        train_parquet = str(tmp_path / "train.parquet")
        val_parquet = str(tmp_path / "val.parquet")
        test_parquet = str(tmp_path / "test.parquet")
        mini_df.to_parquet(train_parquet, index=False)
        mini_df.to_parquet(val_parquet, index=False)
        mini_df.to_parquet(test_parquet, index=False)

    out_dir = tmp_path / "artifacts"
    out_dir.mkdir(parents=True, exist_ok=True)

    train_report = train(
        train_parquets=[train_parquet],
        val_parquets=[val_parquet],
        output_dir=str(out_dir),
        n_iter=5,
        seed=42,
    )
    assert "val_prauc" in train_report
    assert (out_dir / "xgboost_model.joblib").exists()

    calib_res = calibrate(
        model_or_path=out_dir / "xgboost_model.joblib",
        val_parquets=[val_parquet],
        output_path=str(out_dir / "calibration.joblib"),
    )
    assert "t_phishing" in calib_res
    assert "t_suspicious" in calib_res

    import joblib
    model = joblib.load(out_dir / "xgboost_model.joblib")
    bundle = ModelBundle(
        model=model,
        calibrator=calib_res["calibrator"],
        schema_version="2.0.0-dev",
        model_version="2.0.0",
        t_phishing=calib_res["t_phishing"],
        t_suspicious=calib_res["t_suspicious"],
        features=[f"feat_{i}" for i in range(67)],
        metrics=train_report,
    )
    bundle_path = out_dir / "model_bundle.pkl.gz"
    bundle.save(bundle_path)
    assert bundle_path.exists()

    report_dir = tmp_path / "reports"
    frozen_sets = {
        "phreshphish_val": val_parquet,
        "phreshphish_test": test_parquet,
    }
    legit_p = stubs_dir / "frozen_legit_1k.parquet"
    if legit_p.exists():
        frozen_sets["frozen_legit_1k"] = str(legit_p)
    oot_p = stubs_dir / "frozen_phishing_oot.parquet"
    if oot_p.exists():
        frozen_sets["frozen_phishing_oot"] = str(oot_p)

    eval_report = evaluate_gates(
        bundle_path=bundle_path,
        frozen_sets=frozen_sets,
        output_dir=str(report_dir),
    )

    report_json_path = report_dir / "evaluation_report.json"
    assert report_json_path.exists()

    with open(report_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "GATE_SUMMARY" in data
    for gate_key in ["gate_1", "gate_2", "gate_3", "gate_4", "gate_5"]:
        assert gate_key in data["GATE_SUMMARY"]
        assert "status" in data["GATE_SUMMARY"][gate_key]
        assert data["GATE_SUMMARY"][gate_key]["status"] in ("PASS", "FAIL")
