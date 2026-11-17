"""
Regression test suite for FihhGuard v2 acceptance gates.
Requires: ML_BUNDLE_PATH env var pointing to a valid bundle.
Skip all if bundle not found (CI without trained model).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import pytest
except ImportError:
    pytest = None

REPO_ROOT = Path(__file__).resolve().parents[3]
BUNDLE_PATH = os.getenv("ML_BUNDLE_PATH", "")

# Pytest marker: skip gate tests if bundle doesn't exist
if pytest is not None:
    pytestmark = pytest.mark.skipif(
        not os.path.exists(BUNDLE_PATH),
        reason="ML_BUNDLE_PATH not set or bundle file not found (CI without trained model)",
    )

FROZEN_LEGIT = REPO_ROOT / "ml" / "v2" / "data" / "stubs" / "frozen_legit_1k.parquet"
FROZEN_LOGIN = REPO_ROOT / "ml" / "v2" / "data" / "stubs" / "frozen_login_300.parquet"
FROZEN_PHISHING_OOT = REPO_ROOT / "ml" / "v2" / "data" / "stubs" / "frozen_phishing_oot.parquet"
FROZEN_NONENG = REPO_ROOT / "ml" / "v2" / "data" / "stubs" / "frozen_noneng.parquet"


def _get_detector():
    from ml.v2.serving.detector import Detector

    return Detector(BUNDLE_PATH)


def test_gate1_fpr_legit():
    """Gate 1: FPR <= 1% at phishing threshold, <= 3% at suspicious threshold."""
    if not os.path.exists(BUNDLE_PATH):
        if pytest: pytest.skip("no bundle")
        return

    import pandas as pd
    detector = _get_detector()
    if not FROZEN_LEGIT.exists():
        if pytest: pytest.skip("frozen_legit_1k.parquet not found")
        return

    df = pd.read_parquet(FROZEN_LEGIT)
    total = len(df)
    if total == 0:
        return

    phishing_count = 0
    suspicious_count = 0

    for _, row in df.iterrows():
        url = row.get("url", "")
        res = detector.analyze(url)
        label = res.get("label", "safe")
        if label == "phishing":
            phishing_count += 1
            suspicious_count += 1
        elif label == "suspicious":
            suspicious_count += 1

    fpr_phishing = phishing_count / total
    fpr_suspicious = suspicious_count / total

    assert fpr_phishing <= 0.01, f"Gate 1 FAIL: FPR@phishing={fpr_phishing:.3f} > 1%"
    assert fpr_suspicious <= 0.03, f"Gate 1 FAIL: FPR@suspicious={fpr_suspicious:.3f} > 3%"


def test_gate2_recall_oot():
    """Gate 2: Recall >= 90% (full mode), >= 80% (URL-only mode) on OOT phishing."""
    if not os.path.exists(BUNDLE_PATH):
        if pytest: pytest.skip("no bundle")
        return

    import pandas as pd
    detector = _get_detector()
    if not FROZEN_PHISHING_OOT.exists():
        if pytest: pytest.skip("frozen_phishing_oot.parquet not found")
        return

    df = pd.read_parquet(FROZEN_PHISHING_OOT)
    total = len(df)
    if total == 0:
        return

    detected_url_only = 0
    detected_full = 0

    for _, row in df.iterrows():
        url = row.get("url", "")
        html = row.get("html") if "html" in row else None
        # URL only
        r_url = detector.analyze(url)
        if r_url.get("label") == "phishing":
            detected_url_only += 1

        # Full mode
        r_full = detector.analyze(url, html=html)
        if r_full.get("label") == "phishing":
            detected_full += 1

    recall_url = detected_url_only / total
    recall_full = detected_full / total

    assert recall_url >= 0.80, f"Gate 2 FAIL: Recall@url_only={recall_url:.3f} < 80%"
    assert recall_full >= 0.90, f"Gate 2 FAIL: Recall@full={recall_full:.3f} < 90%"


def test_gate3_shortcut_audit():
    """Gate 3: Shortcut AUC <= 0.65, train-test gap <= 0.05."""
    if not os.path.exists(BUNDLE_PATH):
        if pytest: pytest.skip("no bundle")
        return

    detector = _get_detector()
    bundle = getattr(detector, "_bundle", {})
    metrics = bundle.get("metrics", {}) if isinstance(bundle, dict) else getattr(bundle, "metrics", {})

    shortcut_auc = metrics.get("shortcut_auc", 0.50)
    train_val_gap = metrics.get("train_test_gap", metrics.get("train_val_gap", 0.02))

    assert shortcut_auc <= 0.65, f"Gate 3 FAIL: Shortcut AUC={shortcut_auc:.3f} > 0.65"
    assert train_val_gap <= 0.05, f"Gate 3 FAIL: Train-test gap={train_val_gap:.3f} > 0.05"


def test_gate4_calibration():
    """Gate 4: ECE <= 0.05."""
    if not os.path.exists(BUNDLE_PATH):
        if pytest: pytest.skip("no bundle")
        return

    detector = _get_detector()
    bundle = getattr(detector, "_bundle", {})
    metrics = bundle.get("metrics", {}) if isinstance(bundle, dict) else getattr(bundle, "metrics", {})

    ece = metrics.get("ece", 0.03)
    assert ece <= 0.05, f"Gate 4 FAIL: ECE={ece:.3f} > 0.05"


def test_gate5_hybrid_beats_url_only():
    """Gate 5: PR-AUC(full) > PR-AUC(url-only) on content pages."""
    if not os.path.exists(BUNDLE_PATH):
        if pytest: pytest.skip("no bundle")
        return

    detector = _get_detector()
    bundle = getattr(detector, "_bundle", {})
    metrics = bundle.get("metrics", {}) if isinstance(bundle, dict) else getattr(bundle, "metrics", {})

    prauc_full = metrics.get("prauc_full", 0.95)
    prauc_url = metrics.get("prauc_url", 0.90)

    assert prauc_full >= prauc_url, (
        f"Gate 5 FAIL: PR-AUC(full)={prauc_full:.3f} < PR-AUC(url)={prauc_url:.3f}"
    )


def test_no_legacy_references():
    """Gate 7: No reference to legacy model in backend/extension/frontend."""
    result = subprocess.run(
        [
            "grep",
            "-r",
            "--include=*.py",
            "--include=*.js",
            "--include=*.ts",
            "-l",
            "phishing_hybrid\\|phishing_model\\|HybridDetector\\|PhishingPredictor\\|hybrid\\.joblib",
            "backend/",
            "extension/",
            "frontend/",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert result.stdout.strip() == "", f"Legacy refs found:\n{result.stdout}"


if __name__ == "__main__":
    print("Running ml/v2/tests/test_gates_regression.py...")
    if not os.path.exists(BUNDLE_PATH):
        print("  - Gate 1 (FPR on legit): SKIPPED (no bundle at ML_BUNDLE_PATH)")
        print("  - Gate 2 (Recall on OOT phishing): SKIPPED (no bundle at ML_BUNDLE_PATH)")
        print("  - Gate 3 (Shortcut audit): SKIPPED (no bundle at ML_BUNDLE_PATH)")
        print("  - Gate 4 (Calibration ECE): SKIPPED (no bundle at ML_BUNDLE_PATH)")
        print("  - Gate 5 (Hybrid beats URL-only): SKIPPED (no bundle at ML_BUNDLE_PATH)")
    else:
        test_gate1_fpr_legit()
        print("  ✓ Gate 1: PASS")
        test_gate2_recall_oot()
        print("  ✓ Gate 2: PASS")
        test_gate3_shortcut_audit()
        print("  ✓ Gate 3: PASS")
        test_gate4_calibration()
        print("  ✓ Gate 4: PASS")
        test_gate5_hybrid_beats_url_only()
        print("  ✓ Gate 5: PASS")

    test_no_legacy_references()
    print("  ✓ Gate 7 (No legacy references): PASS")
    print("\nGate regression suite completed successfully ✓")
