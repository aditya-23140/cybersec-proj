"""
ml/v2/tests/conftest.py — Shared fixtures for v2 regression test suite.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

# Optional imports handled gracefully
try:
    import pytest
except ImportError:
    pytest = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_PATH = os.getenv("ML_BUNDLE_PATH", "")

FROZEN_LEGIT_PATH = REPO_ROOT / "ml" / "v2" / "data" / "stubs" / "frozen_legit_1k.parquet"
FROZEN_LOGIN_PATH = REPO_ROOT / "ml" / "v2" / "data" / "stubs" / "frozen_login_300.parquet"
FROZEN_PHISHING_OOT_PATH = REPO_ROOT / "ml" / "v2" / "data" / "stubs" / "frozen_phishing_oot.parquet"
FROZEN_NONENG_PATH = REPO_ROOT / "ml" / "v2" / "data" / "stubs" / "frozen_noneng.parquet"


def _pytest_fixture(func):
    """Fixture decorator that is a no-op if pytest is not installed."""
    if pytest is not None:
        return pytest.fixture(scope="session")(func)
    return func


@_pytest_fixture
def bundle_path_fixture() -> str:
    return BUNDLE_PATH


@_pytest_fixture
def detector_fixture():
    """Loads Detector from BUNDLE_PATH if bundle exists."""
    if not BUNDLE_PATH or not Path(BUNDLE_PATH).exists():
        if pytest is not None:
            pytest.skip("ML_BUNDLE_PATH not set or file not found")
        return None

    from ml.v2.serving.detector import Detector

    return Detector(BUNDLE_PATH)


def _load_parquet_safe(p: Path):
    if not p.exists():
        return None
    try:
        import pandas as pd
        return pd.read_parquet(p)
    except Exception:
        return None


@_pytest_fixture
def frozen_legit_df():
    return _load_parquet_safe(FROZEN_LEGIT_PATH)


@_pytest_fixture
def frozen_login_df():
    return _load_parquet_safe(FROZEN_LOGIN_PATH)


@_pytest_fixture
def frozen_phishing_oot_df():
    return _load_parquet_safe(FROZEN_PHISHING_OOT_PATH)


@_pytest_fixture
def frozen_noneng_df():
    return _load_parquet_safe(FROZEN_NONENG_PATH)
