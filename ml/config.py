"""
ml/config.py — All configurable constants for the ML pipeline.
Change here; do not scatter magic numbers elsewhere.
"""

import os

# ── Paths ──────────────────────────────────────────────────────────────────
DATA_DIR: str = os.getenv("ML_DATA_DIR", "data")
ARTIFACTS_DIR: str = os.getenv("ML_ARTIFACTS_DIR", "artifacts")
REPORTS_DIR: str = os.getenv("ML_REPORTS_DIR", "reports")

# ── Dataset ────────────────────────────────────────────────────────────────
PHIUSIIL_URL: str = (
    "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
)
DOWNLOAD_TIMEOUT: int = int(os.getenv("ML_DOWNLOAD_TIMEOUT", "60"))

# ── Reproducibility ────────────────────────────────────────────────────────
RANDOM_SEED: int = 42

# ── Train / val / test split fractions ────────────────────────────────────
TEST_SIZE: float = 0.15
VAL_SIZE: float = 0.15

# ── Model ──────────────────────────────────────────────────────────────────
MODEL_VERSION: str = "1.0.0"

# ── Hyperparameter grid ────────────────────────────────────────────────────
# Small grid to finish within the deadline; extend if time permits.
PARAM_GRID: dict = {
    "max_depth": [3, 5],
    "n_estimators": [100, 200],
    "learning_rate": [0.05, 0.1],
}

# ── Default thresholds (overridden by val-set selection at training time) ──
DEFAULT_SUSPICIOUS_THRESHOLD: float = 0.30
DEFAULT_DANGEROUS_THRESHOLD: float = 0.70
