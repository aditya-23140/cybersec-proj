"""
services/predictor.py — Loads PhishingPredictor from ml/src/predict.py.

The ML model may not be available at dev/test time.  When the artefacts
directory is missing or the import fails, the predictor is set to None
and all endpoints return 503 MODEL_UNAVAILABLE rather than crashing.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import config

logger = logging.getLogger(__name__)

# Module-level state -------------------------------------------------------- #
_predictor: Any = None          # PhishingPredictor instance or None
_threshold_config: dict | None = None
_model_loaded: bool = False


def load_predictor() -> None:
    """
    Attempt to import and initialise PhishingPredictor.
    Called once from the FastAPI lifespan hook.
    On any failure the predictor stays None (503 returned to callers).
    """
    global _predictor, _threshold_config, _model_loaded

    artifacts_dir = Path(config.ML_ARTIFACTS_DIR).resolve()
    ml_root = artifacts_dir.parent  # …/ml/

    # ------------------------------------------------------------------ #
    # Load threshold config (optional — used by risk_policy)
    # ------------------------------------------------------------------ #
    threshold_path = artifacts_dir / "threshold_config.json"
    if threshold_path.exists():
        try:
            with threshold_path.open() as fh:
                _threshold_config = json.load(fh)
            logger.info("Loaded threshold_config.json")
        except Exception as exc:
            logger.warning("Could not read threshold_config.json: %s", exc)

    # ------------------------------------------------------------------ #
    # Import PhishingPredictor
    # ------------------------------------------------------------------ #
    if not artifacts_dir.exists():
        logger.warning(
            "ML artifacts directory not found: %s — model will be unavailable.",
            artifacts_dir,
        )
        return

    ml_root_str = str(ml_root)
    if ml_root_str not in sys.path:
        sys.path.insert(0, ml_root_str)

    try:
        from src.predict import PhishingPredictor  # type: ignore[import]

        _predictor = PhishingPredictor(artifacts_dir=str(artifacts_dir))
        _model_loaded = True
        logger.info("PhishingPredictor loaded successfully from %s", artifacts_dir)
    except ModuleNotFoundError as exc:
        logger.warning("ml.src.predict not found (%s) — model unavailable.", exc)
    except Exception as exc:
        logger.error("Failed to load PhishingPredictor: %s", exc, exc_info=True)


# --------------------------------------------------------------------------- #
# Public accessors
# --------------------------------------------------------------------------- #

def is_model_loaded() -> bool:
    return _model_loaded


def get_predictor() -> Any:
    return _predictor


def get_threshold_config() -> dict | None:
    return _threshold_config


def predict(url: str) -> dict[str, Any]:
    """
    Run inference on *url*.

    Returns a dict with at minimum:
        prediction           : str  ("benign" | "phishing")
        phishing_probability : float [0, 1]

    Raises:
        RuntimeError if the model is not loaded.
    """
    if not _model_loaded or _predictor is None:
        raise RuntimeError("Model is not loaded")

    result = _predictor.predict(url)

    # Normalise the result dict so downstream code can rely on consistent keys
    if isinstance(result, dict):
        return result

    # Some predictor implementations return a tuple (label, prob)
    if isinstance(result, (list, tuple)) and len(result) >= 2:
        return {"prediction": result[0], "phishing_probability": float(result[1])}

    raise ValueError(f"Unexpected predictor output type: {type(result)}")
