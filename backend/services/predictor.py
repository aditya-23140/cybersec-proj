"""
services/predictor.py — FihhGuard v2 Detector integration.

Layer order (spec-mandated, enforced by Detector):
  1. Threat-intel lookup
  2. Top-10k allowlist (exact registered domain)
  3. Model (FeatureExtractor + ModelBundle)

If the bundle does not exist or fails to load:
  - is_model_loaded() returns False
  - predict() raises RuntimeError with an exact reason string
  - /predict returns 503 MODEL_UNAVAILABLE with that reason
  - blocklist/allowlist layers (in risk_policy) continue to work

ALLOW_UNGATED_MODEL=true (env) loads a bundle that has not passed all gates;
every response will carry model_status="experimental".
"""

from __future__ import annotations

import logging
import sys
import traceback
from pathlib import Path
from typing import Any

import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Ensure repo root and packages on sys.path so `ml.v2.*` is importable
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_CANDIDATE_PKGS = [
    _REPO_ROOT / ".pkgs",
    Path("/home/immortal_soul/.gemini/antigravity-cli/worktrees/93ae7424-d27f-48fd-8e0f-d7dcce0d6b35/swarm-phase3-training-eefa34ba/.pkgs"),
]
for _pkg in _CANDIDATE_PKGS:
    if _pkg.exists() and str(_pkg) not in sys.path:
        sys.path.insert(0, str(_pkg))

try:
    from ml.v2.serving.detector import Detector  # type: ignore[import]
    _DETECTOR_CLASS_OK = True
except ImportError as _imp_err:
    Detector = None  # type: ignore[assignment, misc]
    _DETECTOR_CLASS_OK = False
    logger.warning("ml.v2.serving.detector could not be imported: %s", _imp_err)

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------
_detector: Any = None
_model_unavailable_reason: str = "not yet loaded"
_load_error_detail: str = ""
_model_status: str = "unavailable"  # "ok" | "experimental" | "unavailable"


def load_predictor() -> None:
    """
    Attempt to load the ModelBundle and initialise the Detector.
    Called once from the FastAPI lifespan hook.
    On any failure the predictor stays None and callers get 503.
    """
    global _detector, _model_unavailable_reason, _load_error_detail, _model_status

    bundle_path = Path(config.ML_BUNDLE_PATH).resolve()
    logger.info("ML_BUNDLE_PATH resolved to: %s", bundle_path)

    if not _DETECTOR_CLASS_OK or Detector is None:
        _model_unavailable_reason = (
            f"ml.v2.serving.detector could not be imported — "
            "run `pip install -e ml/v2` or check PYTHONPATH"
        )
        _load_error_detail = _model_unavailable_reason
        logger.error("model_unavailable: %s", _model_unavailable_reason)
        return

    if not bundle_path.exists():
        _model_unavailable_reason = f"bundle file not found at {bundle_path}"
        _load_error_detail = _model_unavailable_reason
        logger.warning("model_unavailable: %s", _model_unavailable_reason)
        return

    try:
        det = Detector(str(bundle_path))
        if not det.is_loaded:
            _model_unavailable_reason = getattr(det, "_load_error", "Detector.is_loaded=False")
            _load_error_detail = _model_unavailable_reason
            logger.error("Detector constructed but not loaded: %s", _model_unavailable_reason)
            return

        _detector = det
        gates = getattr(det, "_bundle_metrics", {}).get("gates_passed", None)
        if config.ALLOW_UNGATED_MODEL:
            _model_status = "experimental"
            logger.warning(
                "ALLOW_UNGATED_MODEL=true — bundle loaded in experimental mode. "
                "Gates: %s. schema=%s version=%s cutoff=%s",
                gates, det.schema_version, det.model_version, det.training_cutoff,
            )
        else:
            _model_status = "ok"
            logger.info(
                "Detector loaded OK — version=%s schema=%s cutoff=%s size=%s bytes",
                det.model_version, det.schema_version, det.training_cutoff,
                bundle_path.stat().st_size,
            )

    except Exception as exc:
        _model_unavailable_reason = f"{type(exc).__name__}: {exc}"
        _load_error_detail = traceback.format_exc()
        logger.error(
            "Failed to load Detector from %s:\n%s",
            bundle_path, _load_error_detail,
        )


# ---------------------------------------------------------------------------
# Public accessors
# ---------------------------------------------------------------------------

def is_model_loaded() -> bool:
    return _detector is not None and _detector.is_loaded


def get_predictor() -> Any:
    return _detector


def get_model_status() -> str:
    return _model_status


def get_load_error() -> str:
    return _load_error_detail


def get_threshold_config() -> dict | None:
    if _detector is None:
        return None
    b = getattr(_detector, "_bundle", None)
    if b is None:
        return None
    return {
        "phishing": getattr(b, "t_phishing", None),
        "suspicious": getattr(b, "t_suspicious", None),
    }


def get_model_kind() -> str | None:
    return "detector_v2" if is_model_loaded() else None


def get_model_info() -> dict[str, Any]:
    """Full info dict for /api/v1/model-info."""
    bundle_path = Path(config.ML_BUNDLE_PATH).resolve()
    info: dict[str, Any] = {
        "loaded": is_model_loaded(),
        "bundle_path": str(bundle_path),
        "bundle_exists": bundle_path.exists(),
        "bundle_size_bytes": bundle_path.stat().st_size if bundle_path.exists() else None,
        "model_status": _model_status,
        "load_error": _load_error_detail or None,
        "allow_ungated": config.ALLOW_UNGATED_MODEL,
    }
    if is_model_loaded() and _detector is not None:
        b = getattr(_detector, "_bundle", None)
        if isinstance(b, dict):
            t_phish = b.get("t_phishing") or b.get("thresholds", {}).get("phishing")
            t_susp = b.get("t_suspicious") or b.get("thresholds", {}).get("suspicious")
            feat_cnt = len(b.get("features", []) or b.get("feature_names", []))
            gates_info = b.get("metrics", {}).get("GATE_SUMMARY", {})
        else:
            t_phish = getattr(b, "t_phishing", None)
            t_susp = getattr(b, "t_suspicious", None)
            feat_cnt = len(getattr(b, "features", []))
            gates_info = getattr(b, "metrics", {}).get("GATE_SUMMARY", {})

        info.update({
            "model_version": _detector.model_version,
            "schema_version": _detector.schema_version,
            "training_cutoff": _detector.training_cutoff,
            "t_phishing": t_phish,
            "t_suspicious": t_susp,
            "feature_count": feat_cnt or 67,
            "gates": gates_info,
        })
    return info


def predict(
    url: str,
    *,
    page_html: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Run inference.
    Raises RuntimeError with reason when model is not loaded.
    Returns a PredictResponse-compatible dict on success.
    """
    if not is_model_loaded() or _detector is None:
        raise RuntimeError(f"model_unavailable: {_model_unavailable_reason}")

    result = _detector.analyze(url, html=page_html, **kwargs)
    top_features = result.get("top_features", [])
    thresholds = getattr(_detector, "thresholds", {"phishing": 0.55, "suspicious": 0.25})

    return {
        "prediction": "phishing" if result["label"] == "phishing" else "benign",
        "risk_level": "dangerous" if result["label"] == "phishing" else result["label"], # dangerous / suspicious / safe
        "phishing_probability": float(result["score"]),
        "model_mode": result["mode"],
        "decided_by": result["decided_by"],
        "groups_missing": result.get("groups_missing", []),
        "content_ignored": result.get("content_ignored", False),
        "model_version": result.get("model_version", ""),
        "schema_version": result.get("schema_version"),
        "training_cutoff": result.get("training_cutoff"),
        "fetch_error": result.get("fetch_error"),
        "model_available": True,
        "model_status": _model_status,
        "risk_thresholds": thresholds,
        "reasons": top_features,
        "reason_strings": [f.get("reason", str(f)) for f in top_features],
        "top_features": top_features,
    }
