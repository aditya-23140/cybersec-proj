"""
bundle.py — ModelBundle: single deployable artifact containing model, calibrator,
schema version, thresholds, feature definitions, and validation metadata.
"""

from __future__ import annotations

import gzip
import logging
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np

logger = logging.getLogger(__name__)


class ModelBundle:
    """
    Encapsulates all trained components needed for production inference:
    - Base classifier (XGBoost or baseline)
    - Probability calibrator (IsotonicRegression)
    - Schema version and ordered feature names
    - Decision thresholds: t_phishing, t_suspicious
    - Model metadata and evaluation metrics
    """

    def __init__(
        self,
        *,
        model: Any,
        calibrator: Any = None,
        schema_version: str = "2.0.0-dev",
        model_version: str = "2.0.0",
        training_cutoff: str = "",
        data_card_version: str = "v2.0",
        t_phishing: float = 0.85,
        t_suspicious: float = 0.50,
        features: Optional[list[str]] = None,
        metrics: Optional[dict[str, Any]] = None,
    ) -> None:
        self.model = model
        self.calibrator = calibrator
        self.schema_version = schema_version
        self.model_version = model_version
        self.training_cutoff = training_cutoff
        self.data_card_version = data_card_version
        self.t_phishing = float(t_phishing)
        self.t_suspicious = float(t_suspicious)
        self.features = list(features or [])
        self.metrics = dict(metrics or {})

    def refuse_mismatched_schema(self, schema_version: str) -> None:
        """
        Raise ValueError if *schema_version* does not match bundle's schema_version.
        """
        if schema_version != self.schema_version:
            raise ValueError(
                f"Schema version mismatch: bundle expects '{self.schema_version}', "
                f"received '{schema_version}'"
            )

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Produce calibrated probability of phishing.

        Returns 1D array of floats in [0, 1].
        """
        X_arr = np.asarray(X, dtype=np.float32)
        if X_arr.ndim == 1:
            X_arr = X_arr.reshape(1, -1)

        # Raw model scores
        if hasattr(self.model, "predict_proba"):
            raw = self.model.predict_proba(X_arr)[:, 1]
        elif hasattr(self.model, "decision_function"):
            scores = self.model.decision_function(X_arr)
            raw = 1.0 / (1.0 + np.exp(-scores))
        else:
            raw = self.model.predict(X_arr).astype(np.float64)

        if self.calibrator is not None and hasattr(self.calibrator, "predict"):
            calibrated = self.calibrator.predict(raw)
            return np.clip(calibrated, 0.0, 1.0)

        return np.clip(raw, 0.0, 1.0)

    def predict_label(self, score: float) -> str:
        """
        Map a calibrated probability score to categorical verdict:
        - score >= t_phishing  -> 'phishing'
        - score >= t_suspicious -> 'suspicious'
        - otherwise             -> 'safe'
        """
        score_val = float(score)
        if score_val >= self.t_phishing:
            return "phishing"
        if score_val >= self.t_suspicious:
            return "suspicious"
        return "safe"

    def save(self, path: str | Path) -> None:
        """
        Save the bundle to disk as a single compressed file (.pkl.gz).
        """
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "__header__": {
                "bundle_type": "FihhGuardModelBundle",
                "bundle_format_version": "2.0",
                "schema_version": self.schema_version,
            },
            "schema_version": self.schema_version,
            "model_version": self.model_version,
            "training_cutoff": self.training_cutoff,
            "data_card_version": self.data_card_version,
            "t_phishing": self.t_phishing,
            "t_suspicious": self.t_suspicious,
            "features": self.features,
            "metrics": self.metrics,
            "model": self.model,
            "calibrator": self.calibrator,
        }

        with gzip.open(p, "wb") as gz_f:
            joblib.dump(payload, gz_f, compress=3)
        logger.info("Saved ModelBundle to %s", p)

    @classmethod
    def load(cls, path: str | Path, expected_schema_version: Optional[str] = None) -> "ModelBundle":
        """
        Load a ModelBundle from a .pkl.gz file.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Bundle file not found: {p}")

        with gzip.open(p, "rb") as gz_f:
            data = joblib.load(gz_f)

        if not isinstance(data, dict) or "__header__" not in data:
            raise ValueError(f"Invalid bundle file format in {p}")

        header = data["__header__"]
        schema_ver = header.get("schema_version", data.get("schema_version", "unknown"))

        bundle = cls(
            model=data.get("model"),
            calibrator=data.get("calibrator"),
            schema_version=schema_ver,
            model_version=data.get("model_version", "2.0.0"),
            training_cutoff=data.get("training_cutoff", ""),
            data_card_version=data.get("data_card_version", "v2.0"),
            t_phishing=data.get("t_phishing", 0.85),
            t_suspicious=data.get("t_suspicious", 0.50),
            features=data.get("features", []),
            metrics=data.get("metrics", {}),
        )

        if expected_schema_version is not None:
            bundle.refuse_mismatched_schema(expected_schema_version)

        return bundle
