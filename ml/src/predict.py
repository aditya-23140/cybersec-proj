"""
predict.py — Inference module loaded by the FastAPI backend.

Usage:
    from src.predict import PhishingPredictor
    predictor = PhishingPredictor(artifacts_dir="artifacts/")
    result = predictor.predict("https://example.com")
"""

from __future__ import annotations

import json
import logging
import math
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_KNOWN_OFFICIAL_DOMAINS = frozenset(
    {
        "amazon.com",
        "apple.com",
        "facebook.com",
        "google.com",
        "instagram.com",
        "linkedin.com",
        "microsoft.com",
        "netflix.com",
        "paypal.com",
        "spotify.com",
        "twitter.com",
        "discord.com",
        "wikipedia.org",
        "youtube.com",
    }
)


# ─────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class PredictionResult:
    request_id: str
    url: str
    prediction: str            # "phishing" | "benign"
    risk_level: str            # "safe" | "suspicious" | "dangerous"
    phishing_probability: float  # 0.0 – 1.0
    model_version: str
    warnings: list[str] = field(default_factory=list)
    explanation: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Predictor class
# ─────────────────────────────────────────────────────────────────────────────


class PhishingPredictor:
    """
    Load the trained XGBoost model and feature schema, then produce
    PredictionResult objects for arbitrary URLs.

    Parameters
    ----------
    artifacts_dir:
        Directory containing model.ubj, feature_schema.json,
        threshold_config.json, and metadata.json.
    enable_dns:
        If True, perform live DNS / WHOIS enrichment for network features.
        Defaults to False for fast, safe inference.
    """

    def __init__(self, artifacts_dir: str, enable_dns: bool = False) -> None:
        self._artifacts_dir = Path(artifacts_dir)
        self._enable_dns = enable_dns
        self._model: Any = None
        self._feature_schema: dict = {}
        self._threshold_config: dict = {}
        self._metadata: dict = {}
        self._calibration: dict = {}
        self._load_artifacts()

    # ------------------------------------------------------------------ #
    # Artifact loading
    # ------------------------------------------------------------------ #

    def _load_artifacts(self) -> None:
        """Load model and supporting JSON files. Raises on missing model."""
        from .model_registry import (
            load_feature_schema,
            load_metadata,
            load_model,
            load_threshold_config,
        )

        self._model = load_model(self._artifacts_dir)

        try:
            self._feature_schema = load_feature_schema(self._artifacts_dir)
        except FileNotFoundError:
            logger.warning("feature_schema.json not found — using defaults.")

        schema_count = self._feature_schema.get("feature_count")
        model_count = getattr(self._model, "n_features_in_", None)
        if model_count is None:
            model_count = self._model.get_booster().num_features()
        if schema_count is not None and int(model_count) != int(schema_count):
            raise RuntimeError(
                "Model artifact is incompatible with feature_schema.json: "
                f"model expects {model_count} features, schema defines {schema_count}. "
                "Retrain the model and restart the backend."
            )

        try:
            self._threshold_config = load_threshold_config(self._artifacts_dir)
        except FileNotFoundError:
            logger.warning("threshold_config.json not found — using default thresholds.")

        try:
            self._metadata = load_metadata(self._artifacts_dir)
        except FileNotFoundError:
            logger.warning("metadata.json not found.")
        try:
            from .model_registry import load_calibration
            self._calibration = load_calibration(self._artifacts_dir)
        except FileNotFoundError:
            logger.warning("calibration.json not found — using raw URL-model scores.")

    # ------------------------------------------------------------------ #
    # Threshold helpers
    # ------------------------------------------------------------------ #

    @property
    def _suspicious_threshold(self) -> float:
        return float(
            self._threshold_config.get(
                "optimal_f1_threshold",
                self._threshold_config.get("suspicious_threshold", 0.3),
            )
        )

    @property
    def _dangerous_threshold(self) -> float:
        return float(self._threshold_config.get("dangerous_threshold", 0.7))

    @property
    def _optimal_threshold(self) -> float:
        return float(self._threshold_config.get("optimal_f1_threshold", 0.5))

    def _probability_to_risk(self, prob: float) -> tuple[str, str]:
        """Return (risk_level, prediction) for a given probability."""
        if prob >= self._dangerous_threshold:
            return "dangerous", "phishing"
        if prob >= self._suspicious_threshold:
            return "suspicious", "phishing"
        return "safe", "benign"

    def _calibrate_probability(self, probability: float) -> float:
        """Apply persisted Platt scaling to the URL-model probability."""
        if self._calibration.get("method") != "platt":
            return probability
        clipped = min(max(probability, 1e-6), 1 - 1e-6)
        logit = math.log(clipped / (1 - clipped))
        value = (
            float(self._calibration.get("slope", 1.0)) * logit
            + float(self._calibration.get("intercept", 0.0))
        )
        return 1.0 / (1.0 + math.exp(-value))

    # ------------------------------------------------------------------ #
    # Feature extraction
    # ------------------------------------------------------------------ #

    def _extract(self, url: str):
        """
        Extract features from *url*.

        Returns FeatureVector. Raises ValueError for invalid URLs.
        """
        from .feature_extractor import extract_features
        return extract_features(url, enable_dns=self._enable_dns)

    # ------------------------------------------------------------------ #
    # Explanation builder
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_explanation(
        feature_vector,
        risk_level: str,
        probability: float,
        contributions: list[tuple[str, float]],
    ) -> str:
        feature_labels = {
            "length_url": "URL length",
            "qty_dots_url": "number of dots",
            "qty_hyphens_path": "path hyphens",
            "subdomain_count": "subdomain count",
            "has_brand_keyword": "brand/security keyword",
            "hostname_hyphen_count": "hostname hyphen count",
            "hostname_digit_count": "hostname digit count",
            "brand_lookalike": "brand lookalike signal",
            "suspicious_path_keyword": "suspicious path keyword",
            "is_domain_ip": "IP-address hostname",
            "has_obfuscation": "URL obfuscation",
            "digit_ratio_url": "URL digit ratio",
        }
        positive = [
            feature_labels.get(name, name)
            for name, value in contributions
            if value > 0.05
        ][:3]
        negative = [
            feature_labels.get(name, name)
            for name, value in contributions
            if value < -0.05
        ][:3]
        details: list[str] = []
        if positive:
            details.append("increased the phishing score: " + ", ".join(positive))
        if negative:
            details.append("reduced the phishing score: " + ", ".join(negative))

        assessment = f"The model assigned a {risk_level} risk ({probability:.1%} phishing probability)."
        if details:
            assessment += " Model contribution analysis shows that " + "; ".join(details) + "."
        else:
            assessment += " No individual URL feature made a strong contribution to the score."

        if feature_vector.missing_features:
            assessment += (
                " Network-dependent features were unavailable: "
                + ", ".join(feature_vector.missing_features)
                + "."
            )

        return (
            assessment
            + " This is a statistical assessment of URL features, not verification "
            "of the website's ownership or content."
        )

    # ------------------------------------------------------------------ #
    # Public predict method
    # ------------------------------------------------------------------ #

    def predict(self, url: str) -> dict:
        """
        Analyse *url* and return a dict compatible with PredictResponse.

        Raises
        ------
        ValueError
            For unsupported URL schemes or unparseable URLs.
        RuntimeError
            If the model is not loaded (should not happen post-__init__).
        """
        import numpy as np

        if self._model is None:
            raise RuntimeError("Model is not loaded")

        request_id = str(uuid.uuid4())

        # Extract features
        fv = self._extract(url)  # raises ValueError for bad URLs
        hostname = (urlparse(url).hostname or "").lower().rstrip(".")
        try:
            import tldextract

            extracted = tldextract.extract(hostname)
            registrable_domain = (
                f"{extracted.domain}.{extracted.suffix}"
                if extracted.domain and extracted.suffix
                else hostname
            )
        except ImportError:
            registrable_domain = hostname
        feature_index = {
            name: index for index, name in enumerate(fv.feature_names)
        }
        high_confidence_signals = {
            "brand_lookalike": bool(
                fv.features[feature_index["brand_lookalike"]]
            ),
            "known_official_domain": registrable_domain in _KNOWN_OFFICIAL_DOMAINS,
        }

        expected_features = getattr(self._model, "n_features_in_", None)
        if expected_features is None:
            expected_features = self._model.get_booster().num_features()
        if len(fv.features) != int(expected_features):
            raise RuntimeError(
                "Feature vector is incompatible with the loaded model: "
                f"model expects {expected_features} features, extractor produced "
                f"{len(fv.features)}. Retrain the model and restart the backend."
            )

        X = np.array([fv.features], dtype=np.float32)
        url_model_score = float(self._model.predict_proba(X)[0, 1])
        prob = self._calibrate_probability(url_model_score)

        risk_level, prediction = self._probability_to_risk(prob)
        contributions: list[tuple[str, float]] = []
        try:
            from xgboost import DMatrix
            from .feature_extractor import FEATURE_NAMES

            model_contributions = self._model.get_booster().predict(
                DMatrix(X), pred_contribs=True
            )[0]
            contributions = sorted(
                zip(FEATURE_NAMES, model_contributions[:-1]),
                key=lambda item: abs(float(item[1])),
                reverse=True,
            )
        except (AttributeError, ImportError, ValueError) as exc:
            logger.warning("Could not calculate model contributions: %s", exc)

        explanation = self._build_explanation(fv, risk_level, prob, contributions)

        warnings: list[str] = list(fv.warnings)

        model_version = self._metadata.get("model_version", "1.0.0")

        return {
            "request_id": request_id,
            "url": url,
            "prediction": prediction,
            "risk_level": risk_level,
            "phishing_probability": round(prob, 6),
            "url_model_score": round(url_model_score, 6),
            "calibrated_url_model_score": round(prob, 6),
            "model_version": model_version,
            "warnings": warnings,
            "explanation": explanation,
            "high_confidence_signals": high_confidence_signals,
        }
