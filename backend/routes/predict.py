"""
routes/predict.py — POST /api/v1/predict (core phishing-detection endpoint).
"""

from __future__ import annotations

import json
import logging
import uuid
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status

import config
import models
from database import get_db
from routes.auth import get_optional_user
from schemas import ErrorResponse, PredictRequest, PredictResponse
from services import predictor as predictor_svc
from services.risk_policy import apply_policy

logger = logging.getLogger(__name__)
router = APIRouter(tags=["predict"])

_VALID_SCHEMES = {"http", "https"}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _validate_url(url: str) -> None:
    """Raise 422 if the URL is not a valid http/https URL."""
    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "INVALID_URL", "detail": "URL could not be parsed"},
        )

    if parsed.scheme not in _VALID_SCHEMES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "INVALID_URL", "detail": "URL must use http or https scheme"},
        )

    if not parsed.netloc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "INVALID_URL", "detail": "URL has no host/domain"},
        )


def _build_explanation(raw: dict, source: str) -> str:
    if source == "blocklist":
        return (
            "This URL's domain is on your personal blocklist. "
            "It has been marked as dangerous regardless of the model's output."
        )
    if source == "high_confidence_domain_signal":
        return (
            "This hostname contains a one-character lookalike of a known brand. "
            "The high-confidence domain signal overrides the model's lower score "
            "because lookalike domains are a known phishing technique. "
            "This does not verify the website's content or ownership."
        )
    if source == "official_domain_registry":
        return (
            "The registrable domain matches a known official brand domain. "
            "This is a domain-level trust signal, not verification of the page's "
            "content, redirect behavior, or account safety."
        )
    explanation = raw.get("explanation")
    if isinstance(explanation, str) and explanation.strip():
        return explanation
    return (
        "The model returned a result without an explanation. "
        "This is a statistical assessment of URL features, not verification "
        "of the website's ownership or content."
    )


# --------------------------------------------------------------------------- #
# Endpoint
# --------------------------------------------------------------------------- #

@router.post(
    "/predict",
    response_model=PredictResponse,
    responses={
        422: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
        408: {"model": ErrorResponse},
    },
)
def predict(
    body: PredictRequest,
    request: Request,
    current_user: dict | None = Depends(get_optional_user),
) -> PredictResponse:
    """Analyse a URL for phishing indicators."""
    url = body.url
    request_id = str(uuid.uuid4())

    # ------------------------------------------------------------------ #
    # 1. Validate URL
    # ------------------------------------------------------------------ #
    _validate_url(url)

    # ------------------------------------------------------------------ #
    # 2. Ensure model is available
    # ------------------------------------------------------------------ #
    if not predictor_svc.is_model_loaded():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "MODEL_UNAVAILABLE", "detail": "Model is not loaded"},
        )

    # ------------------------------------------------------------------ #
    # 3. Fetch user's block/allow lists (empty for anonymous users)
    # ------------------------------------------------------------------ #
    blocklist_domains: list[str] = []
    allowlist_domains: list[str] = []

    if current_user:
        with get_db() as conn:
            blocklist_domains = models.get_all_blocklist_domains(conn, current_user["id"])
            allowlist_domains = models.get_all_allowlist_domains(conn, current_user["id"])

    # ------------------------------------------------------------------ #
    # 4. Run model
    # ------------------------------------------------------------------ #
    try:
        raw = predictor_svc.predict(url)
    except RuntimeError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "MODEL_UNAVAILABLE", "detail": "Model is not loaded"},
        )
    except TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_408_REQUEST_TIMEOUT,
            detail={"error": "TIMEOUT", "detail": "Prediction timed out"},
        )
    except Exception as exc:
        logger.error("Predictor raised unexpected error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "PREDICTION_ERROR", "detail": "Internal prediction error"},
        )

    # ------------------------------------------------------------------ #
    # 5. Apply risk policy
    # ------------------------------------------------------------------ #
    policy = apply_policy(url, raw, blocklist_domains, allowlist_domains)

    prediction: str = policy["prediction"]
    risk_level: str = policy["risk_level"]
    probability: float = policy["phishing_probability"]
    warnings: list[str] = policy["warnings"]
    source: str = policy["source"]

    explanation = _build_explanation(raw, source)

    # ------------------------------------------------------------------ #
    # 6. Persist scan to DB (log at DEBUG to avoid leaking URL params)
    # ------------------------------------------------------------------ #
    try:
        with get_db() as conn:
            models.insert_scan(
                conn,
                user_id=current_user["id"] if current_user else None,
                url=url,
                prediction=prediction,
                risk_level=risk_level,
                phishing_probability=probability,
                model_version=config.MODEL_VERSION,
                warnings_json=json.dumps(warnings),
                explanation=explanation,
                source=source,
            )
    except Exception as exc:
        logger.error("Failed to persist scan: %s", exc, exc_info=True)
        # Non-fatal — still return the prediction

    return PredictResponse(
        request_id=request_id,
        url=url,
        prediction=prediction,
        risk_level=risk_level,
        phishing_probability=probability,
        model_version=config.MODEL_VERSION,
        warnings=warnings,
        explanation=explanation,
        source=source,
    )
