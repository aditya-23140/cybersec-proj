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
from services.network_enrichment import enrich_url
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


def _network_explanation(raw: dict) -> str:
    network = raw.get("network_signals", {})
    if not network or not network.get("enrichment_enabled", False):
        return ""

    details: list[str] = []
    dns = network.get("dns", {})
    if dns.get("dns_resolves"):
        details.append("the website address resolved successfully")

    whois = network.get("whois", {})
    age = whois.get("domain_age_days")
    if age is not None and age < 14:
        details.append("the domain was registered recently")

    tls = network.get("tls", {})
    if tls.get("certificate_checked") and not tls.get("certificate_valid"):
        details.append("the security certificate is invalid or does not match")

    reputation = network.get("reputation", {})
    provider = reputation.get("reputation_provider")
    if reputation.get("reputation_hit"):
        details.append(f"{provider or 'Configured reputation provider'} reported the URL")
    elif provider and reputation.get("lookup_status") == "ok":
        details.append("no known malicious report was found")

    http_signals = network.get("http", {})
    if http_signals:
        status = http_signals.get("request_status")
        if status == "ok":
            details.append(
                f"HTTP fetch returned status {http_signals.get('http_status')}"
            )
            if http_signals.get("redirect_count", 0):
                details.append(
                    f"{http_signals['redirect_count']} redirect(s) followed"
                )
            if http_signals.get("cross_domain_redirect"):
                details.append("redirect crossed to another domain")
            if http_signals.get("has_password_field"):
                details.append("page contains a password field")
            if http_signals.get("external_form_count", 0):
                details.append("page contains an external form")
            if http_signals.get("suspicious_text_hits", 0):
                details.append(
                    f"{http_signals['suspicious_text_hits']} suspicious text match(es)"
                )
        elif status in {"timeout", "error", "unavailable"}:
            details.append("the website could not be reached for content verification")

    return (
        " Additional checks found "
        + "; ".join(details)
        + "."
        if details
        else ""
    )


def _build_explanation(raw: dict, source: str) -> str:
    explanation: str
    if source == "blocklist":
        explanation = (
            "This URL's domain is on your personal blocklist. "
            "It has been marked as dangerous regardless of the model's output."
        )
    elif source == "high_confidence_domain_signal":
        explanation = (
            "This hostname appears to impersonate a known brand on an unrelated "
            "domain. The high-confidence domain signal overrides the model's "
            "lower score because brand impersonation is a known phishing technique. "
            "This does not verify the website's content or ownership."
        )
    elif source == "official_domain_registry":
        explanation = (
            "The registrable domain matches a known official brand domain. "
            "This is a domain-level trust signal, not verification of the page's "
            "content, redirect behavior, or account safety."
        )
    elif source == "page_content_signal":
        explanation = (
            "The loaded page contains a password field whose form submits to an "
            "external domain. This is a high-risk credential-harvesting signal. "
            "The assessment uses aggregate page structure only and does not send "
            "page text, credentials, cookies, or form values."
        )
    elif source == "fetched_page_signal":
        http_signals = raw.get("network_signals", {}).get("http", {})
        factors: list[str] = []
        if http_signals.get("has_password_field"):
            factors.append("a password field")
        if http_signals.get("external_form_count", 0) > 0:
            factors.append("a form submitting to an external domain")
        if http_signals.get("cross_domain_redirect"):
            factors.append("a cross-domain redirect")
        if http_signals.get("suspicious_text_hits", 0) > 0:
            factors.append("suspicious account or urgency language")
        explanation = (
            "The fetched page was flagged because it contained "
            + ", ".join(factors)
            + ". This inspection used bounded HTML analysis and did not store "
            "page content, credentials, cookies, or form values."
        )
    elif source == "reputation":
        reputation = raw.get("network_signals", {}).get("reputation", {})
        provider = reputation.get("reputation_provider") or "configured reputation"
        explanation = (
            f"The URL was reported by {provider}. This is stronger evidence than "
            "URL structure alone, but reputation databases can be delayed or "
            "incomplete."
        )
    elif source == "network_signal":
        network = raw.get("network_signals", {})
        whois = network.get("whois", {})
        tls = network.get("tls", {})
        factors: list[str] = []
        age = whois.get("domain_age_days")
        if age is not None and age < 14:
            factors.append(f"the domain is only {age} days old")
        if tls.get("certificate_checked") and not tls.get("certificate_valid"):
            factors.append("the HTTPS certificate is invalid or does not match the hostname")
        if factors:
            factor_text = "; ".join(factors)
            explanation = (
                "Live network checks found these suspicious indicators: "
                f"{factor_text}. These signals increase risk but do not independently "
                "prove that the website is malicious."
            )
        else:
            explanation = (
                "Live network checks produced a suspicious result, but no specific "
                "network factor was available. Treat this as supporting evidence only."
            )
    elif source == "verification_incomplete":
        explanation = (
            "This website could not be fully verified, so it was not marked safe. "
            "Do not enter passwords or payment details unless you confirm the "
            "address through an official source."
        )
    else:
        explanation = raw.get("explanation", "")
        if not isinstance(explanation, str) or not explanation.strip():
            explanation = (
                "The URL structure did not show strong phishing indicators. "
                "This result is not proof that the website is safe."
            )
    return explanation + _network_explanation(raw)


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
    if body.page_signals is not None:
        raw["page_signals"] = body.page_signals.model_dump()
    try:
        raw["network_signals"] = enrich_url(url)
    except ValueError as exc:
        logger.warning("Network enrichment skipped: %s", exc)
        raw["network_signals"] = {"enrichment_enabled": False}

    # ------------------------------------------------------------------ #
    # 5. Apply risk policy
    # ------------------------------------------------------------------ #
    policy = apply_policy(url, raw, blocklist_domains, allowlist_domains)

    prediction: str = policy["prediction"]
    risk_level: str = policy["risk_level"]
    probability: float = policy["phishing_probability"]
    warnings: list[str] = policy["warnings"]
    source: str = policy["source"]
    verification_status: str = policy.get("verification_status", "unknown")

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
                url_model_score=raw.get("url_model_score"),
                calibrated_url_model_score=raw.get("calibrated_url_model_score"),
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
        verification_status=verification_status,
        network_signals=raw.get("network_signals", {}),
        domain_identity={
            "known_official_domain": raw.get("high_confidence_signals", {}).get(
                "known_official_domain", False
            ),
            "brand_lookalike": raw.get("high_confidence_signals", {}).get(
                "brand_lookalike", False
            ),
            "brand_impersonation": raw.get("high_confidence_signals", {}).get(
                "brand_impersonation", False
            ),
        },
        evidence_summary={
            "dns_resolved": raw.get("network_signals", {})
            .get("dns", {})
            .get("dns_resolves"),
            "tls_valid": raw.get("network_signals", {})
            .get("tls", {})
            .get("certificate_valid"),
            "http_status": raw.get("network_signals", {})
            .get("http", {})
            .get("request_status"),
            "reputation_hit": raw.get("network_signals", {})
            .get("reputation", {})
            .get("reputation_hit", False),
        },
    )
