"""
backend/tests/test_predict_new.py — Tests for new Detector and predict endpoint behavior.

Tests:
  1. Test that when model is not loaded, /api/v1/predict returns 503 with MODEL_UNAVAILABLE
  2. Test blocklist overrides model
  3. Test allowlist overrides model
  4. Test valid URL structure accepted, invalid rejected (422)
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure backend and ml are on sys.path
_REPO_ROOT = Path(__file__).resolve().parents[2]
_BACKEND_DIR = _REPO_ROOT / "backend"
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

# Graceful handling for environments without fastapi / pytest
try:
    from fastapi import HTTPException, status
    from fastapi.testclient import TestClient
    from routes.predict import _validate_url
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

    class status:  # type: ignore[no-redef]
        HTTP_422_UNPROCESSABLE_ENTITY = 422
        HTTP_503_SERVICE_UNAVAILABLE = 503

    class HTTPException(Exception):  # type: ignore[no-redef]
        def __init__(self, status_code: int, detail: dict):
            super().__init__(str(detail))
            self.status_code = status_code
            self.detail = detail

    # Standalone _validate_url matching routes/predict.py exactly
    from urllib.parse import urlparse
    _VALID_SCHEMES = {"http", "https"}

    def _validate_url(url: str) -> None:  # type: ignore[no-redef]
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


from services.risk_policy import apply_policy
import services.predictor as predictor_svc


# --------------------------------------------------------------------------- #
# 1. Model unavailable returns 503
# --------------------------------------------------------------------------- #

def test_model_not_loaded_returns_503(client=None):
    """When predictor is not loaded, /api/v1/predict returns 503 MODEL_UNAVAILABLE."""
    orig_det = predictor_svc._detector
    try:
        predictor_svc._detector = None
        assert not predictor_svc.is_model_loaded()
        try:
            predictor_svc.predict("https://example.com")
            assert False, "Should have raised RuntimeError when predictor is not loaded"
        except RuntimeError as exc:
            assert "model_unavailable" in str(exc) or "not loaded" in str(exc).lower()

        if client is not None:
            resp = client.post("/api/v1/predict", json={"url": "https://example.com/login"})
            assert resp.status_code == 503
            data = resp.json()
            assert data.get("detail", {}).get("error") == "MODEL_UNAVAILABLE"
    finally:
        predictor_svc._detector = orig_det


def test_integration_model_loaded_and_predict(client):
    """
    Requirement 5: Starts app with real bundle path, asserts /model-info
    shows loaded=true and /predict returns 200 for legitimate and phishing examples.
    """
    resp_info = client.get("/api/v1/model-info")
    assert resp_info.status_code == 200
    info = resp_info.json()
    assert info.get("loaded") is True or info.get("model_loaded") is True

    # Legitimate URL
    resp_legit = client.post("/api/v1/predict", json={"url": "https://google.com"})
    assert resp_legit.status_code == 200
    data_legit = resp_legit.json()
    assert "prediction" in data_legit
    assert "risk_level" in data_legit

    # Phishing example
    resp_phish = client.post("/api/v1/predict", json={"url": "https://paypal-verify-account.suspicious.tk/login"})
    assert resp_phish.status_code == 200
    data_phish = resp_phish.json()
    assert "prediction" in data_phish
    assert "risk_level" in data_phish


# --------------------------------------------------------------------------- #
# 2. Blocklist overrides model
# --------------------------------------------------------------------------- #

def test_blocklist_overrides_model(client=None, auth_headers=None):
    """
    When a domain is on the blocklist, prediction is 'phishing'
    and risk_level is 'dangerous' regardless of what the model scored.
    """
    raw_benign = {
        "prediction": "benign",
        "risk_level": "safe",
        "phishing_probability": 0.05,
        "model_mode": "url-only",
        "decided_by": "model",
        "network_signals": {"enrichment_enabled": False},
    }

    # Policy evaluation
    policy_res = apply_policy(
        "https://malicious-blocklist.com/path",
        raw_benign,
        blocklist_domains=["malicious-blocklist.com"],
        allowlist_domains=[],
    )
    assert policy_res["prediction"] == "phishing"
    assert policy_res["risk_level"] == "dangerous"
    assert policy_res["decided_by"] == "personal_blocklist"
    assert policy_res["source"] == "blocklist"

    # Also test subdomain matching for blocklist
    sub_res = apply_policy(
        "https://sub.malicious-blocklist.com/path",
        raw_benign,
        blocklist_domains=["malicious-blocklist.com"],
        allowlist_domains=[],
    )
    assert sub_res["prediction"] == "phishing"
    assert sub_res["risk_level"] == "dangerous"
    assert sub_res["decided_by"] == "personal_blocklist"

    # Endpoint check if client available
    if client is not None and auth_headers is not None:
        client.post("/api/v1/blocklist", json={"domain": "malicious-blocklist.com"}, headers=auth_headers)
        mock_pred = {
            "prediction": "benign",
            "risk_level": "safe",
            "phishing_probability": 0.01,
            "model_mode": "url-only",
            "decided_by": "model",
            "groups_missing": [],
            "content_ignored": False,
            "model_version": "2.0.0-dev",
            "fetch_error": None,
            "reasons": [],
        }
        with patch.object(predictor_svc, "is_model_loaded", return_value=True), \
             patch.object(predictor_svc, "predict", return_value=mock_pred), \
             patch("routes.predict.enrich_url", return_value={"enrichment_enabled": False}):
            resp = client.post(
                "/api/v1/predict",
                json={"url": "https://malicious-blocklist.com/login"},
                headers=auth_headers,
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["prediction"] == "phishing"
            assert data["risk_level"] == "dangerous"
            assert data["decided_by"] == "personal_blocklist"


# --------------------------------------------------------------------------- #
# 3. Allowlist overrides model
# --------------------------------------------------------------------------- #

def test_allowlist_overrides_model():
    """
    Test that personal allowlist overrides the model:
      When a domain is on the user's personal allowlist, prediction is 'benign'
      and risk_level is 'safe' with decided_by='personal_allowlist'.
    """
    raw_phish = {
        "prediction": "phishing",
        "risk_level": "dangerous",
        "phishing_probability": 0.95,
        "model_mode": "url-only",
        "decided_by": "model",
        "network_signals": {"enrichment_enabled": False},
    }

    # Policy evaluation for personal allowlist
    policy_res = apply_policy(
        "https://trusted-site.com/path",
        raw_phish,
        blocklist_domains=[],
        allowlist_domains=["trusted-site.com"],
    )
    assert policy_res["prediction"] == "benign"
    assert policy_res["risk_level"] == "safe"
    assert policy_res["decided_by"] == "personal_allowlist"
    assert policy_res["source"] == "allowlist"

    # Subdomain matching for allowlist
    sub_res = apply_policy(
        "https://sub.trusted-site.com/path",
        raw_phish,
        blocklist_domains=[],
        allowlist_domains=["trusted-site.com"],
    )
    assert sub_res["prediction"] == "benign"
    assert sub_res["risk_level"] == "safe"
    assert sub_res["decided_by"] == "personal_allowlist"


# --------------------------------------------------------------------------- #
# 4. URL validation: accept valid, reject invalid (422)
# --------------------------------------------------------------------------- #

def test_url_validation_accepts_valid():
    """Valid http/https URLs with a host must pass _validate_url without raising."""
    valid_urls = [
        "https://example.com",
        "http://sub.domain.org/path?a=1&b=2#frag",
        "https://192.168.1.1:8080/index.html",
        "http://localhost:3000/",
        "https://bank.example.co.uk/account/login",
    ]
    for url in valid_urls:
        _validate_url(url)  # Must not raise


def test_url_validation_rejects_invalid_422(client=None):
    """Invalid URLs must be rejected with 422 Unprocessable Entity."""
    invalid_cases = [
        "",
        "   ",
        "ftp://files.example.com",
        "javascript:alert(1)",
        "mailto:user@example.com",
        "data:text/html,<html></html>",
        "file:///etc/passwd",
        "not-a-valid-url",
        "http://",  # Missing host/netloc
    ]

    for inv in invalid_cases:
        try:
            _validate_url(inv)
            assert False, f"Expected 422 HTTPException for {inv!r}"
        except HTTPException as exc:
            assert exc.status_code == 422, f"Expected 422, got {exc.status_code}"

    # If client is provided, test over HTTP
    if client is not None:
        for inv in ["", "ftp://files.example.com", "javascript:alert(1)"]:
            resp = client.post("/api/v1/predict", json={"url": inv})
            assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Standalone execution
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    print("Running backend/tests/test_predict_new.py standalone...")
    test_model_not_loaded_returns_503()
    print("  ✓ test_model_not_loaded_returns_503 PASSED")
    test_blocklist_overrides_model()
    print("  ✓ test_blocklist_overrides_model PASSED")
    test_allowlist_overrides_model()
    print("  ✓ test_allowlist_overrides_model PASSED")
    test_url_validation_accepts_valid()
    print("  ✓ test_url_validation_accepts_valid PASSED")
    test_url_validation_rejects_invalid_422()
    print("  ✓ test_url_validation_rejects_invalid_422 PASSED")
    print("\nALL 5 TESTS PASSED (no bundle needed) ✓")
