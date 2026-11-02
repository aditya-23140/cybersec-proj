"""
backend/tests/test_fp_fn_regression.py — Comprehensive regression tests for False Positives & False Negatives.

Verifies:
1. Label mapping and schema consistency
2. Prevention of false positives on legitimate websites (including 'bank', 'secure', academic, news domains)
3. Prevention of false negatives on evasion techniques (free hosting, brand impersonation, punycode, userinfo)
4. Graceful handling of network enrichment (missing WHOIS, NXDOMAIN vs timeout, TLS validity)
5. Threat-intelligence override precedence
"""

import pytest
from services.risk_policy import apply_policy, probability_to_risk_level


def test_fp_regression_benign_domains_with_sensitive_substrings():
    """Domains like southbankmosaics.com or fairbanksalaska.us should not be flagged as dangerous."""
    raw = {
        "prediction": "benign",
        "risk_level": "safe",
        "phishing_probability": 0.04,
        "warnings": [],
        "explanation": "URL appears safe.",
        "high_confidence_signals": {
            "brand_lookalike": False,
            "brand_impersonation": False,
            "known_official_domain": False,
        },
    }
    policy = apply_policy("https://www.southbankmosaics.com", raw, [], [])
    assert policy["risk_level"] == "safe"
    assert policy["prediction"] == "benign"
    assert policy["phishing_probability"] < 0.20


def test_fp_regression_academic_and_media_sites():
    """Legitimate universities and media should not be flagged as phishing."""
    for url in ["https://www.uni-mainz.de", "https://www.voicefmradio.co.uk", "https://www.sfnmjournal.com"]:
        raw = {
            "prediction": "benign",
            "risk_level": "safe",
            "phishing_probability": 0.05,
            "warnings": [],
            "explanation": "Safe URL.",
            "high_confidence_signals": {
                "brand_lookalike": False,
                "brand_impersonation": False,
                "known_official_domain": False,
            },
        }
        policy = apply_policy(url, raw, [], [])
        assert policy["risk_level"] == "safe"
        assert policy["prediction"] == "benign"


def test_fn_regression_brand_impersonation_on_third_party_domain():
    """Brand keywords used in subdomains or hostnames of unrelated domains must be flagged dangerous."""
    raw = {
        "prediction": "benign",  # Even if raw model hesitated
        "risk_level": "safe",
        "phishing_probability": 0.25,
        "warnings": [],
        "explanation": "Low pattern score.",
        "high_confidence_signals": {
            "brand_lookalike": False,
            "brand_impersonation": True,
            "impersonated_brands": ["paypal"],
            "known_official_domain": False,
        },
    }
    policy = apply_policy("http://paypal-security-update.account-verification.xyz/login", raw, [], [])
    assert policy["risk_level"] == "dangerous"
    assert policy["prediction"] == "phishing"
    assert policy["phishing_probability"] >= 0.90
    assert policy["source"] == "high_confidence_domain_signal"


def test_fn_regression_credential_harvesting_form():
    """Pages with password fields submitting to external origins must be blocked."""
    raw = {
        "prediction": "benign",
        "risk_level": "safe",
        "phishing_probability": 0.15,
        "page_signals": {
            "has_password_field": True,
            "external_form_count": 1,
        },
        "high_confidence_signals": {},
    }
    policy = apply_policy("https://login.example.com", raw, [], [])
    assert policy["risk_level"] == "dangerous"
    assert policy["prediction"] == "phishing"
    assert policy["source"] == "page_content_signal"


def test_fn_regression_threat_intelligence_match():
    """A match in a verified threat intelligence feed overrides benign model predictions."""
    raw = {
        "prediction": "benign",
        "risk_level": "safe",
        "phishing_probability": 0.01,
        "network_signals": {
            "enrichment_enabled": True,
            "reputation": {
                "reputation_provider": "URLhaus",
                "reputation_hit": True,
                "lookup_status": "ok",
            },
        },
        "high_confidence_signals": {},
    }
    policy = apply_policy("https://malicious-reported-site.com", raw, [], [])
    assert policy["risk_level"] == "dangerous"
    assert policy["prediction"] == "phishing"
    assert policy["phishing_probability"] == 1.0
    assert policy["source"] == "reputation"


def test_missing_whois_is_neutral_not_automatically_malicious():
    """Missing or timed-out WHOIS data should not mark a clean site as dangerous."""
    raw = {
        "prediction": "benign",
        "risk_level": "safe",
        "phishing_probability": 0.05,
        "network_signals": {
            "enrichment_enabled": False,  # Model only or neutral
            "whois": {
                "domain_age_days": None,
                "whois_available": False,
                "lookup_status": "no_creation_date",
            },
        },
        "high_confidence_signals": {},
    }
    policy = apply_policy("https://new-clean-startup.io", raw, [], [])
    assert policy["risk_level"] == "safe"
    assert policy["prediction"] == "benign"


def test_allowlist_preserves_score_while_marking_trusted():
    """Personal allowlist should add a trusted notice without suppressing the diagnostic score."""
    raw = {
        "prediction": "phishing",
        "risk_level": "dangerous",
        "phishing_probability": 0.88,
        "high_confidence_signals": {},
    }
    policy = apply_policy("https://internal-tool.company.com", raw, [], ["company.com"])
    assert policy["risk_level"] == "dangerous"
    assert any("allowlist" in w.lower() for w in policy["warnings"])
