"""
services/risk_policy.py — Apply allow/block list rules to a raw prediction.

Domain matching rules
---------------------
* Exact match:    listed domain == URL domain
* Subdomain match: URL domain ends with "." + listed domain
  e.g. "example.com" matches "sub.example.com" but NOT "attacker-example.com"
"""

from __future__ import annotations

from urllib.parse import urlparse

from services.predictor import get_threshold_config


# --------------------------------------------------------------------------- #
# Domain matching
# --------------------------------------------------------------------------- #

def _extract_domain(url: str) -> str:
    """Return the netloc (host) of *url*, lowercased, without port."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host.lower()


def domain_matches(url_domain: str, listed_domain: str) -> bool:
    """
    Return True if *url_domain* equals *listed_domain* or is a subdomain of it.

    >>> domain_matches("sub.example.com", "example.com")
    True
    >>> domain_matches("attacker-example.com", "example.com")
    False
    >>> domain_matches("example.com", "example.com")
    True
    """
    listed = listed_domain.lower().strip()
    url = url_domain.lower().strip()
    return url == listed or url.endswith("." + listed)


def check_domain_in_list(url: str, domains: list[str]) -> bool:
    """Return True if the URL's domain matches any domain in *domains*."""
    url_domain = _extract_domain(url)
    return any(domain_matches(url_domain, d) for d in domains)


# --------------------------------------------------------------------------- #
# Risk-level thresholds
# --------------------------------------------------------------------------- #

def _get_thresholds() -> dict:
    """Return threshold config or sensible defaults.

    threshold_config.json stores suspicious_threshold and dangerous_threshold
    at the top level (not nested under a 'thresholds' key).
    """
    cfg = get_threshold_config()
    if cfg and "optimal_f1_threshold" in cfg:
        return {
            "safe": float(cfg["optimal_f1_threshold"]),
            "suspicious": float(cfg["dangerous_threshold"]),
        }
    # Defaults: < 0.3 → safe, 0.3–0.7 → suspicious, > 0.7 → dangerous
    return {"safe": 0.3, "suspicious": 0.7}


def probability_to_risk_level(probability: float) -> str:
    """Convert a phishing probability to a risk-level string."""
    thresholds = _get_thresholds()
    safe_threshold = thresholds.get("safe", 0.3)
    suspicious_threshold = thresholds.get("suspicious", 0.7)

    if probability < safe_threshold:
        return "safe"
    if probability < suspicious_threshold:
        return "suspicious"
    return "dangerous"


def _live_verification_status(url: str, network: dict) -> tuple[bool, list[str]]:
    """Return whether live checks corroborate a safe result."""
    reasons: list[str] = []
    dns = network.get("dns", {})
    http = network.get("http", {})
    tls = network.get("tls", {})

    if not dns.get("dns_resolves", False):
        reasons.append("the hostname did not resolve in DNS")
    if http.get("request_status") != "ok":
        reasons.append("the page could not be fetched")
    if urlparse(url).scheme.lower() == "https":
        if not tls.get("certificate_checked", False):
            reasons.append("the HTTPS certificate could not be verified")
        elif not tls.get("certificate_valid", False):
            reasons.append("the HTTPS certificate is invalid or mismatched")
    return not reasons, reasons


# --------------------------------------------------------------------------- #
# Policy application
# --------------------------------------------------------------------------- #

def apply_policy(
    url: str,
    raw_prediction: dict,
    blocklist_domains: list[str],
    allowlist_domains: list[str],
) -> dict:
    """
    Apply blocklist/allowlist rules to a raw model prediction.

    Parameters
    ----------
    url : str
        The URL that was analysed.
    raw_prediction : dict
        Output from ``predictor.predict(url)`` with keys:
        ``prediction``, ``phishing_probability``.
    blocklist_domains : list[str]
        Domains the user has blocklisted.
    allowlist_domains : list[str]
        Domains the user has allowlisted.

    Returns
    -------
    dict with keys:
        prediction, risk_level, phishing_probability, warnings, source
    """
    warnings: list[str] = []

    # ------------------------------------------------------------------ #
    # 1. Blocklist takes absolute precedence
    # ------------------------------------------------------------------ #
    if check_domain_in_list(url, blocklist_domains):
        return {
            "prediction": "phishing",
            "risk_level": "dangerous",
            "phishing_probability": raw_prediction.get("phishing_probability", 1.0),
            "warnings": [
                "⛔ Domain is on your personal blocklist. "
                "This result overrides the model prediction."
            ],
            "source": "blocklist",
        }

    signals = raw_prediction.get("high_confidence_signals", {})
    network = raw_prediction.get("network_signals", {})
    live_verified, verification_reasons = _live_verification_status(url, network)

    probability = float(raw_prediction.get("phishing_probability", 0.0))
    reputation = network.get("reputation", {})
    if reputation.get("reputation_hit"):
        return {
            "prediction": "phishing",
            "risk_level": "dangerous",
            "phishing_probability": 1.0,
            "warnings": [
                f"⚠ The configured {reputation.get('reputation_provider', 'reputation')} "
                "provider has reported this URL."
            ],
            "source": "reputation",
        }

    page_signals = raw_prediction.get("page_signals", {})
    if (
        page_signals.get("has_password_field")
        and page_signals.get("external_form_count", 0) > 0
    ):
        probability = max(float(raw_prediction.get("phishing_probability", 0.0)), 0.9)
        return {
            "prediction": "phishing",
            "risk_level": "dangerous",
            "phishing_probability": probability,
            "warnings": [
                "⚠ The page contains a password field that submits to an external "
                "domain, a high-risk credential-harvesting pattern."
            ],
            "source": "page_content_signal",
        }

    if signals.get("brand_lookalike"):
        return {
            "prediction": "phishing",
            "risk_level": "dangerous",
            "phishing_probability": max(
                float(raw_prediction.get("phishing_probability", 0.0)), 0.98
            ),
            "warnings": [
                "⚠ The hostname contains a one-character lookalike of a known brand. "
                "This high-confidence domain signal overrides the lower model score."
            ],
            "source": "high_confidence_domain_signal",
        }

    http_signals = network.get("http", {})
    if (
        http_signals.get("has_password_field")
        and http_signals.get("external_form_count", 0) > 0
    ):
        return {
            "prediction": "phishing",
            "risk_level": "dangerous",
            "phishing_probability": max(probability, 0.95),
            "warnings": [
                "⚠ The fetched page contains a password field submitting to an "
                "external domain, a credential-harvesting pattern."
            ],
            "source": "fetched_page_signal",
        }

    if (
        http_signals.get("cross_domain_redirect")
        and http_signals.get("suspicious_text_hits", 0) > 0
    ):
        return {
            "prediction": "phishing",
            "risk_level": "dangerous",
            "phishing_probability": max(probability, 0.9),
            "warnings": [
                "⚠ The URL redirected to another domain and the fetched page "
                "contained suspicious account or urgency language."
            ],
            "source": "fetched_page_signal",
        }

    whois = network.get("whois", {})
    tls = network.get("tls", {})
    network_warnings: list[str] = []
    if whois.get("domain_age_days") is not None and whois["domain_age_days"] < 14:
        network_warnings.append(
            "The domain was registered less than 14 days ago."
        )
    if (
        urlparse(url).scheme.lower() == "https"
        and tls.get("certificate_checked", False)
        and not tls.get("certificate_valid", False)
    ):
        network_warnings.append(
            "The HTTPS certificate is invalid or does not match the hostname."
        )
    if network_warnings and probability >= 0.2:
        return {
            "prediction": "phishing",
            "risk_level": "dangerous" if probability >= 0.7 else "suspicious",
            "phishing_probability": probability,
            "warnings": network_warnings,
            "source": "network_signal",
        }

    if signals.get("known_official_domain") and live_verified:
        return {
            "prediction": "benign",
            "risk_level": "safe",
            "phishing_probability": min(
                float(raw_prediction.get("phishing_probability", 0.0)), 0.02
            ),
            "warnings": [
                "✓ The registrable domain matches a known official brand domain. "
                "This does not verify the page content or account safety."
            ],
            "source": "official_domain_registry",
        }

    if network.get("enrichment_enabled") and not live_verified:
        return {
            "prediction": "benign",
            "risk_level": "suspicious",
            "phishing_probability": max(probability, 0.3),
            "warnings": [
                "⚠ The model score is low, but the website could not be fully "
                "verified. " + "; ".join(verification_reasons) + "."
            ],
            "source": "verification_incomplete",
        }

    # ------------------------------------------------------------------ #
    # 2. Resolve prediction and probability from model output
    # ------------------------------------------------------------------ #
    probability = float(raw_prediction.get("phishing_probability", 0.0))
    prediction: str = raw_prediction.get("prediction", "benign")

    # Normalise prediction label
    if prediction not in ("benign", "phishing"):
        prediction = "phishing" if probability >= 0.5 else "benign"

    risk_level = probability_to_risk_level(probability)

    # ------------------------------------------------------------------ #
    # 3. Allowlist — note but do NOT override the model result
    # ------------------------------------------------------------------ #
    if check_domain_in_list(url, allowlist_domains):
        warnings.append(
            "✅ Domain is on your personal allowlist. "
            "The model prediction is shown but you have marked this domain as trusted."
        )

    return {
        "prediction": prediction,
        "risk_level": risk_level,
        "phishing_probability": probability,
        "warnings": warnings,
        "source": "model",
    }
