"""
services/risk_policy.py — Apply allow/block list rules and calibrated risk aggregation.

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
    """Return calibrated thresholds from threshold_config.json or defaults."""
    cfg = get_threshold_config()
    if cfg and "optimal_f1_threshold" in cfg:
        suspicious = float(cfg.get("suspicious_threshold", float(cfg["optimal_f1_threshold"]) * 0.7))
        dangerous = float(cfg.get("dangerous_threshold", 0.70))
        return {
            "safe": suspicious,
            "suspicious": dangerous,
        }
    return {"safe": 0.35, "suspicious": 0.70}


def probability_to_risk_level(probability: float) -> str:
    """Convert a phishing probability to a calibrated risk-level string."""
    thresholds = _get_thresholds()
    safe_threshold = thresholds.get("safe", 0.35)
    suspicious_threshold = thresholds.get("suspicious", 0.70)

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


def _official_domain_verified(url: str, network: dict) -> bool:
    """Verify domain identity without requiring a page fetch to finish."""
    dns = network.get("dns", {})
    if not dns.get("dns_resolves", False):
        return False

    if urlparse(url).scheme.lower() == "https":
        tls = network.get("tls", {})
        if not tls.get("certificate_checked") or not tls.get("certificate_valid"):
            return False

    http = network.get("http", {})
    if http.get("cross_domain_redirect"):
        return False
    return http.get("request_status") in {"ok", "timeout"}


def _verification_status(url: str, network: dict, official_domain: bool) -> str:
    """Report evidence completeness separately from phishing risk."""
    if not network or not network.get("enrichment_enabled", False):
        return "unverified"

    dns = network.get("dns", {})
    tls = network.get("tls", {})
    http = network.get("http", {})

    if dns.get("lookup_status") == "nxdomain" or (dns.get("dns_resolves") is False and dns.get("lookup_status") not in ("timeout", "temporary_failure")):
        return "failed"

    if urlparse(url).scheme.lower() == "https" and (
        tls.get("lookup_status") == "invalid_certificate"
        or (tls.get("certificate_checked") and not tls.get("certificate_valid"))
    ):
        return "failed"

    if http.get("cross_domain_redirect") and http.get("has_password_field"):
        return "failed"

    if http.get("request_status") != "ok":
        return "partial" if official_domain else "incomplete"

    return "verified"


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
    Apply blocklist/allowlist rules and calibrated risk aggregation to a raw model prediction.
    """
    warnings: list[str] = list(raw_prediction.get("warnings", []))

    # ------------------------------------------------------------------ #
    # 1. Blocklist takes absolute precedence
    # ------------------------------------------------------------------ #
    if check_domain_in_list(url, blocklist_domains):
        return {
            "prediction": "phishing",
            "risk_level": "dangerous",
            "phishing_probability": max(float(raw_prediction.get("phishing_probability", 1.0)), 0.99),
            "warnings": [
                "⛔ Domain is on your personal blocklist. "
                "This result overrides the model prediction."
            ],
            "source": "blocklist",
            "verification_status": "blocked",
        }

    signals = raw_prediction.get("high_confidence_signals", {})
    network = raw_prediction.get("network_signals", {})
    official_domain = bool(signals.get("known_official_domain"))
    live_verified, verification_reasons = _live_verification_status(url, network)
    verification_status = _verification_status(url, network, official_domain)

    probability = float(raw_prediction.get("phishing_probability", 0.0))

    # ------------------------------------------------------------------ #
    # 2. Verified threat-feed reputation match (URLhaus)
    # ------------------------------------------------------------------ #
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
            "verification_status": "flagged_by_threat_intel",
        }

    # ------------------------------------------------------------------ #
    # 3. Confirmed page-level credential harvesting
    # ------------------------------------------------------------------ #
    page_signals = raw_prediction.get("page_signals", {})
    if (
        page_signals.get("has_password_field")
        and page_signals.get("external_form_count", 0) > 0
    ):
        return {
            "prediction": "phishing",
            "risk_level": "dangerous",
            "phishing_probability": max(probability, 0.95),
            "warnings": [
                "⚠ The inspected page contains a password field submitting to an external domain, "
                "a confirmed credential-harvesting pattern."
            ],
            "source": "page_content_signal",
            "verification_status": verification_status,
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
            "verification_status": verification_status,
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
            "verification_status": verification_status,
        }

    # ------------------------------------------------------------------ #
    # 4. High-confidence brand impersonation / lookalike
    # ------------------------------------------------------------------ #
    if signals.get("brand_lookalike") or signals.get("brand_impersonation"):
        impersonated = signals.get("impersonated_brands", [])
        brand_text = f" ({', '.join(impersonated)})" if impersonated else ""
        return {
            "prediction": "phishing",
            "risk_level": "dangerous",
            "phishing_probability": max(probability, 0.98),
            "warnings": [
                f"⚠ The hostname appears to impersonate a known brand on an unrelated domain{brand_text}. "
                "This high-confidence domain signal overrides the model score."
            ],
            "source": "high_confidence_domain_signal",
            "verification_status": verification_status,
        }

    # ------------------------------------------------------------------ #
    # 5. Negative network signals context
    # ------------------------------------------------------------------ #
    whois = network.get("whois", {})
    tls = network.get("tls", {})
    network_warnings: list[str] = []

    if whois.get("domain_age_days") is not None and whois["domain_age_days"] < 14:
        network_warnings.append("The domain was registered less than 14 days ago.")

    if (
        urlparse(url).scheme.lower() == "https"
        and tls.get("certificate_checked", False)
        and not tls.get("certificate_valid", False)
    ):
        network_warnings.append("The HTTPS certificate is invalid or does not match the hostname.")

    if network_warnings and probability >= 0.7 and not official_domain:
        return {
            "prediction": "phishing",
            "risk_level": "dangerous",
            "phishing_probability": probability,
            "warnings": network_warnings,
            "source": "network_signal",
            "verification_status": verification_status,
        }

    # ------------------------------------------------------------------ #
    # 6. Official verified brand domain
    # ------------------------------------------------------------------ #
    if official_domain and _official_domain_verified(url, network):
        return {
            "prediction": "benign",
            "risk_level": "safe",
            "phishing_probability": min(probability, 0.02),
            "warnings": [
                "✓ The registrable domain matches a known official brand domain. "
                "The domain and HTTPS connection were verified; page content could "
                "not be confirmed if the fetch timed out."
            ],
            "source": "official_domain_registry",
            "verification_status": verification_status,
        }

    # ------------------------------------------------------------------ #
    # 7. Incomplete verification for safe models
    # ------------------------------------------------------------------ #
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
            "verification_status": verification_status,
        }

    # ------------------------------------------------------------------ #
    # 8. Model-based classification & calibrated risk level
    # ------------------------------------------------------------------ #
    risk_level = probability_to_risk_level(probability)
    prediction = "phishing" if risk_level in ("suspicious", "dangerous") else "benign"

    # ------------------------------------------------------------------ #
    # 9. User personal allowlist
    # ------------------------------------------------------------------ #
    if check_domain_in_list(url, allowlist_domains):
        warnings.append(
            "✅ Domain is on your personal allowlist. "
            "The model prediction is shown but you have marked this domain as trusted."
        )

    return {
        "prediction": prediction,
        "risk_level": risk_level,
        "phishing_probability": round(probability, 6),
        "warnings": warnings,
        "source": "model",
        "verification_status": verification_status,
    }
