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


def probability_to_risk_level(probability: float, thresholds: dict | None = None) -> str:
    """Convert a phishing probability to a calibrated risk-level string."""
    selected = thresholds or _get_thresholds()
    # Support both {"phishing": 0.55, "suspicious": 0.25} and {"dangerous": 0.7, "safe": 0.35}
    if "phishing" in selected and "suspicious" in selected:
        t_phish = float(selected["phishing"])
        t_susp = float(selected["suspicious"])
    else:
        t_phish = float(selected.get("dangerous", selected.get("suspicious", 0.70)))
        t_susp = float(selected.get("safe", 0.35))

    if probability >= t_phish:
        return "dangerous"
    if probability >= t_susp:
        return "suspicious"
    return "safe"


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
    Pure model-based policy application.
    Uses only the trained ML model's calibrated probability and thresholds for prediction.
    Personal allow/block lists are respected for logged-in users; all 3rd-party site lookups are removed.
    """
    warnings: list[str] = list(raw_prediction.get("warnings", []))

    # 1. User's personal blocklist in local database (logged-in user override)
    if check_domain_in_list(url, blocklist_domains):
        return {
            "prediction": "phishing",
            "risk_level": "dangerous",
            "phishing_probability": 1.0,
            "warnings": [
                "⛔ Domain is on your personal blocklist."
            ],
            "source": "blocklist",
            "decided_by": "personal_blocklist",
            "verification_status": "blocked",
        }

    # 2. User's personal allowlist in local database (logged-in user override)
    if check_domain_in_list(url, allowlist_domains):
        return {
            "prediction": "benign",
            "risk_level": "safe",
            "phishing_probability": 0.0,
            "warnings": [
                "✅ Domain is on your personal allowlist."
            ],
            "source": "allowlist",
            "decided_by": "personal_allowlist",
            "verification_status": "trusted",
        }

    # 3. Pure Model-Based Verdict
    probability = float(raw_prediction.get("phishing_probability", 0.0))
    thresholds = raw_prediction.get("risk_thresholds")
    risk_level = probability_to_risk_level(probability, thresholds)
    prediction = "phishing" if risk_level == "dangerous" else "benign"

    return {
        "prediction": prediction,
        "risk_level": risk_level,
        "phishing_probability": round(probability, 6),
        "warnings": warnings,
        "source": "model",
        "decided_by": "model",
        "verification_status": "model_evaluated",
    }
