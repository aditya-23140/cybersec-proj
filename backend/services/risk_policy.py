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
