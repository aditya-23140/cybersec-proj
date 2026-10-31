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

    if signals.get("known_official_domain"):
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

    # ------------------------------------------------------------------ #
    # 2. Resolve prediction and probability from model output
    # ------------------------------------------------------------------ #
    probability: float = float(raw_prediction.get("phishing_probability", 0.0))
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
