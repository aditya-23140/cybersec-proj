"""
reputation.py — Reputation feature extraction (Group 3).

All inputs are optional. When all are None → URL-only mode → all features NaN.
Never crashes; NaN on failure.
"""

from __future__ import annotations

import datetime
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

nan = float("nan")

# ---------------------------------------------------------------------------
# Registrar risk (heuristic mapping, no network)
# ---------------------------------------------------------------------------

_HIGH_RISK_REGISTRARS = {
    "namecheap", "porkbun", "epik", "dynadot", "reg.ru",
    "nicenic", "west263", "net-chinese", "bizcn",
}
_MEDIUM_RISK_REGISTRARS = {
    "godaddy", "networksolutions", "name.com", "enom", "tucows",
}


def _registrar_risk(registrar: str | None) -> float:
    if not registrar:
        return nan
    r = registrar.lower()
    for h in _HIGH_RISK_REGISTRARS:
        if h in r:
            return 1.0
    for m in _MEDIUM_RISK_REGISTRARS:
        if m in r:
            return 0.5
    return 0.0


# ---------------------------------------------------------------------------
# ASN risk (heuristic)
# ---------------------------------------------------------------------------

_HIGH_RISK_ASNS = {
    # Known bulletproof/abusive ASNs
    "as206070", "as49505", "as202685", "as57858",
    "as35624", "as43350", "as50304",
}
_MEDIUM_RISK_ASNS = {"as16509", "as14618", "as15169"}  # large shared clouds


def _asn_risk(asn: str | None) -> float:
    if not asn:
        return nan
    a = asn.lower().replace(" ", "")
    if a in _HIGH_RISK_ASNS:
        return 1.0
    if a in _MEDIUM_RISK_ASNS:
        return 0.5
    return 0.0


# ---------------------------------------------------------------------------
# Country risk (very rough heuristic)
# ---------------------------------------------------------------------------

_HIGH_RISK_COUNTRIES = {"ru", "cn", "kp", "ir", "ng", "ro"}
_MEDIUM_RISK_COUNTRIES = {"ua", "in", "bd", "pk", "vn", "tz"}


def _country_risk(country: str | None) -> float:
    if not country:
        return nan
    c = country.lower()
    if c in _HIGH_RISK_COUNTRIES:
        return 1.0
    if c in _MEDIUM_RISK_COUNTRIES:
        return 0.5
    return 0.0


# ---------------------------------------------------------------------------
# Tranco rank bucket
# ---------------------------------------------------------------------------

def _rank_bucket(rank: int | None) -> float:
    if rank is None:
        return 0.0  # 0 = not ranked
    if rank <= 10_000:
        return 1.0
    if rank <= 100_000:
        return 2.0
    return 3.0


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

def extract_reputation_features(
    url: str,
    *,
    whois_data: dict | None = None,
    dns_data: dict | None = None,
    tls_data: dict | None = None,
    tranco_rank: int | None = None,
    asn_data: dict | None = None,
) -> dict[str, float]:
    """
    Extract reputation features.

    When all optional args are None → URL-only mode → all features NaN.
    Never raises.

    whois_data keys (all optional):
        creation_date (str ISO8601 or datetime), registrar (str)
    dns_data keys (all optional):
        mx (list[str]), spf (str|bool), dmarc (str|bool),
        a_records (list[str]), ttl (int|list[int])
    tls_data keys (all optional):
        issuer (str), not_before (str ISO8601), not_after (str ISO8601),
        san_count (int)
    asn_data keys (all optional):
        asn (str), country (str)
    """
    result: dict[str, float] = {
        "domain_age_days":      nan,
        "registrar_risk_score": nan,
        "mx_present":           nan,
        "spf_present":          nan,
        "dmarc_present":        nan,
        "dns_ttl_min":          nan,
        "a_record_count":       nan,
        "tls_issuer_free_ca":   nan,
        "tls_age_days":         nan,
        "tls_validity_days":    nan,
        "tls_san_count":        nan,
        "tranco_rank_bucket":   nan,
        "hosting_asn_risk":     nan,
        "hosting_country_risk": nan,
    }

    # URL-only mode: all inputs are None
    all_none = (
        whois_data is None
        and dns_data is None
        and tls_data is None
        and tranco_rank is None
        and asn_data is None
    )
    if all_none:
        return result

    try:
        now = datetime.datetime.utcnow()

        # --- WHOIS ---
        if whois_data is not None:
            try:
                creation = whois_data.get("creation_date")
                if creation is not None:
                    if isinstance(creation, str):
                        # Try ISO format
                        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"):
                            try:
                                creation = datetime.datetime.strptime(creation[:19], fmt[:len(creation[:19])])
                                break
                            except ValueError:
                                continue
                    if isinstance(creation, datetime.datetime):
                        delta = now - creation
                        result["domain_age_days"] = max(0.0, float(delta.days))
                    elif isinstance(creation, datetime.date):
                        delta = now.date() - creation
                        result["domain_age_days"] = max(0.0, float(delta.days))
            except Exception as exc:
                logger.debug("whois creation_date parse error: %s", exc)

            result["registrar_risk_score"] = _registrar_risk(whois_data.get("registrar"))

        # --- DNS ---
        if dns_data is not None:
            mx = dns_data.get("mx")
            result["mx_present"] = 1.0 if (mx and len(mx) > 0) else 0.0

            spf = dns_data.get("spf")
            if spf is not None:
                result["spf_present"] = 1.0 if spf else 0.0

            dmarc = dns_data.get("dmarc")
            if dmarc is not None:
                result["dmarc_present"] = 1.0 if dmarc else 0.0

            a_records = dns_data.get("a_records", [])
            result["a_record_count"] = float(len(a_records) if a_records else 0)

            ttl = dns_data.get("ttl")
            if ttl is not None:
                if isinstance(ttl, list):
                    ttl = min(ttl) if ttl else nan
                try:
                    result["dns_ttl_min"] = float(ttl)
                except (TypeError, ValueError):
                    pass

        # --- TLS ---
        if tls_data is not None:
            issuer = tls_data.get("issuer", "")
            _FREE_CA_KEYWORDS = {"let's encrypt", "letsencrypt", "zerossl", "buypass", "sectigo free"}
            if isinstance(issuer, str):
                issuer_l = issuer.lower()
                result["tls_issuer_free_ca"] = (
                    1.0 if any(kw in issuer_l for kw in _FREE_CA_KEYWORDS) else 0.0
                )

            try:
                not_before = tls_data.get("not_before")
                not_after = tls_data.get("not_after")
                if not_before is not None:
                    if isinstance(not_before, str):
                        not_before = datetime.datetime.fromisoformat(not_before[:19])
                    result["tls_age_days"] = max(0.0, float((now - not_before).days))
                if not_after is not None and not_before is not None:
                    if isinstance(not_after, str):
                        not_after = datetime.datetime.fromisoformat(not_after[:19])
                    result["tls_validity_days"] = max(0.0, float((not_after - not_before).days))
            except Exception as exc:
                logger.debug("TLS date parse error: %s", exc)

            san_count = tls_data.get("san_count")
            if san_count is not None:
                try:
                    result["tls_san_count"] = float(san_count)
                except (TypeError, ValueError):
                    pass

        # --- Tranco ---
        result["tranco_rank_bucket"] = _rank_bucket(tranco_rank)

        # --- ASN ---
        if asn_data is not None:
            result["hosting_asn_risk"]     = _asn_risk(asn_data.get("asn"))
            result["hosting_country_risk"] = _country_risk(asn_data.get("country"))

    except Exception as exc:
        logger.warning("extract_reputation_features unexpected error: %s", exc)

    return result
