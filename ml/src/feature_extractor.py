"""
feature_extractor.py — Shared feature module used by both training and inference.

Implements the 8 features from Misiek & Hyla (2026):
  1. length_url
  2. qty_dots_url
  3. qty_hyphens_path
  4. subdomain_count
  5. has_brand_keyword
  6. qty_nameservers
  7. is_spf_domain
  8. time_domain_activation
  9. hostname_hyphen_count
 10. hostname_digit_count
 11. brand_lookalike
 12. suspicious_path_keyword

Network-dependent features (qty_nameservers, is_spf_domain, time_domain_activation)
are only fetched when enable_dns=True. Otherwise, fallback constants are used.

NEVER makes HTTP requests to the target URL — only DNS/WHOIS queries when
enable_dns=True.
"""

from __future__ import annotations

import logging
import re
import warnings
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, unquote

logger = logging.getLogger(__name__)

# ── Brand keyword list ────────────────────────────────────────────────────────
BRAND_KEYWORDS: frozenset[str] = frozenset(
    {
        "paypal",
        "apple",
        "microsoft",
        "google",
        "amazon",
        "facebook",
        "instagram",
        "twitter",
        "netflix",
        "ebay",
        "bank",
        "secure",
        "account",
        "login",
        "signin",
        "verify",
        "update",
        "confirm",
        "wallet",
        "chase",
        "wellsfargo",
        "citibank",
        "hsbc",
        "barclays",
        "linkedin",
        "dropbox",
        "spotify",
        "adobe",
        "office365",
        "outlook",
        "gmail",
        "yahoo",
        "whatsapp",
        "telegram",
        "coinbase",
        "binance",
        "blockchain",
        "crypto",
        "nft",
        "steam",
        "playstation",
        "xbox",
    }
)

# ── Feature order (critical — model was trained on this exact order) ──────────
FEATURE_NAMES: list[str] = [
    "length_url",
    "qty_dots_url",
    "qty_hyphens_path",
    "subdomain_count",
    "has_brand_keyword",
    "qty_nameservers",
    "is_spf_domain",
    "time_domain_activation",
    "hostname_hyphen_count",
    "hostname_digit_count",
    "brand_lookalike",
    "suspicious_path_keyword",
]

# ── Fallback constants for network-required features ─────────────────────────
# These are overridden by training-set medians stored in feature_schema.json;
# the module-level defaults are used before the schema is available.
_FALLBACK_QTY_NAMESERVERS: float = 0.0  # replaced by median at training time
_FALLBACK_IS_SPF_DOMAIN: float = 0.0  # conservative: missing SPF ≈ suspicious
_FALLBACK_TIME_DOMAIN_ACTIVATION: float = -1.0  # sentinel for "unknown"

# Schemes that cannot be analysed as URLs
_UNSUPPORTED_SCHEMES = {"javascript", "data", "file", "blob", "about"}
_SUSPICIOUS_PATH_KEYWORDS = frozenset(
    {"account", "billing", "confirm", "login", "password", "signin", "update", "verify"}
)


# ─────────────────────────────────────────────────────────────────────────────
# Public data structures
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class FeatureVector:
    """Container returned by :func:`extract_features`."""

    features: list[float]  # Length == len(FEATURE_NAMES)
    feature_names: list[str]  # Always FEATURE_NAMES
    missing_features: list[str]  # Names of features using fallback values
    warnings: list[str]  # Human-readable notes for the caller


# ─────────────────────────────────────────────────────────────────────────────
# URL parsing helpers
# ─────────────────────────────────────────────────────────────────────────────

_IP_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"  # IPv4
    r"|^\[.*\]$"  # IPv6 bracket notation
)


def _parse_url(url: str) -> tuple[str, "urlparse"]:
    """
    Parse *url* and return ``(normalised_url, parsed)``.

    Raises
    ------
    ValueError
        If the scheme is unsupported (javascript:, data:, …) or the URL
        cannot be meaningfully parsed.
    """
    url = url.strip()
    if not url:
        raise ValueError("Empty URL")

    # Detect unsupported schemes before adding a default one
    lower = url.lower()
    for scheme in _UNSUPPORTED_SCHEMES:
        if lower.startswith(scheme + ":"):
            raise ValueError(f"Unsupported URL scheme: {scheme!r}")

    # Add scheme if missing so urlparse works correctly
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    if scheme in _UNSUPPORTED_SCHEMES:
        raise ValueError(f"Unsupported URL scheme: {scheme!r}")

    if not parsed.netloc:
        raise ValueError(f"Cannot parse netloc from URL: {url!r}")

    return url, parsed


def _hostname(parsed: "urlparse") -> str:
    """Return the hostname portion, stripping port and decoding percent-encoding."""
    host = parsed.hostname or ""
    try:
        host = unquote(host)
    except Exception:
        pass
    # Normalise IDN to ASCII (punycode) for consistent processing
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError, UnicodeEncodeError):
        pass
    return host.lower()


def _subdomain_count(host: str) -> int:
    """
    Count subdomain labels (everything left of the registrable domain).

    Uses a simple heuristic: number of dots in the hostname minus the number
    of dots in the effective TLD (1 for .com, 2 for .co.uk, etc.).

    For IP addresses, returns 0.
    """
    if _IP_RE.match(host):
        return 0

    try:
        import tldextract  # lazy import — only needed at feature-extraction time

        ext = tldextract.extract(host)
        if not ext.domain:
            return 0
        # subdomain labels = number of dot-separated parts in ext.subdomain
        return len(ext.subdomain.split(".")) if ext.subdomain else 0
    except ImportError:
        # Fallback: very naive — dots in hostname minus 1 (for domain.tld)
        parts = host.rstrip(".").split(".")
        return max(0, len(parts) - 2)


def _edit_distance(left: str, right: str) -> int:
    """Return Levenshtein distance without adding a runtime dependency."""
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[j] + 1,
                    previous[j - 1] + (left_char != right_char),
                )
            )
        previous = current
    return previous[-1]


def _is_brand_lookalike(host: str) -> float:
    """Detect one-edit brand lookalikes in the registrable domain label."""
    try:
        import tldextract

        domain = tldextract.extract(host).domain
    except ImportError:
        domain = host.rsplit(".", 1)[0].split(".")[-1]

    if not domain or domain in BRAND_KEYWORDS:
        return 0.0
    return float(
        any(
            len(brand) >= 5 and _edit_distance(domain, brand) == 1
            for brand in BRAND_KEYWORDS
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
# DNS / WHOIS helpers (only called when enable_dns=True)
# ─────────────────────────────────────────────────────────────────────────────


def _count_nameservers(domain: str) -> tuple[float, Optional[str]]:
    """Return (count, error_message_or_None)."""
    try:
        import dns.resolver  # dnspython

        answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        return float(len(answers)), None
    except Exception as exc:
        return _FALLBACK_QTY_NAMESERVERS, str(exc)


def _has_spf_record(domain: str) -> tuple[float, Optional[str]]:
    """Return (1.0 if SPF found else 0.0, error_or_None)."""
    try:
        import dns.resolver

        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=spf1"):
                return 1.0, None
        return 0.0, None
    except Exception as exc:
        return _FALLBACK_IS_SPF_DOMAIN, str(exc)


def _domain_age_days(domain: str) -> tuple[float, Optional[str]]:
    """Return (age_in_days, error_or_None). -1.0 if unknown."""
    try:
        import whois  # python-whois
        from datetime import datetime, timezone

        info = whois.whois(domain)
        creation = info.creation_date
        if creation is None:
            return _FALLBACK_TIME_DOMAIN_ACTIVATION, "No creation date in WHOIS"
        # creation_date can be a list
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            now = datetime.now(timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age = (now - creation).days
            return float(age), None
        return _FALLBACK_TIME_DOMAIN_ACTIVATION, "Unexpected creation_date type"
    except Exception as exc:
        return _FALLBACK_TIME_DOMAIN_ACTIVATION, str(exc)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def extract_features(url: str, enable_dns: bool = False) -> FeatureVector:
    """
    Extract the 8 phishing-detection features from *url*.

    Parameters
    ----------
    url:
        Raw URL string (with or without scheme).
    enable_dns:
        If ``True``, perform DNS NS/TXT lookups and a WHOIS query to populate
        network-dependent features. If ``False`` (default), those features
        use their fallback values immediately without any network call.

    Returns
    -------
    FeatureVector
        ``features`` is guaranteed to be length 8 in ``FEATURE_NAMES`` order.

    Raises
    ------
    ValueError
        For unparseable URLs or unsupported schemes (javascript:, data:, …).
    """
    normalised_url, parsed = _parse_url(url)
    host = _hostname(parsed)
    path = parsed.path or ""

    missing: list[str] = []
    feature_warnings: list[str] = []

    # ── Feature 1: length_url ─────────────────────────────────────────────
    length_url = float(len(normalised_url))

    # ── Feature 2: qty_dots_url ───────────────────────────────────────────
    qty_dots_url = float(normalised_url.count("."))

    # ── Feature 3: qty_hyphens_path ───────────────────────────────────────
    decoded_path = unquote(path)
    qty_hyphens_path = float(decoded_path.count("-"))

    # ── Feature 4: subdomain_count ────────────────────────────────────────
    subdomain_count = float(_subdomain_count(host))

    # ── Feature 5: has_brand_keyword ──────────────────────────────────────
    host_lower = host.lower()
    has_brand = any(kw in host_lower for kw in BRAND_KEYWORDS)
    has_brand_keyword = 1.0 if has_brand else 0.0

    # ── Features 6–8: network-dependent ──────────────────────────────────
    if enable_dns:
        # Determine the registrable domain for DNS queries
        try:
            import tldextract

            ext = tldextract.extract(host)
            query_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else host
        except ImportError:
            query_domain = host

        qty_ns, ns_err = _count_nameservers(query_domain)
        if ns_err:
            missing.append("qty_nameservers")
            feature_warnings.append(f"qty_nameservers fallback ({ns_err})")

        is_spf, spf_err = _has_spf_record(query_domain)
        if spf_err:
            missing.append("is_spf_domain")
            feature_warnings.append(f"is_spf_domain fallback ({spf_err})")

        age_days, age_err = _domain_age_days(query_domain)
        if age_err:
            missing.append("time_domain_activation")
            feature_warnings.append(f"time_domain_activation fallback ({age_err})")
    else:
        qty_ns = _FALLBACK_QTY_NAMESERVERS
        is_spf = _FALLBACK_IS_SPF_DOMAIN
        age_days = _FALLBACK_TIME_DOMAIN_ACTIVATION
        missing.extend(["qty_nameservers", "is_spf_domain", "time_domain_activation"])
        feature_warnings.append(
            "Network features are using fallback values (enable_dns=False). "
            "Pass enable_dns=True for live DNS/WHOIS enrichment."
        )

    hostname_hyphen_count = float(host.count("-"))
    hostname_digit_count = float(sum(char.isdigit() for char in host))
    brand_lookalike = _is_brand_lookalike(host)
    path_tokens = set(re.findall(r"[a-z0-9]+", f"{decoded_path} {parsed.query}".lower()))
    suspicious_path_keyword = float(bool(path_tokens & _SUSPICIOUS_PATH_KEYWORDS))

    features = [
        length_url,
        qty_dots_url,
        qty_hyphens_path,
        subdomain_count,
        has_brand_keyword,
        qty_ns,
        is_spf,
        age_days,
        hostname_hyphen_count,
        hostname_digit_count,
        brand_lookalike,
        suspicious_path_keyword,
    ]

    assert len(features) == len(FEATURE_NAMES), (
        f"Feature count mismatch: {len(features)} != {len(FEATURE_NAMES)}"
    )

    return FeatureVector(
        features=features,
        feature_names=list(FEATURE_NAMES),
        missing_features=missing,
        warnings=feature_warnings,
    )


def set_network_fallbacks(median_nameservers: float) -> None:
    """
    Update the module-level fallback for ``qty_nameservers`` to the training-
    set median. Called by the training pipeline after computing the median so
    that inference uses a data-informed default.
    """
    global _FALLBACK_QTY_NAMESERVERS
    _FALLBACK_QTY_NAMESERVERS = median_nameservers
