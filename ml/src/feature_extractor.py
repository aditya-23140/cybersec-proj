"""
feature_extractor.py — Shared feature module used by both training and inference.

Implements URL-observable phishing features:
   1. length_url
   2. length_hostname
   3. length_path
   4. qty_dots_url
   5. qty_hyphens_url
   6. qty_hyphens_path
   7. subdomain_count
   8. has_brand_keyword
   9. hostname_hyphen_count
  10. hostname_digit_count
  11. brand_lookalike
  12. brand_impersonation
  13. suspicious_path_keyword
  14. is_domain_ip
  15. has_obfuscation
  16. has_userinfo
  17. digit_ratio_url
  18. is_https
  19. has_punycode
  20. query_length
  21. qty_params

The model uses only URL-observable features that can be extracted identically
and deterministically at both training and inference time. Optional live
network enrichment (DNS, TLS, WHOIS, reputation) is handled by the API service.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import unquote, urlparse, urlunparse

import tldextract

logger = logging.getLogger(__name__)

# Offline TLDExtract singleton — avoids live network requests to publicsuffix.org
_offline_extract = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
)


def get_tld_extract():
    """Return the shared offline TLDExtract instance."""
    return _offline_extract


# ── Brand keyword list ────────────────────────────────────────────────────────
# Use only high-profile targeted brands; generic authentication/security terms
# like "login", "secure", "verify", "account", and "bank" belong in path/query
# features to prevent false positives on benign domains (e.g. southbankmosaics.com).
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
        "steam",
        "playstation",
        "xbox",
        "bankofamerica",
        "ledger",
        "trezor",
        "metamask",
        "github",
        "gitlab",
        "bitbucket",
        "stackoverflow",
        "reddit",
    }
)

KNOWN_OFFICIAL_DOMAINS: frozenset[str] = frozenset(
    {
        "amazon.com",
        "apple.com",
        "facebook.com",
        "google.com",
        "instagram.com",
        "linkedin.com",
        "microsoft.com",
        "netflix.com",
        "paypal.com",
        "spotify.com",
        "twitter.com",
        "discord.com",
        "wikipedia.org",
        "youtube.com",
        "ledger.com",
        "coinbase.com",
        "binance.com",
        "chase.com",
        "wellsfargo.com",
        "citi.com",
        "citibank.com",
        "adobe.com",
        "dropbox.com",
        "yahoo.com",
        "whatsapp.com",
        "telegram.org",
        "steampowered.com",
        "playstation.com",
        "xbox.com",
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "stackoverflow.com",
        "reddit.com",
    }
)

_KNOWN_BRAND_LABELS: frozenset[str] = frozenset(
    d.split(".", 1)[0] for d in KNOWN_OFFICIAL_DOMAINS
)

# ── Feature order (critical — model is trained on this exact order) ───────────
FEATURE_NAMES: list[str] = [
    "length_url",
    "length_hostname",
    "length_path",
    "qty_dots_url",
    "qty_hyphens_url",
    "qty_hyphens_path",
    "subdomain_count",
    "has_brand_keyword",
    "hostname_hyphen_count",
    "hostname_digit_count",
    "brand_lookalike",
    "brand_impersonation",
    "suspicious_path_keyword",
    "is_domain_ip",
    "has_obfuscation",
    "has_userinfo",
    "digit_ratio_url",
    "is_https",
    "has_punycode",
    "query_length",
    "qty_params",
]

# Schemes that cannot be analysed as standard URLs
_UNSUPPORTED_SCHEMES = {"javascript", "data", "file", "blob", "about", "vbscript"}

_SUSPICIOUS_PATH_KEYWORDS = frozenset(
    {
        "account",
        "billing",
        "confirm",
        "login",
        "password",
        "signin",
        "sign-in",
        "log-in",
        "update",
        "verify",
        "verification",
        "banking",
        "wallet",
        "security",
        "authenticate",
        "recovery",
        "credential",
        "suspend",
        "unlock",
    }
)

_IP_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"  # IPv4
    r"|^\[.*\]$"  # IPv6 bracket notation
)


# ─────────────────────────────────────────────────────────────────────────────
# Public data structures
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class FeatureVector:
    """Container returned by :func:`extract_features`."""

    features: list[float]  # Length == len(FEATURE_NAMES)
    feature_names: list[str]  # Always FEATURE_NAMES
    missing_features: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# URL parsing helpers
# ─────────────────────────────────────────────────────────────────────────────


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

    # Detect unsupported schemes before adding default scheme
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
    return host.lower().rstrip(".")


def _subdomain_count(host: str) -> int:
    """Count subdomain labels before the registrable domain."""
    if _IP_RE.match(host):
        return 0

    ext = _offline_extract(host)
    if not ext.domain:
        return 0
    labels = [label for label in ext.subdomain.split(".") if label]
    if labels and labels[0].lower() == "www":
        labels = labels[1:]
    return len(labels)


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


def _is_brand_lookalike(domain_label: str) -> float:
    """Detect one-edit brand lookalikes in the registrable domain label."""
    if not domain_label or domain_label in BRAND_KEYWORDS:
        return 0.0
    return float(
        any(
            len(brand) >= 4 and _edit_distance(domain_label, brand) == 1
            for brand in BRAND_KEYWORDS
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def extract_features(url: str, enable_dns: bool = False) -> FeatureVector:
    """
    Extract phishing-detection features from *url*.

    Parameters
    ----------
    url:
        Raw URL string (with or without scheme).
    enable_dns:
        If True, log warning that DNS enrichment is performed by backend API.

    Returns
    -------
    FeatureVector
        ``features`` is guaranteed to be length len(FEATURE_NAMES) in exact order.

    Raises
    ------
    ValueError
        For unparseable URLs or unsupported schemes (javascript:, data:, …).
    """
    normalised_url, parsed = _parse_url(url)
    host = _hostname(parsed)
    path = parsed.path or ""
    query = parsed.query or ""

    # Canonical host and URL strips generic 'www.' prefix for feature consistency
    canonical_host = host[4:] if (host.startswith("www.") and len(host) > 4) else host
    if parsed.netloc.lower().startswith("www."):
        canonical_netloc = parsed.netloc[4:]
        canonical_url = urlunparse(parsed._replace(netloc=canonical_netloc))
    else:
        canonical_url = normalised_url

    ext = _offline_extract(canonical_host)
    domain_label = ext.domain.lower() if ext.domain else ""
    registrable_domain = (
        f"{ext.domain}.{ext.suffix}".lower()
        if ext.domain and ext.suffix
        else canonical_host
    )

    feature_warnings: list[str] = []

    # 1. Component lengths
    length_url = float(len(canonical_url))
    length_hostname = float(len(canonical_host))
    decoded_path = unquote(path)
    length_path = float(len(decoded_path))

    # 2. Character counts
    qty_dots_url = float(canonical_url.count("."))
    qty_hyphens_url = float(canonical_url.count("-"))
    qty_hyphens_path = float(decoded_path.count("-"))

    # 3. Hostname & Subdomain characteristics
    subdomain_count = float(_subdomain_count(canonical_host))
    hostname_hyphen_count = float(canonical_host.count("-"))
    hostname_digit_count = float(sum(char.isdigit() for char in canonical_host))

    # 4. Token-based brand keyword & impersonation
    host_tokens = set(re.findall(r"[a-z0-9]+", canonical_host))
    matched_brands = host_tokens & BRAND_KEYWORDS
    has_brand_keyword = 1.0 if matched_brands else 0.0

    # Brand impersonation: brand token present in hostname, but the domain is NOT the brand's official domain
    is_official_brand = (
        domain_label in BRAND_KEYWORDS
        or registrable_domain in KNOWN_OFFICIAL_DOMAINS
    )
    brand_impersonation = 1.0 if (matched_brands and not is_official_brand) else 0.0

    # 5. Lookalike domain
    brand_lookalike = _is_brand_lookalike(domain_label)

    # 6. Sensitive keywords in path or query
    combined_path_query = f"{decoded_path} {unquote(query)}".lower()
    path_tokens = set(re.findall(r"[a-z0-9]+", combined_path_query))
    suspicious_path_keyword = 1.0 if bool(path_tokens & _SUSPICIOUS_PATH_KEYWORDS) else 0.0

    # 7. Structural anomalies
    is_domain_ip = 1.0 if bool(_IP_RE.match(canonical_host)) else 0.0
    has_obfuscation = 1.0 if ("%" in canonical_url or "\\" in canonical_url or "@" in canonical_url) else 0.0
    has_userinfo = 1.0 if (parsed.username is not None or "@" in (parsed.netloc.split(":")[0])) else 0.0
    digit_ratio_url = float(sum(char.isdigit() for char in canonical_url) / max(1, len(canonical_url)))
    is_https = 1.0 if parsed.scheme.lower() == "https" else 0.0
    has_punycode = 1.0 if ("xn--" in canonical_host) else 0.0

    # 8. Query parameters
    query_length = float(len(query))
    qty_params = float(len([p for p in query.split("&") if p])) if query else 0.0

    if enable_dns:
        feature_warnings.append(
            "DNS/WHOIS enrichment is handled by the API enrichment layer for live domain signals."
        )

    features = [
        length_url,
        length_hostname,
        length_path,
        qty_dots_url,
        qty_hyphens_url,
        qty_hyphens_path,
        subdomain_count,
        has_brand_keyword,
        hostname_hyphen_count,
        hostname_digit_count,
        brand_lookalike,
        brand_impersonation,
        suspicious_path_keyword,
        is_domain_ip,
        has_obfuscation,
        has_userinfo,
        digit_ratio_url,
        is_https,
        has_punycode,
        query_length,
        qty_params,
    ]

    assert len(features) == len(FEATURE_NAMES), (
        f"Feature count mismatch: {len(features)} != {len(FEATURE_NAMES)}"
    )

    return FeatureVector(
        features=features,
        feature_names=list(FEATURE_NAMES),
        missing_features=[],
        warnings=feature_warnings,
    )
