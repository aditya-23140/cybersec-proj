"""
brand.py — Brand/impersonation feature extraction (Group 2).

Rules:
- Pure function; no network calls
- Never crashes; NaN on failure
- Deterministic
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .url_lexical import _extract_registered_domain, _is_ip_address

# ---------------------------------------------------------------------------
# Brand registry: keyword → registered domain
# ---------------------------------------------------------------------------

BRAND_DOMAINS: dict[str, str] = {
    "google":       "google.com",
    "facebook":     "facebook.com",
    "microsoft":    "microsoft.com",
    "apple":        "apple.com",
    "amazon":       "amazon.com",
    "paypal":       "paypal.com",
    "netflix":      "netflix.com",
    "instagram":    "instagram.com",
    "twitter":      "twitter.com",
    "linkedin":     "linkedin.com",
    "ebay":         "ebay.com",
    "wellsfargo":   "wellsfargo.com",
    "bankofamerica":"bankofamerica.com",
    "chase":        "chase.com",
    "citibank":     "citibank.com",
    "yahoo":        "yahoo.com",
    "dropbox":      "dropbox.com",
    "github":       "github.com",
    "adobe":        "adobe.com",
    "office365":    "office.com",
    "office":       "office.com",
    "outlook":      "live.com",
    "hotmail":      "live.com",
    "live":         "live.com",
    "icloud":       "icloud.com",
    "spotify":      "spotify.com",
    "steam":        "steampowered.com",
    "discord":      "discord.com",
    "twitch":       "twitch.tv",
    "tiktok":       "tiktok.com",
}

# All registered domains of known brands (for exact match)
_BRAND_REG_DOMAINS: set[str] = set(BRAND_DOMAINS.values())
# All brand keywords
_BRAND_KEYWORDS: list[str] = list(BRAND_DOMAINS.keys())

# Default fallback Tranco-like top-50 popular domains for edit-distance comparison
_DEFAULT_TRANCO: list[str] = [
    "google.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "netflix.com", "instagram.com", "twitter.com", "linkedin.com",
    "ebay.com", "wellsfargo.com", "bankofamerica.com", "chase.com", "citibank.com",
    "yahoo.com", "dropbox.com", "github.com", "adobe.com", "office.com",
    "youtube.com", "reddit.com", "wikipedia.org", "baidu.com", "yandex.ru",
    "qq.com", "taobao.com", "tmall.com", "jd.com", "weibo.com",
    "zoom.us", "salesforce.com", "shopify.com", "stripe.com", "twilio.com",
    "cloudflare.com", "aws.amazon.com", "azure.microsoft.com", "icloud.com",
    "spotify.com", "steampowered.com", "discord.com", "twitch.tv", "tiktok.com",
    "nytimes.com", "bbc.com", "cnn.com", "medium.com", "wordpress.com",
]

# ---------------------------------------------------------------------------
# Homoglyph map
# ---------------------------------------------------------------------------

# Cyrillic / lookalike substitutions (key=lookalike char, value=ASCII equiv)
_HOMOGLYPH_MAP: dict[str, str] = {
    "0": "o",
    "1": "l",
    "5": "s",
    "@": "a",
    # Cyrillic confusables (Unicode)
    "\u043e": "o",   # о → o
    "\u0430": "a",   # а → a
    "\u0435": "e",   # е → e
    "\u0441": "c",   # с → c
    "\u0440": "p",   # р → p
    "\u0445": "x",   # х → x
    "\u0456": "i",   # і → i
    "\u0458": "j",   # ј → j
    # Multi-char substitutions handled separately
}

# Multi-char homoglyphs: check presence in hostname
_MULTI_HOMOGLYPHS: dict[str, str] = {
    "vv": "w",
    "rn": "m",
    "cl": "d",
    "li": "h",
}


# ---------------------------------------------------------------------------
# Levenshtein distance (pure Python, no external deps)
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Standard Levenshtein distance between strings a and b."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    la, lb = len(a), len(b)
    # Keep two rows
    prev = list(range(lb + 1))
    curr = [0] * (lb + 1)
    for i in range(1, la + 1):
        curr[0] = i
        for j in range(1, lb + 1):
            if a[i - 1] == b[j - 1]:
                curr[j] = prev[j - 1]
            else:
                curr[j] = 1 + min(prev[j], curr[j - 1], prev[j - 1])
        prev, curr = curr, prev
    return prev[lb]


def _normalized_edit_distance(a: str, b: str, cap: int = 10) -> float:
    """
    Returns 0.0 (identical) to 1.0 (far apart / safe).
    Raw distance is capped at `cap` then divided by cap.
    """
    dist = min(_levenshtein(a, b), cap)
    return dist / cap


def _brand_edit_distance_min(reg_domain: str, brand_domains: list[str]) -> float:
    """
    Returns minimum normalized Levenshtein distance from reg_domain to any
    brand domain in the list (using just the SLD part, e.g. 'paypal' vs 'paypal').
    """
    if not reg_domain or not brand_domains:
        return 1.0
    # Compare just the name without TLD to allow cross-TLD typosquats
    def _sld(d: str) -> str:
        return d.split(".")[0] if "." in d else d

    sld_target = _sld(reg_domain)
    min_dist = 1.0
    for bd in brand_domains:
        sld_b = _sld(bd)
        dist = _normalized_edit_distance(sld_target, sld_b)
        if dist < min_dist:
            min_dist = dist
    return min_dist


# ---------------------------------------------------------------------------
# Homoglyph score
# ---------------------------------------------------------------------------

def _homoglyph_score(hostname: str) -> float:
    """
    Ratio of chars in hostname that are homoglyphs (after replacing them
    the string would look like a known brand).
    """
    if not hostname:
        return 0.0
    count = 0
    for ch in hostname:
        if ch in _HOMOGLYPH_MAP:
            count += 1
    # Also check for multi-char patterns
    for pattern in _MULTI_HOMOGLYPHS:
        count += hostname.count(pattern)
    total = len(hostname)
    return min(1.0, count / total) if total > 0 else 0.0


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

def extract_brand_features(
    url: str,
    tranco_domains: list[str] | None = None,
    *,
    page_title: str | None = None,
    og_site_name: str | None = None,
) -> dict[str, float]:
    """
    Extract brand/impersonation features from *url*.

    Args:
        url: The URL to analyze.
        tranco_domains: Optional list of registered domains (Tranco top-N) for
            edit-distance comparison. Falls back to built-in list when None.
        page_title: Optional page <title> text (required for some features).
        og_site_name: Optional og:site_name content (required for some features).

    Returns dict[str, float] with NaN for unavailable features.
    Never raises.
    """
    nan = float("nan")
    result: dict[str, float] = {
        "brand_edit_distance_min":          nan,
        "brand_homoglyph_score":            nan,
        "brand_keyword_in_subdomain":       nan,
        "brand_keyword_in_path":            nan,
        "page_claimed_brand_mismatch":      nan,
        "known_brand_in_title":             nan,
        "known_brand_in_og":                nan,
        "registered_domain_matches_brand":  nan,
    }

    try:
        if url is None:
            raise ValueError("url is None")
        url = str(url)

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()

        # Registered domain and subdomain
        reg_domain = _extract_registered_domain(hostname)
        # Subdomain labels (everything before registered domain)
        if reg_domain and hostname.endswith(reg_domain) and hostname != reg_domain:
            subdomain_part = hostname[: len(hostname) - len(reg_domain)].strip(".")
        else:
            subdomain_part = ""
        subdomain_labels = [lb for lb in subdomain_part.split(".") if lb]

        # Brand list for edit distance
        brand_list = tranco_domains if tranco_domains is not None else _DEFAULT_TRANCO

        # 1. Minimum edit distance
        result["brand_edit_distance_min"] = _brand_edit_distance_min(reg_domain, brand_list)

        # 2. Homoglyph score (on full hostname)
        result["brand_homoglyph_score"] = _homoglyph_score(hostname)

        # 3. Brand keyword in subdomain
        keyword_in_sub = 0.0
        for kw in _BRAND_KEYWORDS:
            if any(kw in label for label in subdomain_labels):
                keyword_in_sub = 1.0
                break
        result["brand_keyword_in_subdomain"] = keyword_in_sub

        # 4. Brand keyword in path
        keyword_in_path = 0.0
        for kw in _BRAND_KEYWORDS:
            if kw in path:
                keyword_in_path = 1.0
                break
        result["brand_keyword_in_path"] = keyword_in_path

        # 5. registered_domain_matches_brand: exact match to known brand registered domain
        result["registered_domain_matches_brand"] = (
            1.0 if reg_domain in _BRAND_REG_DOMAINS else 0.0
        )

        # 6–8. Features requiring optional page data
        if page_title is not None:
            title_lower = page_title.lower()
            # known_brand_in_title: any brand keyword in page title
            result["known_brand_in_title"] = (
                1.0 if any(kw in title_lower for kw in _BRAND_KEYWORDS) else 0.0
            )
            # page_claimed_brand_mismatch:
            # True if page title claims a brand but reg domain != that brand's domain
            claimed_brand = None
            for kw, bd in BRAND_DOMAINS.items():
                if kw in title_lower:
                    claimed_brand = bd
                    break
            if claimed_brand is not None:
                result["page_claimed_brand_mismatch"] = (
                    0.0 if reg_domain == claimed_brand else 1.0
                )
            else:
                result["page_claimed_brand_mismatch"] = 0.0
        # else page_claimed_brand_mismatch and known_brand_in_title stay NaN

        if og_site_name is not None:
            og_lower = og_site_name.lower()
            result["known_brand_in_og"] = (
                1.0 if any(kw in og_lower for kw in _BRAND_KEYWORDS) else 0.0
            )
        # else known_brand_in_og stays NaN

    except Exception:
        pass  # return whatever was set so far

    return result
