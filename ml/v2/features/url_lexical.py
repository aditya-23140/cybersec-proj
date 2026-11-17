"""
url_lexical.py — URL lexical feature extraction (Group 1).

Rules:
- Pure function: takes url str, returns dict[str, float]
- Never crashes: all computation in try/except, NaN on failure
- No network calls
- Deterministic
- No scheme (http/https) features
"""

from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from urllib.parse import urlparse, unquote

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits) of string s."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def _is_ip_address(hostname: str) -> bool:
    """Return True if hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False
    # Strip brackets for IPv6
    h = hostname.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _extract_registered_domain(hostname: str) -> str:
    """
    Naive registered-domain extractor (no tldextract).
    Returns 'second-level.tld' for typical hostnames.
    Falls back gracefully for IPs and edge cases.
    """
    if not hostname:
        return ""
    if _is_ip_address(hostname):
        return hostname
    labels = hostname.lower().split(".")
    if len(labels) < 2:
        return hostname.lower()
    # Known multi-part TLDs (best-effort small list)
    _MULTI_TLDS = {
        "co.uk", "co.in", "co.jp", "co.nz", "co.za", "co.au",
        "com.au", "com.br", "com.mx", "com.ar",
        "net.au", "org.uk", "me.uk", "ac.uk", "gov.uk",
        "web.app", "firebaseapp.com", "github.io", "netlify.app",
        "pages.dev", "glitch.me", "myshopify.com", "wordpress.com",
        "blogspot.com", "weebly.com", "weeblysite.com",
    }
    if len(labels) >= 3:
        two_part = ".".join(labels[-2:])
        three_part = ".".join(labels[-3:])
        if three_part in _MULTI_TLDS:
            # registered domain spans the last 3 labels; take 4-th from end
            if len(labels) >= 4:
                return ".".join(labels[-4:])
            return three_part
        if two_part in _MULTI_TLDS:
            if len(labels) >= 3:
                return ".".join(labels[-3:])
            return two_part
    return ".".join(labels[-2:])


# ---------------------------------------------------------------------------
# TLD risk map
# ---------------------------------------------------------------------------

_HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".club", ".online",
}
_MEDIUM_RISK_TLDS = {".info", ".biz", ".cc"}


def _tld_risk(hostname: str) -> float:
    if not hostname or _is_ip_address(hostname):
        return 0.0
    labels = hostname.lower().split(".")
    tld = "." + labels[-1] if labels else ""
    if tld in _HIGH_RISK_TLDS:
        return 1.0
    if tld in _MEDIUM_RISK_TLDS:
        return 0.5
    return 0.0


# ---------------------------------------------------------------------------
# URL shortener / shared-hosting registries
# ---------------------------------------------------------------------------

_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.io",
    "tiny.cc", "is.gd", "buff.ly", "adf.ly", "rb.gy", "cutt.ly",
    "shorturl.at", "tiny.one", "shrinkme.io", "clk.sh", "bl.ink",
    "dub.sh", "url.ie", "v.gd", "0cn.net", "hyperurl.co",
}

_SHARED_HOSTING_DOMAINS = {
    "web.app", "firebaseapp.com", "weeblysite.com", "weebly.com",
    "github.io", "netlify.app", "pages.dev", "glitch.me",
    "myshopify.com", "wordpress.com", "blogspot.com",
    "azurewebsites.net", "herokuapp.com", "vercel.app",
    "surge.sh", "carrd.co", "wixsite.com", "squarespace.com",
    "000webhostapp.com", "infinityfreeapp.com",
}


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

def extract_url_lexical(url: str) -> dict[str, float]:
    """
    Extract URL lexical features from *url*.

    Returns dict[str, float] with NaN for any feature that cannot be computed.
    Never raises.
    """
    nan = float("nan")
    result: dict[str, float] = {
        "url_length":            nan,
        "hostname_length":       nan,
        "path_length":           nan,
        "query_length":          nan,
        "fragment_length":       nan,
        "url_entropy":           nan,
        "hostname_entropy":      nan,
        "path_entropy":          nan,
        "digit_ratio_url":       nan,
        "letter_ratio_url":      nan,
        "special_char_count_url":nan,
        "subdomain_depth":       nan,
        "tld_risk_score":        nan,
        "has_ip_host":           nan,
        "has_userinfo":          nan,
        "has_punycode":          nan,
        "idn_homograph_score":   nan,
        "shortener_flag":        nan,
        "shared_hosting_flag":   nan,
        "qty_dots_url":          nan,
        "qty_hyphens_url":       nan,
        "qty_at_url":            nan,
        "path_token_count":      nan,
        "path_depth":            nan,
    }

    try:
        if url is None:
            raise ValueError("url is None")
        url = str(url)

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        # Basic lengths
        result["url_length"]       = float(len(url))
        result["hostname_length"]  = float(len(hostname))
        result["path_length"]      = float(len(parsed.path))
        result["query_length"]     = float(len(parsed.query))
        result["fragment_length"]  = float(len(parsed.fragment))

        # Entropy
        result["url_entropy"]      = _shannon_entropy(url)
        result["hostname_entropy"] = _shannon_entropy(hostname)
        result["path_entropy"]     = _shannon_entropy(parsed.path)

        # Character ratios / counts
        total_chars = len(url)
        if total_chars > 0:
            result["digit_ratio_url"]  = sum(c.isdigit() for c in url) / total_chars
            result["letter_ratio_url"] = sum(c.isalpha() for c in url) / total_chars
        else:
            result["digit_ratio_url"]  = 0.0
            result["letter_ratio_url"] = 0.0

        # Special char: non-alphanum, non-dot, non-hyphen
        result["special_char_count_url"] = float(
            sum(1 for c in url if not c.isalnum() and c not in (".", "-"))
        )

        # Subdomain depth: labels - 2, min 0; IP → 0
        if _is_ip_address(hostname):
            result["subdomain_depth"] = 0.0
        else:
            labels = [lb for lb in hostname.split(".") if lb]
            depth = max(0, len(labels) - 2)
            result["subdomain_depth"] = float(depth)

        # TLD risk
        result["tld_risk_score"] = _tld_risk(hostname)

        # IP host
        result["has_ip_host"] = 1.0 if _is_ip_address(hostname) else 0.0

        # Userinfo (@ in netloc)
        result["has_userinfo"] = 1.0 if "@" in (parsed.netloc or "") else 0.0

        # Punycode
        result["has_punycode"] = 1.0 if "xn--" in hostname else 0.0

        # IDN homograph score: ratio of non-ASCII chars in decoded hostname
        try:
            decoded_hostname = hostname.encode("ascii").decode("ascii")
            result["idn_homograph_score"] = 0.0
        except UnicodeEncodeError:
            # hostname has non-ASCII chars
            non_ascii = sum(1 for c in hostname if ord(c) > 127)
            result["idn_homograph_score"] = non_ascii / len(hostname) if hostname else 0.0

        # Shortener flag: registered domain in shortener set
        reg_domain = _extract_registered_domain(hostname)
        result["shortener_flag"] = 1.0 if (
            reg_domain in _SHORTENER_DOMAINS
            or any(hostname == d or hostname.endswith("." + d) for d in _SHORTENER_DOMAINS)
        ) else 0.0

        # Shared hosting flag: hostname or registered domain matches shared hosting
        result["shared_hosting_flag"] = 1.0 if (
            reg_domain in _SHARED_HOSTING_DOMAINS
            or any(hostname == d or hostname.endswith("." + d) for d in _SHARED_HOSTING_DOMAINS)
        ) else 0.0

        # Count-based
        result["qty_dots_url"]    = float(url.count("."))
        result["qty_hyphens_url"] = float(url.count("-"))
        result["qty_at_url"]      = float(url.count("@"))

        # Path tokens
        path_segments = [s for s in parsed.path.split("/") if s]
        result["path_token_count"] = float(len(path_segments))
        result["path_depth"]       = float(len(path_segments))  # same metric

    except Exception:
        pass  # return whatever was set so far, rest remain NaN

    return result
