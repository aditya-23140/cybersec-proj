"""
redirect.py — Redirect/behaviour feature extraction (Group 5).

Never crashes; NaN on failure.
When redirect_history and final_url are both None → all NaN.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from .url_lexical import _extract_registered_domain, _SHORTENER_DOMAINS

logger = logging.getLogger(__name__)

nan = float("nan")


def _get_reg_domain(url: str) -> str:
    try:
        hostname = (urlparse(url).hostname or "").lower()
        return _extract_registered_domain(hostname)
    except Exception:
        return ""


def extract_redirect_features(
    url: str,
    *,
    redirect_history: list[str] | None = None,
    final_url: str | None = None,
) -> dict[str, float]:
    """
    Extract redirect/behaviour features.

    Args:
        url: Original requested URL.
        redirect_history: Ordered list of intermediate URLs (not including url or final_url).
        final_url: The final URL after all redirects.

    Returns dict[str, float] with NaN for unavailable features.
    Never raises.
    """
    result: dict[str, float] = {
        "redirect_count":        nan,
        "cross_domain_redirect": nan,
        "final_domain_changed":  nan,
        "shortener_expanded":    nan,
        "redirect_chain_length": nan,
    }

    if redirect_history is None and final_url is None:
        return result

    try:
        history = list(redirect_history) if redirect_history is not None else []
        effective_final = final_url if final_url is not None else (history[-1] if history else url)

        # redirect_count: number of intermediate hops
        result["redirect_count"] = float(len(history))

        # redirect_chain_length: total chain including start and final
        result["redirect_chain_length"] = float(len(history) + 1)

        # Domains
        origin_domain = _get_reg_domain(url)
        final_domain = _get_reg_domain(effective_final)

        # final_domain_changed: 1 if final != origin
        result["final_domain_changed"] = (
            1.0 if final_domain and final_domain != origin_domain else 0.0
        )

        # cross_domain_redirect: any hop changes registered domain
        all_urls = [url] + history + [effective_final]
        domains = [_get_reg_domain(u) for u in all_urls]
        unique_domains = set(d for d in domains if d)
        result["cross_domain_redirect"] = (
            1.0 if len(unique_domains) > 1 else 0.0
        )

        # shortener_expanded: original URL was a known shortener
        result["shortener_expanded"] = (
            1.0 if origin_domain in _SHORTENER_DOMAINS else 0.0
        )

    except Exception as exc:
        logger.warning("extract_redirect_features error: %s", exc)

    return result
