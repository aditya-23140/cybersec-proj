"""
backend/services/page_fetcher.py — Lightweight HTML fetcher for hybrid scanning.

Privacy model:
  - Fetches HTML structure only (no JS execution, no cookies sent)
  - Strips all <input> value attributes before returning to prevent accidental
    data leakage (e.g. server-prefilled username in a "remember me" field)
  - Hard cap: 300 KB returned, configurable timeout, 3 redirects max
  - Returns None on any error — caller falls back to URL-only scanning
  - Never raises; all errors are logged at DEBUG level and swallowed

Usage:
    from services.page_fetcher import fetch_page_html
    html = fetch_page_html("https://example.com")  # None on failure
"""

from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_MAX_BYTES = 300_000
_DEFAULT_TIMEOUT = 5.0
_MAX_REDIRECTS = 3

# Strip <input value="..."> to prevent leaking any user data that might
# have been pre-filled by the server (e.g. username in a "remember me" field)
_INPUT_VALUE_RE = re.compile(
    r'(<input\b[^>]*?)\bvalue\s*=\s*(?:"[^"]*"|\'[^\']*\'|\S+)',
    re.IGNORECASE,
)

# Skip obviously non-HTML content types early
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml", "text/xml", "application/xml")


def fetch_page_html(
    url: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    max_bytes: int = _MAX_BYTES,
) -> Optional[str]:
    """
    Fetch up to *max_bytes* of HTML from *url*.

    Returns the sanitized HTML string, or None if the page cannot be
    fetched cleanly (timeout, connection error, non-HTML response, etc.).
    Never raises.
    """
    try:
        import httpx
    except ImportError:
        logger.warning("page_fetcher: httpx not installed — cannot fetch page HTML")
        return None

    try:
        with httpx.Client(
            follow_redirects=True,
            max_redirects=_MAX_REDIRECTS,
            timeout=timeout,
            headers={
                "User-Agent": _UA,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
            verify=False,  # Don't block phishing pages with self-signed certs
        ) as client:
            with client.stream("GET", url) as response:
                # Only parse HTML/XML responses
                ct = response.headers.get("content-type", "").lower()
                if not any(t in ct for t in _HTML_CONTENT_TYPES):
                    logger.debug(
                        "page_fetcher: skipping non-HTML content-type %r for %s", ct, url
                    )
                    return None

                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes(chunk_size=8192):
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= max_bytes:
                        break

                raw = b"".join(chunks)[:max_bytes]

        # Decode — try UTF-8 first, fall back to latin-1
        try:
            html = raw.decode("utf-8", errors="replace")
        except Exception:
            html = raw.decode("latin-1", errors="replace")

        # Sanitize: strip input field values to prevent accidental data leakage
        html = _INPUT_VALUE_RE.sub(r"\1", html)

        logger.debug(
            "page_fetcher: fetched %d bytes from %s", len(html), url
        )
        return html

    except Exception as exc:
        logger.debug(
            "page_fetcher: could not fetch %s — %s: %s",
            url, type(exc).__name__, exc,
        )
        return None
