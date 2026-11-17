"""
backend/services/page_fetcher.py — Lightweight, SSRF-hardened HTML fetcher for hybrid scanning.

Privacy & Security model:
  - Allowed schemes: http, https only
  - Hostname resolved before connection; rejects loopback, RFC 1918 private,
    link-local, cloud metadata (169.254.169.254), multicast, reserved, unspecified,
    and IPv4-mapped IPv6 variants across ALL resolved addresses.
  - TCP connection is pinned to the validated IP to prevent DNS rebinding.
  - TLS verification is strictly enabled (verify=True) with SNI and hostname checks
    pinned to the original domain name.
  - Automatic redirects disabled; followed manually up to 3 hops with full re-validation.
  - Strips all <input> value attributes before returning to prevent accidental data leakage.
  - Rejects non-HTML content types.
  - Cap: 300 KB max bytes, configurable timeout.
  - Returns None on any validation failure or error; never raises.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from typing import Optional
from urllib.parse import urljoin, urlparse

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

# Only accept HTML/XML content types
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml", "text/xml", "application/xml")


def is_disallowed_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if IP is loopback, private, link-local, multicast, reserved, or unspecified."""
    # Check for IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_and_validate_hostname(hostname: str, port: int) -> tuple[bool, list[str]]:
    """
    Resolve *hostname* via DNS and ensure ALL returned IP addresses are public.
    Returns (True, [validated_ips]) if all IPs are safe, or (False, []) if any IP is disallowed.
    """
    # 1. Direct IP address literal check
    try:
        ip_obj = ipaddress.ip_address(hostname.strip("[]"))
        if is_disallowed_ip(ip_obj):
            logger.debug("page_fetcher: IP literal %s is disallowed", hostname)
            return False, []
        return True, [str(ip_obj)]
    except ValueError:
        pass

    # 2. Hostname DNS resolution
    try:
        addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, socket.herror, Exception) as exc:
        logger.debug("page_fetcher: DNS resolution failed for %s: %s", hostname, exc)
        return False, []

    if not addr_info:
        return False, []

    validated_ips: list[str] = []
    for entry in addr_info:
        ip_str = entry[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if is_disallowed_ip(ip_obj):
                logger.debug("page_fetcher: resolved IP %s for %s is disallowed", ip_str, hostname)
                return False, []
            validated_ips.append(str(ip_obj))
        except ValueError:
            return False, []

    return True, validated_ips


def fetch_page_html(
    url: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    max_bytes: int = _MAX_BYTES,
) -> Optional[str]:
    """
    Fetch up to *max_bytes* of HTML from *url* with SSRF prevention.

    Returns the sanitized HTML string, or None if the page cannot be
    fetched cleanly (validation failed, timeout, non-HTML response, etc.).
    Never raises.
    """
    try:
        import httpcore
        import httpx
    except ImportError:
        logger.warning("page_fetcher: httpx or httpcore not installed — cannot fetch page HTML")
        return None

    class _PinnedIPBackend(httpcore.NetworkBackend):
        """NetworkBackend that forces TCP connection to a pre-validated IP to prevent DNS rebinding."""

        def __init__(self, pinned_ip: str, base_backend: httpcore.NetworkBackend):
            self._pinned_ip = pinned_ip
            self._base = base_backend

        def connect_tcp(
            self,
            host: str,
            port: int,
            timeout: float | None = None,
            local_address: str | None = None,
            socket_options: any = None,
        ) -> httpcore.NetworkStream:
            return self._base.connect_tcp(
                host=self._pinned_ip,
                port=port,
                timeout=timeout,
                local_address=local_address,
                socket_options=socket_options,
            )

    try:
        current_url = url
        raw: bytes = b""

        for _ in range(_MAX_REDIRECTS + 1):
            parsed = urlparse(current_url)
            scheme = parsed.scheme.lower()
            if scheme not in ("http", "https"):
                logger.debug("page_fetcher: disallowed scheme %r for %s", scheme, current_url)
                return None

            hostname = parsed.hostname
            if not hostname:
                logger.debug("page_fetcher: URL has no host %s", current_url)
                return None

            port = parsed.port or (443 if scheme == "https" else 80)
            is_safe, resolved_ips = resolve_and_validate_hostname(hostname, port)
            if not is_safe or not resolved_ips:
                logger.debug("page_fetcher: hostname %s failed IP safety check", hostname)
                return None

            pinned_ip = resolved_ips[0]

            transport = httpx.HTTPTransport(verify=True)
            transport._pool._network_backend = _PinnedIPBackend(
                pinned_ip, transport._pool._network_backend
            )

            with httpx.Client(
                transport=transport,
                follow_redirects=False,
                timeout=timeout,
                headers={
                    "User-Agent": _UA,
                    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                },
            ) as client:
                with client.stream("GET", current_url) as response:
                    # Handle manual redirects (up to _MAX_REDIRECTS)
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location")
                        if not location:
                            logger.debug("page_fetcher: redirect without Location header")
                            return None
                        current_url = urljoin(current_url, location)
                        continue

                    if response.status_code != 200:
                        logger.debug("page_fetcher: non-200 HTTP status %s for %s", response.status_code, current_url)
                        return None

                    # Only parse HTML/XML responses
                    ct = response.headers.get("content-type", "").lower()
                    if not any(t in ct for t in _HTML_CONTENT_TYPES):
                        logger.debug("page_fetcher: skipping non-HTML content-type %r for %s", ct, current_url)
                        return None

                    chunks: list[bytes] = []
                    total = 0
                    for chunk in response.iter_bytes(chunk_size=8192):
                        chunks.append(chunk)
                        total += len(chunk)
                        if total >= max_bytes:
                            break

                    raw = b"".join(chunks)[:max_bytes]
                    break
        else:
            logger.debug("page_fetcher: exceeded max redirect hops for %s", url)
            return None

        if not raw:
            return None

        # Decode — try UTF-8 first, fall back to latin-1
        try:
            html = raw.decode("utf-8", errors="replace")
        except Exception:
            html = raw.decode("latin-1", errors="replace")

        # Sanitize: strip input field values to prevent accidental data leakage
        html = _INPUT_VALUE_RE.sub(r"\1", html)

        logger.debug("page_fetcher: fetched %d bytes from %s", len(html), current_url)
        return html

    except Exception as exc:
        logger.debug(
            "page_fetcher: could not fetch %s — %s: %s",
            url, type(exc).__name__, exc,
        )
        return None
