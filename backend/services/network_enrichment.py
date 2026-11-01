"""Bounded live domain, DNS, TLS, and optional reputation enrichment."""

from __future__ import annotations

import json
import logging
import socket
import ssl
import re
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from functools import lru_cache
from time import monotonic
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import config

logger = logging.getLogger(__name__)
_MAX_HTML_BYTES = 256 * 1024
_SUSPICIOUS_TEXT = re.compile(
    r"\b(verify\s+your\s+account|suspend(?:ed)?\s+account|urgent\s+action|"
    r"confirm\s+your\s+identity|crypto(?:currency)?\s+wallet)\b",
    re.IGNORECASE,
)


def _host(url: str) -> str:
    host = urlparse(url).hostname
    if not host:
        raise ValueError("URL has no hostname")
    return host.rstrip(".").lower()


def _registrable_domain(host: str) -> str:
    """Return the domain handled by the registry, excluding subdomains."""
    try:
        import tldextract

        extracted = tldextract.extract(host)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
    except ImportError:
        pass
    return host


def _dns_signals(host: str) -> dict:
    result = {"dns_resolves": False, "has_mx": False, "nameserver_count": None}
    try:
        socket.getaddrinfo(host, None)
        result["dns_resolves"] = True
    except socket.gaierror:
        return result

    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = config.ENRICHMENT_TIMEOUT_SECONDS
        resolver.lifetime = config.ENRICHMENT_TIMEOUT_SECONDS
        try:
            import tldextract

            extracted = tldextract.extract(host)
            nameserver_host = _registrable_domain(host)
        except ImportError:
            nameserver_host = host
        timeout = config.ENRICHMENT_TIMEOUT_SECONDS
        with ThreadPoolExecutor(max_workers=2) as executor:
            mx_future = executor.submit(resolver.resolve, host, "MX")
            ns_future = executor.submit(resolver.resolve, nameserver_host, "NS")
            try:
                result["has_mx"] = bool(mx_future.result(timeout=timeout))
            except Exception:
                result["has_mx"] = False
            try:
                result["nameserver_count"] = len(ns_future.result(timeout=timeout))
            except Exception:
                result["nameserver_count"] = None
    except Exception as exc:
        logger.debug("DNS enrichment incomplete for %s: %s", host, exc)
    return result


@lru_cache(maxsize=256)
def _whois_signals(host: str) -> dict:
    result = {
        "domain_age_days": None,
        "whois_available": False,
        "lookup_status": "unavailable",
    }
    try:
        import whois

        lookup_domain = _registrable_domain(host)
        record = whois.whois(
            lookup_domain,
            quiet=True,
            ignore_socket_errors=True,
            timeout=max(1, int(config.ENRICHMENT_TIMEOUT_SECONDS)),
        )
        creation = record.creation_date
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        if isinstance(creation, datetime):
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            result["domain_age_days"] = max(
                0, (datetime.now(timezone.utc) - creation).days
            )
            result["whois_available"] = True
            result["lookup_status"] = "ok"
        else:
            result["lookup_status"] = "no_creation_date"
    except (TimeoutError, socket.timeout):
        result["lookup_status"] = "timeout"
        logger.debug("WHOIS lookup timed out for %s", host)
    except Exception as exc:
        result["lookup_status"] = "error"
        logger.debug("WHOIS enrichment unavailable for %s: %s", host, exc)
    return result


def _tls_signals(host: str, port: int = 443) -> dict:
    result = {
        "certificate_checked": False,
        "certificate_valid": False,
        "certificate_hostname_match": False,
        "certificate_days_remaining": None,
        "lookup_status": "unavailable",
    }
    context = ssl.create_default_context()
    try:
        with socket.create_connection(
            (host, port), timeout=config.ENRICHMENT_TIMEOUT_SECONDS
        ) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
                result["certificate_checked"] = True
                result["certificate_valid"] = True
                result["certificate_hostname_match"] = True
                not_after = certificate.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    result["certificate_days_remaining"] = max(
                        0, (expiry - datetime.now(timezone.utc)).days
                    )
                result["lookup_status"] = "ok"
    except TimeoutError:
        result["lookup_status"] = "timeout"
        logger.debug("TLS enrichment timed out for %s", host)
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["lookup_status"] = "error"
        logger.debug("TLS enrichment unavailable for %s: %s", host, exc)
    return result


def _urlhaus_reputation(url: str) -> dict:
    if not config.URLHAUS_ENABLED:
        return {
            "reputation_provider": None,
            "reputation_hit": False,
            "lookup_status": "disabled",
        }
    if not config.URLHAUS_AUTH_KEY:
        return {
            "reputation_provider": "URLhaus",
            "reputation_hit": False,
            "lookup_status": "missing_api_key",
        }
    try:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        headers["Auth-Key"] = config.URLHAUS_AUTH_KEY
        request = Request(
            config.URLHAUS_LOOKUP_URL,
            data=f"url={url}".encode(),
            headers=headers,
            method="POST",
        )
        with urlopen(request, timeout=config.ENRICHMENT_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return {
            "reputation_provider": "URLhaus",
            "reputation_hit": payload.get("query_status") == "ok",
            "lookup_status": "ok",
        }
    except Exception as exc:
        status = getattr(exc, "code", None)
        logger.debug("URL reputation lookup unavailable for %s: %s", url, exc)
        return {
            "reputation_provider": "URLhaus",
            "reputation_hit": False,
            "lookup_status": "unauthorized" if status == 401 else "error",
        }


def _http_signals(url: str) -> dict:
    result = {
        "request_status": "unavailable",
        "http_status": None,
        "final_url": None,
        "redirect_count": 0,
        "cross_domain_redirect": False,
        "has_password_field": False,
        "external_form_count": 0,
        "suspicious_text_hits": 0,
    }
    try:
        import httpx

        with httpx.Client(
            follow_redirects=True,
            timeout=config.ENRICHMENT_TIMEOUT_SECONDS,
            headers={"User-Agent": "PhishGuard/1.0 security scanner"},
        ) as client:
            response = client.get(url)
        final_url = str(response.url)
        result.update(
            {
                "request_status": "ok",
                "http_status": response.status_code,
                "final_url": final_url,
                "redirect_count": len(response.history),
            }
        )
        original_host = _host(url)
        final_host = _host(final_url)
        result["cross_domain_redirect"] = (
            final_host != original_host
            and not final_host.endswith("." + original_host)
            and not original_host.endswith("." + final_host)
        )
        content_type = response.headers.get("content-type", "").lower()
        if "html" not in content_type:
            return result
        html = response.content[:_MAX_HTML_BYTES].decode(
            response.encoding or "utf-8", errors="ignore"
        )
        result["has_password_field"] = bool(
            re.search(r"<input\b[^>]*type\s*=\s*[\"']?password\b", html, re.IGNORECASE)
        )
        result["external_form_count"] = len(
            re.findall(r"<form\b[^>]*action\s*=\s*[\"']https?://", html, re.IGNORECASE)
        )
        result["suspicious_text_hits"] = len(_SUSPICIOUS_TEXT.findall(html))
    except httpx.TimeoutException:
        result["request_status"] = "timeout"
    except Exception as exc:
        logger.debug("HTTP enrichment unavailable for %s: %s", url, exc)
        result["request_status"] = "error"
    return result


def enrich_url(url: str) -> dict:
    """Return observable enrichment signals; failures remain explicit."""
    host = _host(url)
    result = {
        "enrichment_enabled": config.ENABLE_NETWORK_ENRICHMENT,
        "host": host,
        "dns": {},
        "whois": {},
        "tls": {},
        "reputation": {},
        "http": {},
    }
    if not config.ENABLE_NETWORK_ENRICHMENT:
        return result

    checks = {
        "dns": lambda: _dns_signals(host),
        "whois": lambda: _whois_signals(host),
        "reputation": lambda: _urlhaus_reputation(url),
        "http": lambda: _http_signals(url),
    }
    if urlparse(url).scheme.lower() == "https":
        checks["tls"] = lambda: _tls_signals(host)

    executor = ThreadPoolExecutor(max_workers=len(checks))
    futures = {name: executor.submit(check) for name, check in checks.items()}
    timeout = max(1, config.ENRICHMENT_TIMEOUT_SECONDS)
    done, _ = wait(futures.values(), timeout=timeout)
    for name, future in futures.items():
        if future not in done:
            result[name] = (
                {"request_status": "timeout"}
                if name == "http"
                else {"lookup_status": "timeout"}
            )
            logger.debug("%s enrichment timed out for %s", name, host)
            continue
        try:
            result[name] = future.result()
        except Exception as exc:
            result[name] = (
                {"request_status": "error"}
                if name == "http"
                else {"lookup_status": "error"}
            )
            logger.debug("%s enrichment failed for %s: %s", name, host, exc)
    executor.shutdown(wait=False, cancel_futures=True)
    return result
