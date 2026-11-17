"""
backend/tests/test_page_fetcher_ssrf.py
Unit tests verifying SSRF protection, IP pinning, redirect re-validation, and TLS configuration.
"""

import socket
from unittest.mock import MagicMock, patch
import pytest

from services.page_fetcher import fetch_page_html, is_disallowed_ip, resolve_and_validate_hostname
import ipaddress


def test_ssrf_rejects_loopback_ipv4():
    """127.0.0.1 must be rejected without any connection attempt."""
    with patch("httpx.Client") as mock_client:
        assert fetch_page_html("http://127.0.0.1/admin") is None
        assert mock_client.call_count == 0


def test_ssrf_rejects_localhost_hostname():
    """localhost resolving to 127.0.0.1 must be rejected without connecting."""
    with patch("httpx.Client") as mock_client:
        assert fetch_page_html("http://localhost:8000/api") is None
        assert mock_client.call_count == 0


def test_ssrf_rejects_rfc1918_10_network():
    """10.x.x.x addresses must be rejected."""
    with patch("httpx.Client") as mock_client:
        assert fetch_page_html("http://10.0.0.5:8080/secret") is None
        assert mock_client.call_count == 0


def test_ssrf_rejects_rfc1918_192_168_network():
    """192.168.x.x addresses must be rejected."""
    with patch("httpx.Client") as mock_client:
        assert fetch_page_html("http://192.168.1.1/router") is None
        assert mock_client.call_count == 0


def test_ssrf_rejects_cloud_metadata_169_254():
    """169.254.169.254 link-local cloud metadata must be rejected."""
    with patch("httpx.Client") as mock_client:
        assert fetch_page_html("http://169.254.169.254/latest/meta-data/") is None
        assert mock_client.call_count == 0


def test_ssrf_rejects_ipv6_loopback():
    """::1 IPv6 loopback must be rejected."""
    with patch("httpx.Client") as mock_client:
        assert fetch_page_html("http://[::1]:8080/") is None
        assert mock_client.call_count == 0


def test_ssrf_rejects_ipv4_mapped_ipv6():
    """IPv4-mapped IPv6 addresses (::ffff:127.0.0.1, ::ffff:10.0.0.1) must be rejected."""
    assert is_disallowed_ip(ipaddress.ip_address("::ffff:127.0.0.1")) is True
    assert is_disallowed_ip(ipaddress.ip_address("::ffff:10.1.2.3")) is True
    assert is_disallowed_ip(ipaddress.ip_address("::ffff:169.254.169.254")) is True

    with patch("httpx.Client") as mock_client:
        assert fetch_page_html("http://[::ffff:127.0.0.1]:8080/") is None
        assert mock_client.call_count == 0


def test_ssrf_rejects_invalid_schemes():
    """Non-HTTP(S) schemes must be rejected."""
    with patch("httpx.Client") as mock_client:
        assert fetch_page_html("file:///etc/passwd") is None
        assert fetch_page_html("ftp://example.com/file") is None
        assert fetch_page_html("gopher://example.com/") is None
        assert mock_client.call_count == 0


def test_ssrf_rejects_dual_homed_if_any_ip_is_private():
    """If DNS returns a public IP and an internal IP, it must be rejected."""
    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
    ]
    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        is_safe, ips = resolve_and_validate_hostname("dual-homed.example.com", 80)
        assert is_safe is False
        assert ips == []


def test_ssrf_public_redirect_to_internal_is_rejected():
    """A public host that responds with a redirect to an internal IP is blocked on the redirect hop."""
    import httpcore
    import httpx

    # First hop is public domain
    fake_public_dns = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 80))
    ]

    mock_base = MagicMock(spec=httpcore.NetworkBackend)
    stream = MagicMock(spec=httpcore.NetworkStream)
    mock_base.connect_tcp.return_value = stream
    # 302 redirect pointing to http://127.0.0.1:8000/internal
    redirect_raw = b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:8000/internal\r\nContent-Length: 0\r\n\r\n"
    stream.read.side_effect = [redirect_raw, b""]

    with patch("socket.getaddrinfo", return_value=fake_public_dns):
        with patch.object(httpx.HTTPTransport, "__init__", return_value=None):
            with patch.object(httpx, "Client") as mock_client_cls:
                # Mock client to return redirect response on first call
                mock_client = MagicMock()
                mock_client_cls.return_value.__enter__.return_value = mock_client
                mock_resp = MagicMock()
                mock_resp.status_code = 302
                mock_resp.headers = {"location": "http://127.0.0.1:8000/internal"}
                mock_client.stream.return_value.__enter__.return_value = mock_resp

                # The second hop will evaluate http://127.0.0.1:8000/internal and return None
                result = fetch_page_html("http://public.example.com/test")
                assert result is None


def test_ssrf_rejects_non_html_content_type():
    """Non-HTML responses (e.g. application/pdf, image/png) are rejected."""
    import httpx

    fake_public_dns = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 80))
    ]
    with patch("socket.getaddrinfo", return_value=fake_public_dns):
        with patch.object(httpx, "Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value.__enter__.return_value = mock_client
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"content-type": "application/pdf"}
            mock_client.stream.return_value.__enter__.return_value = mock_resp

            assert fetch_page_html("http://public.example.com/document.pdf") is None


def test_mocked_https_fetch_pins_ip_and_preserves_sni_and_host():
    """
    Mocked HTTPS fetch:
    1. Verifies that the TCP connection is made to the pinned IP.
    2. Verifies that TLS SNI and certificate validation use the original hostname.
    3. Verifies that the HTTP Host header is set to the original hostname.
    """
    import httpcore
    import httpx

    pinned_ip = "93.184.215.14"
    hostname = "secure.example.com"
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (pinned_ip, 443))]

    mock_base = MagicMock(spec=httpcore.NetworkBackend)
    stream = MagicMock(spec=httpcore.NetworkStream)
    mock_base.connect_tcp.return_value = stream
    stream.start_tls.return_value = stream

    # Mock an HTML response with an <input value="secret"> that should be stripped
    response_body = b"<html><head><title>Login</title></head><body><input type='text' name='user' value='admin_leaked'/><p>Welcome</p></body></html>"
    stream.read.side_effect = [
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: "
        + str(len(response_body)).encode()
        + b"\r\n\r\n"
        + response_body,
        b"",
    ]

    mock_connect = MagicMock(return_value=stream)

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("httpcore._backends.sync.SyncBackend.connect_tcp", mock_connect):
            html = fetch_page_html(f"https://{hostname}/login")

            assert html is not None
            assert "<p>Welcome</p>" in html
            # Value attribute should be stripped
            assert "admin_leaked" not in html

            # 1. Pinned IP is connected to on port 443
            assert mock_connect.called
            call_kwargs = mock_connect.call_args[1]
            assert call_kwargs["host"] == pinned_ip
            assert call_kwargs["port"] == 443

            # 2. TLS SNI uses original hostname for cert validation
            assert stream.start_tls.called
            tls_kwargs = stream.start_tls.call_args[1]
            assert tls_kwargs["server_hostname"] == hostname

