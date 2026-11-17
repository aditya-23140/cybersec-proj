"""
backend/tests/test_cors.py
Verify CORS configuration, extension regex, and origin validation.
"""

from fastapi.testclient import TestClient
from main import app


def test_cors_allowed_frontend_origin(client):
    """Allowed origin from config.CORS_ORIGINS receives CORS response headers."""
    resp = client.get(
        "/api/v1/health",
        headers={"Origin": "http://localhost:3000"},
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert resp.headers.get("access-control-allow-credentials") == "true"


def test_cors_disallowed_origin_rejected(client):
    """Disallowed origin does not receive access-control-allow-origin header."""
    resp = client.get(
        "/api/v1/health",
        headers={"Origin": "https://malicious-attacker.com"},
    )
    assert resp.status_code == 200
    assert "access-control-allow-origin" not in resp.headers


def test_cors_literal_wildcard_not_accepted(client):
    """Literal wildcard chrome-extension://* is not accepted as an origin."""
    resp = client.get(
        "/api/v1/health",
        headers={"Origin": "chrome-extension://*"},
    )
    assert resp.status_code == 200
    assert "access-control-allow-origin" not in resp.headers


def test_cors_preflight_options(client):
    """CORS preflight OPTIONS request returns allowed methods and headers."""
    resp = client.options(
        "/api/v1/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "GET" in resp.headers.get("access-control-allow-methods", "")
