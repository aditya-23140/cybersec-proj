"""
backend/tests/conftest.py — Shared test fixtures.
"""
import sys
import os
from pathlib import Path

# Ensure backend root is on path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Use in-memory SQLite for tests
os.environ.setdefault("DATABASE_PATH", ":memory:")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-not-for-production")

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def client():
    """
    TestClient for the FastAPI app.
    The model predictor will be unavailable (503 from /predict),
    but all other routes should work normally.
    """
    from main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def auth_headers(client):
    """Register a test user and return auth headers."""
    client.post("/api/v1/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpassword123",
    })
    resp = client.post("/api/v1/auth/login", json={
        "username": "testuser",
        "password": "testpassword123",
    })
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
