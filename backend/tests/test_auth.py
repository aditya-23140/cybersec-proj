"""
backend/tests/test_auth.py
"""
import pytest


def test_register_creates_user(client):
    resp = client.post("/api/v1/auth/register", json={
        "username": "newuser1",
        "email": "newuser1@example.com",
        "password": "securepassword1",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["username"] == "newuser1"
    assert data["role"] == "user"
    assert "password" not in data
    assert "password_hash" not in data


def test_register_duplicate_username_returns_409(client):
    client.post("/api/v1/auth/register", json={
        "username": "dupuser",
        "email": "dup1@example.com",
        "password": "password123",
    })
    resp = client.post("/api/v1/auth/register", json={
        "username": "dupuser",
        "email": "dup2@example.com",
        "password": "password123",
    })
    assert resp.status_code == 409


def test_login_correct_credentials(client):
    client.post("/api/v1/auth/register", json={
        "username": "loginuser",
        "email": "loginuser@example.com",
        "password": "mypassword123",
    })
    resp = client.post("/api/v1/auth/login", json={
        "username": "loginuser",
        "password": "mypassword123",
    })
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password_returns_401(client):
    client.post("/api/v1/auth/register", json={
        "username": "wrongpwuser",
        "email": "wrongpw@example.com",
        "password": "correctpassword",
    })
    resp = client.post("/api/v1/auth/login", json={
        "username": "wrongpwuser",
        "password": "wrongpassword",
    })
    assert resp.status_code == 401


def test_protected_route_without_token_returns_401(client):
    resp = client.get("/api/v1/history")
    assert resp.status_code == 401


def test_me_with_valid_token(client, auth_headers):
    resp = client.get("/api/v1/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "username" in data
    assert "password_hash" not in data


def test_short_password_rejected(client):
    resp = client.post("/api/v1/auth/register", json={
        "username": "shortpw",
        "email": "shortpw@example.com",
        "password": "abc",
    })
    assert resp.status_code == 422
