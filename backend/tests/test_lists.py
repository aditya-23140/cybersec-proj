"""
backend/tests/test_lists.py
"""
def test_add_and_list_allowlist(client, auth_headers):
    resp = client.post("/api/v1/allowlist", json={"domain": "trusted.com"}, headers=auth_headers)
    assert resp.status_code == 201

    resp = client.get("/api/v1/allowlist", headers=auth_headers)
    assert resp.status_code == 200
    domains = [item["domain"] for item in resp.json()["items"]]
    assert "trusted.com" in domains


def test_duplicate_allowlist_entry_rejected(client, auth_headers):
    client.post("/api/v1/allowlist", json={"domain": "dup-allow.com"}, headers=auth_headers)
    resp = client.post("/api/v1/allowlist", json={"domain": "dup-allow.com"}, headers=auth_headers)
    assert resp.status_code == 409


def test_delete_allowlist_entry(client, auth_headers):
    resp = client.post("/api/v1/allowlist", json={"domain": "to-delete.com"}, headers=auth_headers)
    entry_id = resp.json()["id"]
    resp = client.delete(f"/api/v1/allowlist/{entry_id}", headers=auth_headers)
    assert resp.status_code == 204


def test_add_and_list_blocklist(client, auth_headers):
    resp = client.post("/api/v1/blocklist", json={"domain": "evil.com"}, headers=auth_headers)
    assert resp.status_code == 201

    resp = client.get("/api/v1/blocklist", headers=auth_headers)
    assert resp.status_code == 200
    domains = [item["domain"] for item in resp.json()["items"]]
    assert "evil.com" in domains


def test_cannot_access_other_user_allowlist(client):
    """Two different users should not see each other's lists."""
    client.post("/api/v1/auth/register", json={
        "username": "userA",
        "email": "usera@example.com",
        "password": "passwordA123",
    })
    client.post("/api/v1/auth/register", json={
        "username": "userB",
        "email": "userb@example.com",
        "password": "passwordB123",
    })

    resp_a = client.post("/api/v1/auth/login", json={"username": "userA", "password": "passwordA123"})
    token_a = resp_a.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    resp_b = client.post("/api/v1/auth/login", json={"username": "userB", "password": "passwordB123"})
    token_b = resp_b.json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    client.post("/api/v1/allowlist", json={"domain": "private-a.com"}, headers=headers_a)

    resp = client.get("/api/v1/allowlist", headers=headers_b)
    domains_b = [item["domain"] for item in resp.json()["items"]]
    assert "private-a.com" not in domains_b


def test_domain_matching_policy():
    """Test domain_matches logic directly."""
    from services.risk_policy import domain_matches

    assert domain_matches("sub.example.com", "example.com") is True
    assert domain_matches("example.com", "example.com") is True
    assert domain_matches("attacker-example.com", "example.com") is False
    assert domain_matches("notexample.com", "example.com") is False
    assert domain_matches("example.com.evil.com", "example.com") is False
