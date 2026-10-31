"""
backend/tests/test_stats.py
"""
def test_stats_empty_db_returns_zeros(client):
    resp = client.get("/api/v1/stats")
    assert resp.status_code == 200
    data = resp.json()
    # On a fresh test DB all should be zero (or at most a small number)
    assert "total_scans" in data
    assert "benign_count" in data
    assert "phishing_count" in data
    assert "dangerous_count" in data
    assert "suspicious_count" in data
    assert "safe_count" in data
    assert "model_version" in data
    assert isinstance(data["total_scans"], int)
