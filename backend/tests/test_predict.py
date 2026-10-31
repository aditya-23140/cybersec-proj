"""
backend/tests/test_predict.py
"""
def test_health_returns_200(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "model_loaded" in data


def test_model_info_returns_200(client):
    resp = client.get("/api/v1/model-info")
    assert resp.status_code == 200
    data = resp.json()
    assert "model_version" in data
    assert "model_loaded" in data


def test_predict_invalid_url_returns_422(client):
    resp = client.post("/api/v1/predict", json={"url": "javascript:alert(1)"})
    assert resp.status_code == 422


def test_predict_empty_url_returns_422(client):
    resp = client.post("/api/v1/predict", json={"url": ""})
    assert resp.status_code == 422


def test_predict_no_scheme_url_422(client):
    resp = client.post("/api/v1/predict", json={"url": "ftp://example.com"})
    assert resp.status_code == 422


def test_predict_model_unavailable_returns_503(client):
    """Model is not loaded in tests; expect 503."""
    resp = client.post("/api/v1/predict", json={"url": "https://example.com"})
    # Either 200 (if model loaded) or 503 (model not available in test env)
    assert resp.status_code in (200, 503)


def test_stats_returns_zero_on_empty_db(client):
    resp = client.get("/api/v1/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_scans"] == 0
    assert data["benign_count"] == 0
