"""
backend/tests/test_forum.py
"""
def test_create_forum_post(client, auth_headers):
    resp = client.post("/api/v1/forum/posts", json={
        "title": "How to spot phishing emails",
        "body": "Look for urgent language and suspicious links.",
    }, headers=auth_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "How to spot phishing emails"
    assert "username" in data


def test_list_forum_posts(client, auth_headers):
    resp = client.get("/api/v1/forum/posts", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_add_reply_to_post(client, auth_headers):
    resp = client.post("/api/v1/forum/posts", json={
        "title": "Reply test post",
        "body": "Post body here.",
    }, headers=auth_headers)
    post_id = resp.json()["id"]

    resp = client.post(f"/api/v1/forum/posts/{post_id}/replies", json={
        "body": "This is a reply.",
    }, headers=auth_headers)
    assert resp.status_code == 201
    assert resp.json()["body"] == "This is a reply."


def test_get_replies_for_post(client, auth_headers):
    resp = client.post("/api/v1/forum/posts", json={
        "title": "Get replies test",
        "body": "Body.",
    }, headers=auth_headers)
    post_id = resp.json()["id"]

    client.post(f"/api/v1/forum/posts/{post_id}/replies",
                json={"body": "First reply"}, headers=auth_headers)

    resp = client.get(f"/api/v1/forum/posts/{post_id}/replies", headers=auth_headers)
    assert resp.status_code == 200
    replies = resp.json()
    assert len(replies) >= 1


def test_title_too_long_rejected(client, auth_headers):
    resp = client.post("/api/v1/forum/posts", json={
        "title": "x" * 201,  # max is 200
        "body": "Body",
    }, headers=auth_headers)
    assert resp.status_code == 422


def test_body_too_long_rejected(client, auth_headers):
    resp = client.post("/api/v1/forum/posts", json={
        "title": "Valid title",
        "body": "x" * 5001,  # max is 5000
    }, headers=auth_headers)
    assert resp.status_code == 422


def test_forum_requires_auth(client):
    resp = client.post("/api/v1/forum/posts", json={
        "title": "Unauth post",
        "body": "Should fail.",
    })
    assert resp.status_code == 401


def test_post_not_found_returns_404(client, auth_headers):
    resp = client.get("/api/v1/forum/posts/999999", headers=auth_headers)
    assert resp.status_code == 404
