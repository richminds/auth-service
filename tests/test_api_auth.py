"""HTTP-layer integration tests — drives the real app via TestClient.

Port of the auth-relevant subset of the calling application's
``tests/test_auth_middleware.py`` (the deals/hitl-approval/rag assertions
there belong to other services and have no equivalent here).
"""
from __future__ import annotations

from .conftest import auth_headers, register


# ─────────────────────────────────────────────── register / login


def test_register_duplicate_email_is_409(client):
    register(client, "dup@b.com", "A")
    r = client.post(
        "/auth/register",
        json={"email": "dup@b.com", "name": "A2", "password": "hunter22"},
    )
    assert r.status_code == 409


def test_register_malformed_email_is_422(client):
    r = client.post(
        "/auth/register",
        json={"email": "not-an-email", "name": "A", "password": "hunter22"},
    )
    assert r.status_code == 422


def test_login_with_correct_password(client):
    register(client, "login@b.com", "A")
    r = client.post("/auth/login", json={"email": "login@b.com", "password": "hunter22"})
    assert r.status_code == 200
    assert r.json()["access_token"]


def test_login_with_wrong_password_is_401(client):
    register(client, "login2@b.com", "A")
    r = client.post("/auth/login", json={"email": "login2@b.com", "password": "wrong"})
    assert r.status_code == 401


# ─────────────────────────────────────────────── me / no token


def test_me_requires_a_token(client):
    assert client.get("/auth/me").status_code == 401


def test_me_returns_the_caller_profile(client):
    token, user = register(client, "me@b.com", "Me")
    r = client.get("/auth/me", headers=auth_headers(token))
    assert r.status_code == 200
    assert r.json()["user_id"] == user["user_id"]


def test_invalid_token_is_401(client):
    r = client.get("/auth/me", headers=auth_headers("not-a-real-token"))
    assert r.status_code == 401


# ─────────────────────────────────────────────── logout / revocation


def test_logout_revokes_the_token_used(client):
    token, _ = register(client, "logout-a@example.com", "Logout A")

    assert client.get("/auth/me", headers=auth_headers(token)).status_code == 200

    r = client.post("/auth/logout", headers=auth_headers(token))
    assert r.status_code == 204

    r = client.get("/auth/me", headers=auth_headers(token))
    assert r.status_code == 401
    assert "revoked" in r.json()["detail"].lower()


def test_logout_only_revokes_that_specific_token(client):
    """Logging out one session token must not invalidate a second, separately
    issued token for the same user (e.g. logged in on two devices)."""
    r = client.post(
        "/auth/register",
        json={"email": "logout-b@example.com", "name": "Logout B", "password": "hunter22"},
    )
    first_token = r.json()["access_token"]

    r = client.post("/auth/login", json={"email": "logout-b@example.com", "password": "hunter22"})
    second_token = r.json()["access_token"]
    assert second_token != first_token  # distinct jti per issuance

    r = client.post("/auth/logout", headers=auth_headers(first_token))
    assert r.status_code == 204

    assert client.get("/auth/me", headers=auth_headers(first_token)).status_code == 401
    assert client.get("/auth/me", headers=auth_headers(second_token)).status_code == 200


def test_logout_requires_a_token(client):
    assert client.post("/auth/logout").status_code == 401


# ─────────────────────────────────────────────── organization self-service


# ─────────────────────────────────────────────── organization admin (platform staff only)


def test_non_staff_cannot_list_users(client):
    token, _ = register(client, "org-user3@example.com", "Org User")
    assert client.get("/auth/users", headers=auth_headers(token)).status_code == 403


# ─────────────────────────────────────────────── organization rename / delete


# ─────────────────────────────────────────────── health


def test_health_is_public_and_ready(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] in ("ready", "degraded")


def test_liveness_is_public(client):
    assert client.get("/health/live").status_code == 200
