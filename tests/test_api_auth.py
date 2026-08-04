"""HTTP-layer integration tests — drives the real app via TestClient.

Port of the auth-relevant subset of the calling application's
``tests/test_auth_middleware.py`` (the deals/hitl-approval/rag assertions
there belong to other services and have no equivalent here).
"""
from __future__ import annotations

from .conftest import auth_headers, register


# ─────────────────────────────────────────────── register / login


def test_register_returns_201_and_a_token(client):
    r = client.post(
        "/auth/register",
        json={"email": "a@b.com", "name": "A B", "password": "hunter22"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["access_token"]
    assert body["user"]["email"] == "a@b.com"
    assert body["user"]["is_portless"] is False


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


def test_anyone_can_register_an_organization(client):
    r = client.post("/auth/organizations/register", json={"name": "Acme"})
    assert r.status_code == 201, r.text
    assert r.json()["org_id"]
    assert r.json()["created_by"] == "self-serve"


def test_register_with_org_id_joins_immediately(client):
    org_id = client.post("/auth/organizations/register", json={"name": "Acme"}).json()["org_id"]
    r = client.post(
        "/auth/register",
        json={"email": "joined@b.com", "name": "A", "password": "hunter22", "org_id": org_id},
    )
    assert r.status_code == 201, r.text
    assert r.json()["user"]["org_id"] == org_id


def test_register_with_unknown_org_id_is_404(client):
    r = client.post(
        "/auth/register",
        json={"email": "ghost@b.com", "name": "A", "password": "hunter22", "org_id": "ORG-GHOST"},
    )
    assert r.status_code == 404


def test_guest_can_join_an_organization(client):
    token, user = register(client, "guest@b.com", "Guest")
    assert user["org_id"] is None

    org_id = client.post("/auth/organizations/register", json={"name": "Acme"}).json()["org_id"]
    r = client.post(
        "/auth/me/organization", json={"org_id": org_id}, headers=auth_headers(token)
    )
    assert r.status_code == 200, r.text
    assert r.json()["user"]["org_id"] == org_id

    # the returned token already carries the new org_id claim
    new_token = r.json()["access_token"]
    r = client.get("/auth/me", headers=auth_headers(new_token))
    assert r.json()["org_id"] == org_id


def test_already_assigned_user_cannot_self_join_another_org(client):
    org1 = client.post("/auth/organizations/register", json={"name": "Acme"}).json()["org_id"]
    org2 = client.post("/auth/organizations/register", json={"name": "Globex"}).json()["org_id"]
    token, _ = register(client, "assigned@b.com", "A")
    client.post("/auth/me/organization", json={"org_id": org1}, headers=auth_headers(token))

    r = client.post("/auth/me/organization", json={"org_id": org2}, headers=auth_headers(token))
    assert r.status_code == 409


def test_join_unknown_organization_is_404(client):
    token, _ = register(client, "joinghost@b.com", "A")
    r = client.post(
        "/auth/me/organization", json={"org_id": "ORG-GHOST"}, headers=auth_headers(token)
    )
    assert r.status_code == 404


def test_join_organization_requires_a_token(client):
    org_id = client.post("/auth/organizations/register", json={"name": "Acme"}).json()["org_id"]
    r = client.post("/auth/me/organization", json={"org_id": org_id})
    assert r.status_code == 401


# ─────────────────────────────────────────────── organization admin (platform staff only)


def test_non_staff_cannot_create_organization(client):
    token, _ = register(client, "org-user@example.com", "Org User")
    r = client.post("/auth/organizations", json={"name": "Acme"}, headers=auth_headers(token))
    assert r.status_code == 403


def test_non_staff_cannot_list_organizations(client):
    token, _ = register(client, "org-user2@example.com", "Org User")
    assert client.get("/auth/organizations", headers=auth_headers(token)).status_code == 403


def test_non_staff_cannot_list_users(client):
    token, _ = register(client, "org-user3@example.com", "Org User")
    assert client.get("/auth/users", headers=auth_headers(token)).status_code == 403


def test_staff_can_create_and_list_organizations(client, portless_emails):
    portless_emails("admin@portless.io")
    token, user = register(client, "admin@portless.io", "Admin")
    assert user["is_portless"] is True

    r = client.post("/auth/organizations", json={"name": "Acme"}, headers=auth_headers(token))
    assert r.status_code == 201, r.text
    org_id = r.json()["org_id"]

    r = client.get("/auth/organizations", headers=auth_headers(token))
    assert r.status_code == 200
    assert org_id in [o["org_id"] for o in r.json()]


def test_staff_can_list_users(client, portless_emails):
    portless_emails("admin@portless.io")
    admin_token, _ = register(client, "admin@portless.io", "Admin")
    register(client, "someone@example.com", "Someone")

    r = client.get("/auth/users", headers=auth_headers(admin_token))
    assert r.status_code == 200
    emails = [u["email"] for u in r.json()]
    assert "someone@example.com" in emails
    assert "admin@portless.io" in emails


def test_staff_can_assign_a_user_to_an_organization(client, portless_emails):
    portless_emails("admin@portless.io")
    admin_token, _ = register(client, "admin@portless.io", "Admin")
    _, user = register(client, "assignee@example.com", "Assignee")

    r = client.post("/auth/organizations", json={"name": "Acme"}, headers=auth_headers(admin_token))
    org_id = r.json()["org_id"]

    r = client.patch(
        f"/auth/users/{user['user_id']}/organization",
        json={"org_id": org_id},
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["org_id"] == org_id


def test_assigning_a_nonexistent_organization_is_404(client, portless_emails):
    portless_emails("admin@portless.io")
    admin_token, _ = register(client, "admin@portless.io", "Admin")
    _, user = register(client, "assignee2@example.com", "Assignee")

    r = client.patch(
        f"/auth/users/{user['user_id']}/organization",
        json={"org_id": "ORG-GHOST"},
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 404


# ─────────────────────────────────────────────── health


def test_health_is_public_and_ready(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] in ("ready", "degraded")


def test_liveness_is_public(client):
    assert client.get("/health/live").status_code == 200
