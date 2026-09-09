"""App account endpoints — the applications registered against this service.

Distinct from the organization tests in test_api_auth.py: an organization is a
tenant users belong to, an app account is an application. They use separate
collections, and these tests assert they don't leak into each other.
"""
from __future__ import annotations

from .conftest import ADMIN_ACCOUNT_ID, admin_token, auth_headers, register


def _staff(client, email: str = "admin@richminds.io") -> str:
    """An administrator: a user belonging to the admin app account. Nothing
    else grants it."""
    return admin_token(client, email)


# ─────────────────────────────────────────────── access control


def test_listing_app_accounts_requires_admin(client):
    token, _ = register(client, "plain@example.com", "Plain User")
    assert client.get("/auth/accounts", headers=auth_headers(token)).status_code == 403


def test_registering_an_app_account_requires_admin(client):
    token, _ = register(client, "plain2@example.com", "Plain User")
    r = client.post(
        "/auth/accounts",
        json={"account_id": "sneaky", "name": "Sneaky"},
        headers=auth_headers(token),
    )
    assert r.status_code == 403


def test_admin_is_conferred_by_app_account_membership(client):
    token = admin_token(client, "first-admin@richminds.io")
    me = client.get("/auth/me", headers=auth_headers(token)).json()
    assert me["account_id"] == ADMIN_ACCOUNT_ID
    assert me["is_admin"] is True
    assert client.get("/auth/accounts", headers=auth_headers(token)).status_code == 200


def test_admin_account_is_closed_after_the_first_admin(client):
    """Registration is public, so the admin account can only be self-joined
    once — otherwise anyone knowing the ID could sign themselves up as one."""
    admin_token(client, "the-first@richminds.io")

    r = client.post(
        "/auth/register",
        json={
            "email": "opportunist@example.com",
            "name": "Opportunist",
            "password": "hunter22",
            "account_id": ADMIN_ACCOUNT_ID,
        },
    )
    assert r.status_code == 403


def test_registering_into_an_unknown_app_account_is_404(client):
    r = client.post(
        "/auth/register",
        json={
            "email": "nowhere@example.com",
            "name": "Nowhere",
            "password": "hunter22",
            "account_id": "no-such-app",
        },
    )
    assert r.status_code == 404


def test_app_account_endpoints_require_a_token(client):
    assert client.get("/auth/accounts").status_code == 401


# ─────────────────────────────────────────────── register / list


def test_staff_can_register_and_list_an_app_account(client):
    token = _staff(client)

    r = client.post(
        "/auth/accounts",
        json={"account_id": "sample-app", "name": "Sample App", "description": "An application"},
        headers=auth_headers(token),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["account_id"] == "sample-app"
    assert body["name"] == "Sample App"
    assert body["description"] == "An application"
    assert body["enabled"] is True

    r = client.get("/auth/accounts", headers=auth_headers(token))
    assert r.status_code == 200
    assert "sample-app" in [a["account_id"] for a in r.json()]


def test_account_id_is_caller_supplied_not_generated(client):
    """Applications send account_id at login, so the service must store exactly
    what was asked for rather than minting its own."""
    token = _staff(client)
    r = client.post(
        "/auth/accounts",
        json={"account_id": "knowledge-ingest", "name": "Knowledge Ingest"},
        headers=auth_headers(token),
    )
    assert r.json()["account_id"] == "knowledge-ingest"


def test_duplicate_account_id_is_409(client):
    token = _staff(client)
    client.post(
        "/auth/accounts", json={"account_id": "dup", "name": "First"}, headers=auth_headers(token)
    )
    r = client.post(
        "/auth/accounts", json={"account_id": "dup", "name": "Second"}, headers=auth_headers(token)
    )
    assert r.status_code == 409


def test_malformed_account_id_is_422(client):
    token = _staff(client)
    r = client.post(
        "/auth/accounts",
        json={"account_id": "not a valid id!", "name": "Nope"},
        headers=auth_headers(token),
    )
    assert r.status_code == 422


# ─────────────────────────────────────────────── application type + url


def test_type_and_url_are_stored(client):
    token = _staff(client)
    r = client.post(
        "/auth/accounts",
        json={
            "account_id": "typed-app",
            "name": "Typed App",
            "app_type": "web",
            "app_url": "https://app.example.com",
        },
        headers=auth_headers(token),
    )
    assert r.status_code == 201, r.text
    assert r.json()["app_type"] == "web"
    assert r.json()["app_url"] == "https://app.example.com"


def test_type_defaults_and_url_is_optional(client):
    """Records written before these fields existed still load, so the defaults
    have to be valid on their own."""
    token = _staff(client)
    r = client.post(
        "/auth/accounts",
        json={"account_id": "bare-app", "name": "Bare"},
        headers=auth_headers(token),
    )
    assert r.status_code == 201, r.text
    assert r.json()["app_type"] == "other"
    assert r.json()["app_url"] == ""


def test_unknown_application_type_is_422(client):
    """The dropdown's options are enforced server-side, not just in the UI."""
    token = _staff(client)
    r = client.post(
        "/auth/accounts",
        json={"account_id": "weird-app", "name": "Weird", "app_type": "teapot"},
        headers=auth_headers(token),
    )
    assert r.status_code == 422


def test_non_http_url_is_rejected(client):
    """app_url is rendered as a link in the console, so a javascript: URL must
    never reach it."""
    token = _staff(client)
    r = client.post(
        "/auth/accounts",
        json={
            "account_id": "xss-app",
            "name": "Nope",
            "app_url": "javascript:alert(document.cookie)",
        },
        headers=auth_headers(token),
    )
    assert r.status_code == 422


def test_type_and_url_can_be_updated(client):
    token = _staff(client)
    client.post(
        "/auth/accounts",
        json={"account_id": "evolve", "name": "Evolve", "app_type": "other"},
        headers=auth_headers(token),
    )

    r = client.patch(
        "/auth/accounts/evolve",
        json={"app_type": "mobile", "app_url": "https://m.example.com"},
        headers=auth_headers(token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["app_type"] == "mobile"
    assert r.json()["app_url"] == "https://m.example.com"
    # Untouched fields survive the partial update.
    assert r.json()["name"] == "Evolve"


# ─────────────────────────────────────────────── get / update / delete


def test_get_unknown_app_account_is_404(client):
    token = _staff(client)
    assert client.get("/auth/accounts/ghost", headers=auth_headers(token)).status_code == 404


def test_staff_can_update_name_and_description(client):
    token = _staff(client)
    client.post(
        "/auth/accounts", json={"account_id": "app1", "name": "Old"}, headers=auth_headers(token)
    )

    r = client.patch(
        "/auth/accounts/app1",
        json={"name": "New Name", "description": "Now described"},
        headers=auth_headers(token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "New Name"
    assert r.json()["description"] == "Now described"
    assert r.json()["updated_at"] is not None


def test_partial_update_leaves_other_fields_alone(client):
    token = _staff(client)
    client.post(
        "/auth/accounts",
        json={"account_id": "app2", "name": "Keep Me", "description": "Keep this too"},
        headers=auth_headers(token),
    )

    r = client.patch("/auth/accounts/app2", json={"enabled": False}, headers=auth_headers(token))
    assert r.status_code == 200
    assert r.json()["enabled"] is False
    assert r.json()["name"] == "Keep Me"
    assert r.json()["description"] == "Keep this too"


def test_disabling_is_reversible(client):
    token = _staff(client)
    client.post(
        "/auth/accounts", json={"account_id": "app3", "name": "Toggle"}, headers=auth_headers(token)
    )
    client.patch("/auth/accounts/app3", json={"enabled": False}, headers=auth_headers(token))
    r = client.patch("/auth/accounts/app3", json={"enabled": True}, headers=auth_headers(token))
    assert r.json()["enabled"] is True


def test_updating_an_unknown_app_account_is_404(client):
    token = _staff(client)
    r = client.patch("/auth/accounts/ghost", json={"name": "X"}, headers=auth_headers(token))
    assert r.status_code == 404


def test_staff_can_delete_an_app_account(client):
    token = _staff(client)
    client.post(
        "/auth/accounts", json={"account_id": "temp", "name": "Temp"}, headers=auth_headers(token)
    )

    assert client.delete("/auth/accounts/temp", headers=auth_headers(token)).status_code == 204
    assert client.get("/auth/accounts/temp", headers=auth_headers(token)).status_code == 404


def test_deleting_an_unknown_app_account_is_404(client):
    token = _staff(client)
    assert client.delete("/auth/accounts/ghost", headers=auth_headers(token)).status_code == 404


# ─────────────────────────────────────────────── account_id at login


def test_login_rejects_a_user_from_a_different_account(client):
    """account_id has to mean something: valid credentials typed into the wrong
    application's login form must not work."""
    token = _staff(client)
    client.post(
        "/auth/accounts",
        json={"account_id": "other-app", "name": "Other App"},
        headers=auth_headers(token),
    )
    client.post(
        "/auth/register",
        json={
            "email": "member@other.example",
            "name": "Other Member",
            "password": "hunter22",
            "account_id": "other-app",
        },
    )

    # Right application: fine.
    r = client.post(
        "/auth/login",
        json={"email": "member@other.example", "password": "hunter22", "account_id": "other-app"},
    )
    assert r.status_code == 200

    # Wrong application, same valid credentials: refused, and indistinguishable
    # from a bad password so it can't be used to probe membership.
    r = client.post(
        "/auth/login",
        json={
            "email": "member@other.example",
            "password": "hunter22",
            "account_id": ADMIN_ACCOUNT_ID,
        },
    )
    assert r.status_code == 401


def test_a_user_with_no_accounts_cannot_claim_one(client):
    """The membership check has no exemption for users with no accounts.

    It used to skip entirely when the user belonged to nothing, so anyone who
    could sign up could name the ADMIN account at login and be issued a token
    scoped to it — and since is_admin is derived from
    ``account_id == AUTH_ADMIN_ACCOUNT_ID``, that made them an administrator.
    """
    register(client, "legacy-user@example.com", "Legacy")
    r = client.post(
        "/auth/login",
        json={
            "email": "legacy-user@example.com",
            "password": "hunter22",
            "account_id": ADMIN_ACCOUNT_ID,
        },
    )
    # Same error as a bad password: memberships aren't probeable while
    # unauthenticated.
    assert r.status_code == 401


def test_a_user_with_no_accounts_can_still_sign_in_without_naming_one(client):
    """They are not locked out — they just get a token with no account scope,
    and is_admin false."""
    register(client, "legacy-user@example.com", "Legacy")
    r = client.post(
        "/auth/login",
        json={"email": "legacy-user@example.com", "password": "hunter22"},
    )
    assert r.status_code == 200
    user = r.json()["user"]
    assert user["account_id"] is None
    assert user["is_admin"] is False


def test_login_is_refused_for_a_disabled_application(client):
    token = _staff(client)
    client.post(
        "/auth/accounts",
        json={"account_id": "sunset-app", "name": "Sunset"},
        headers=auth_headers(token),
    )
    client.post(
        "/auth/register",
        json={
            "email": "member@sunset.example",
            "name": "Sunset Member",
            "password": "hunter22",
            "account_id": "sunset-app",
        },
    )
    assert (
        client.post(
            "/auth/login",
            json={
                "email": "member@sunset.example",
                "password": "hunter22",
                "account_id": "sunset-app",
            },
        ).status_code
        == 200
    )

    client.patch(
        "/auth/accounts/sunset-app", json={"enabled": False}, headers=auth_headers(token)
    )

    r = client.post(
        "/auth/login",
        json={"email": "member@sunset.example", "password": "hunter22", "account_id": "sunset-app"},
    )
    assert r.status_code == 403


def test_disabling_then_re_enabling_restores_login(client):
    token = _staff(client)
    client.post(
        "/auth/accounts",
        json={"account_id": "toggle-app", "name": "Toggle"},
        headers=auth_headers(token),
    )
    client.post(
        "/auth/register",
        json={
            "email": "member@toggle.example",
            "name": "Toggle Member",
            "password": "hunter22",
            "account_id": "toggle-app",
        },
    )
    client.patch("/auth/accounts/toggle-app", json={"enabled": False}, headers=auth_headers(token))
    client.patch("/auth/accounts/toggle-app", json={"enabled": True}, headers=auth_headers(token))

    r = client.post(
        "/auth/login",
        json={"email": "member@toggle.example", "password": "hunter22", "account_id": "toggle-app"},
    )
    assert r.status_code == 200


# ─────────────────────────────────────────────── separation from organizations


