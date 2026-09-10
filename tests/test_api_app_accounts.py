"""App account endpoints — the applications registered against this service.

An app account is an APPLICATION, not a tenant: its ``account_id`` is what an
application sends at login and what downstream services scope their data on.
That ID is a UUID minted by the service, so these tests create an account and
read its ID back rather than naming one up front.
"""
from __future__ import annotations

from .conftest import (
    ADMIN_ACCOUNT_ID,
    admin_token,
    auth_headers,
    create_account,
    register,
    selected_account,
)


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
        json={"name": "Sneaky"},
        headers=auth_headers(token),
    )
    assert r.status_code == 403


def test_admin_is_conferred_by_app_account_membership(client):
    token = admin_token(client, "first-admin@richminds.io")
    me = client.get("/auth/me", headers=auth_headers(token)).json()
    assert selected_account(me) == ADMIN_ACCOUNT_ID
    assert me["is_admin"] is True
    assert client.get("/auth/accounts", headers=auth_headers(token)).status_code == 200


def test_admin_account_id_is_stable_across_deployments(client):
    """The admin account's ID is derived, not random.

    ``AUTH_ADMIN_ACCOUNT_ID`` is the only gate on administrative access and the
    account it names is created at startup. A randomly minted ID would leave a
    fresh deployment with no reachable administrator and no correct default,
    so the value has to be predictable from the "richminds" slug — and the same
    one the backfill script computes for an existing database.
    """
    from features.account_ids import account_uuid_for

    assert ADMIN_ACCOUNT_ID == account_uuid_for("richminds")

    token = _staff(client)
    listed = client.get("/auth/accounts", headers=auth_headers(token)).json()
    admin = next(a for a in listed if a["account_id"] == ADMIN_ACCOUNT_ID)
    # The slug it was derived from is recorded, so a migrated record can be
    # traced back to the identity it had before IDs became UUIDs.
    assert admin["legacy_account_id"] == "richminds"


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

    body = create_account(client, token, "Sample App", description="An application")
    assert body["name"] == "Sample App"
    assert body["description"] == "An application"
    assert body["enabled"] is True

    r = client.get("/auth/accounts", headers=auth_headers(token))
    assert r.status_code == 200
    assert body["account_id"] in [a["account_id"] for a in r.json()]


def test_account_id_is_generated_not_caller_supplied(client):
    """The ID is an authorization key, so the service mints it.

    It used to be caller-chosen and readable ("knowledge-ingest"). That made it
    guessable, and naming an account is half of what a login needs — so the
    value is now a UUID the service generates, and anything the caller tries to
    send is ignored rather than honoured.
    """
    import uuid

    token = _staff(client)
    r = client.post(
        "/auth/accounts",
        json={"account_id": "knowledge-ingest", "name": "Knowledge Ingest"},
        headers=auth_headers(token),
    )
    assert r.status_code == 201, r.text
    minted = r.json()["account_id"]
    assert minted != "knowledge-ingest"
    # A real UUID, not just some other string.
    assert uuid.UUID(minted)


def test_two_accounts_with_the_same_name_get_distinct_ids(client):
    """Identity comes from the generated ID, not the display name.

    This replaces the old duplicate-account_id 409: a caller can no longer
    propose an ID, so there is nothing to collide — but two applications may
    legitimately share a name and must still be separate accounts.
    """
    token = _staff(client)
    first = create_account(client, token, "Same Name")
    second = create_account(client, token, "Same Name")
    assert first["account_id"] != second["account_id"]

    listed = [a["account_id"] for a in client.get(
        "/auth/accounts", headers=auth_headers(token)
    ).json()]
    assert first["account_id"] in listed
    assert second["account_id"] in listed


# ─────────────────────────────────────────────── application type + url


def test_type_and_url_are_stored(client):
    token = _staff(client)
    body = create_account(
        client, token, "Typed App", app_type="web", app_url="https://app.example.com"
    )
    assert body["app_type"] == "web"
    assert body["app_url"] == "https://app.example.com"


def test_type_defaults_and_url_is_optional(client):
    """Records written before these fields existed still load, so the defaults
    have to be valid on their own."""
    token = _staff(client)
    body = create_account(client, token, "Bare")
    assert body["app_type"] == "other"
    assert body["app_url"] == ""


def test_unknown_application_type_is_422(client):
    """The dropdown's options are enforced server-side, not just in the UI."""
    token = _staff(client)
    r = client.post(
        "/auth/accounts",
        json={"name": "Weird", "app_type": "teapot"},
        headers=auth_headers(token),
    )
    assert r.status_code == 422


def test_non_http_url_is_rejected(client):
    """app_url is rendered as a link in the console, so a javascript: URL must
    never reach it."""
    token = _staff(client)
    r = client.post(
        "/auth/accounts",
        json={"name": "Nope", "app_url": "javascript:alert(document.cookie)"},
        headers=auth_headers(token),
    )
    assert r.status_code == 422


def test_type_and_url_can_be_updated(client):
    token = _staff(client)
    account_id = create_account(client, token, "Evolve", app_type="other")["account_id"]

    r = client.patch(
        f"/auth/accounts/{account_id}",
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
    account_id = create_account(client, token, "Old")["account_id"]

    r = client.patch(
        f"/auth/accounts/{account_id}",
        json={"name": "New Name", "description": "Now described"},
        headers=auth_headers(token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "New Name"
    assert r.json()["description"] == "Now described"
    assert r.json()["updated_at"] is not None
    # The ID is immutable — applications send it, so a rename must not move it.
    assert r.json()["account_id"] == account_id


def test_partial_update_leaves_other_fields_alone(client):
    token = _staff(client)
    account_id = create_account(
        client, token, "Keep Me", description="Keep this too"
    )["account_id"]

    r = client.patch(
        f"/auth/accounts/{account_id}", json={"enabled": False}, headers=auth_headers(token)
    )
    assert r.status_code == 200
    assert r.json()["enabled"] is False
    assert r.json()["name"] == "Keep Me"
    assert r.json()["description"] == "Keep this too"


def test_disabling_is_reversible(client):
    token = _staff(client)
    account_id = create_account(client, token, "Toggle")["account_id"]
    client.patch(
        f"/auth/accounts/{account_id}", json={"enabled": False}, headers=auth_headers(token)
    )
    r = client.patch(
        f"/auth/accounts/{account_id}", json={"enabled": True}, headers=auth_headers(token)
    )
    assert r.json()["enabled"] is True


def test_updating_an_unknown_app_account_is_404(client):
    token = _staff(client)
    r = client.patch("/auth/accounts/ghost", json={"name": "X"}, headers=auth_headers(token))
    assert r.status_code == 404


def test_staff_can_delete_an_app_account(client):
    token = _staff(client)
    account_id = create_account(client, token, "Temp")["account_id"]

    assert (
        client.delete(f"/auth/accounts/{account_id}", headers=auth_headers(token)).status_code
        == 204
    )
    assert (
        client.get(f"/auth/accounts/{account_id}", headers=auth_headers(token)).status_code == 404
    )


def test_deleting_an_unknown_app_account_is_404(client):
    token = _staff(client)
    assert client.delete("/auth/accounts/ghost", headers=auth_headers(token)).status_code == 404


# ─────────────────────────────────────────────── account_id at login


def test_login_rejects_a_user_from_a_different_account(client):
    """account_id has to mean something: valid credentials typed into the wrong
    application's login form must not work."""
    token = _staff(client)
    other_app = create_account(client, token, "Other App")["account_id"]
    client.post(
        "/auth/register",
        json={
            "email": "member@other.example",
            "name": "Other Member",
            "password": "hunter22",
            "account_id": other_app,
        },
    )

    # Right application: fine.
    r = client.post(
        "/auth/login",
        json={"email": "member@other.example", "password": "hunter22", "account_id": other_app},
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
    # No account to be scoped to, so nothing is marked selected — the client
    # should prompt for one rather than assume the first entry.
    assert user["accounts"] == []
    assert selected_account(user) is None
    assert user["is_admin"] is False


def test_login_is_refused_for_a_disabled_application(client):
    token = _staff(client)
    sunset = create_account(client, token, "Sunset")["account_id"]
    client.post(
        "/auth/register",
        json={
            "email": "member@sunset.example",
            "name": "Sunset Member",
            "password": "hunter22",
            "account_id": sunset,
        },
    )
    assert (
        client.post(
            "/auth/login",
            json={
                "email": "member@sunset.example",
                "password": "hunter22",
                "account_id": sunset,
            },
        ).status_code
        == 200
    )

    client.patch(
        f"/auth/accounts/{sunset}", json={"enabled": False}, headers=auth_headers(token)
    )

    r = client.post(
        "/auth/login",
        json={"email": "member@sunset.example", "password": "hunter22", "account_id": sunset},
    )
    assert r.status_code == 403


def test_disabling_then_re_enabling_restores_login(client):
    token = _staff(client)
    toggle = create_account(client, token, "Toggle")["account_id"]
    client.post(
        "/auth/register",
        json={
            "email": "member@toggle.example",
            "name": "Toggle Member",
            "password": "hunter22",
            "account_id": toggle,
        },
    )
    client.patch(f"/auth/accounts/{toggle}", json={"enabled": False}, headers=auth_headers(token))
    client.patch(f"/auth/accounts/{toggle}", json={"enabled": True}, headers=auth_headers(token))

    r = client.post(
        "/auth/login",
        json={"email": "member@toggle.example", "password": "hunter22", "account_id": toggle},
    )
    assert r.status_code == 200
