"""Multi-account sign-in: one user, several applications.

A user's app accounts are set by staff (PATCH /auth/users/{id}/accounts); at
login the service reports which ones they may work under, and the choice is
exchanged for a token scoped to it (POST /auth/me/account). knowledge-service
filters its chunks and files on that token claim, which is why the choice has
to live in the token rather than in the client.
"""
from __future__ import annotations

from .conftest import ADMIN_ACCOUNT_ID, admin_token, auth_headers, register


def _make_account(client, staff: str, account_id: str, name: str) -> None:
    r = client.post(
        "/auth/accounts",
        json={"account_id": account_id, "name": name},
        headers=auth_headers(staff),
    )
    assert r.status_code == 201, r.text


def _login(client, email: str, password: str = "hunter22", **extra) -> dict:
    r = client.post("/auth/login", json={"email": email, "password": password, **extra})
    assert r.status_code == 200, r.text
    return r.json()


def _two_account_user(client) -> str:
    """A user belonging to two applications. Returns their email.

    The administrator is created by registering into the admin app account —
    membership of it is the only thing that grants admin rights now.
    """
    staff = admin_token(client)
    _make_account(client, staff, "ingest", "Knowledge Ingest")
    _make_account(client, staff, "portal", "Customer Portal")

    _, user = register(client, "multi@example.com", "Multi User")
    r = client.patch(
        f"/auth/users/{user['user_id']}/accounts",
        json={"account_id": "ingest", "account_ids": ["portal"]},
        headers=auth_headers(staff),
    )
    assert r.status_code == 200, r.text
    return "multi@example.com"


def test_login_lists_every_account_and_defaults_to_the_primary(client):
    email = _two_account_user(client)

    body = _login(client, email)
    assert [a["account_id"] for a in body["user"]["accounts"]] == ["ingest", "portal"]
    assert [a["name"] for a in body["user"]["accounts"]] == ["Knowledge Ingest", "Customer Portal"]
    # No account named at login → their default, so a single-account client
    # that never offers a picker still gets a usable token.
    assert body["user"]["account_id"] == "ingest"


def test_selecting_an_account_rescopes_the_token(client):
    email = _two_account_user(client)
    token = _login(client, email)["access_token"]

    r = client.post(
        "/auth/me/account", json={"account_id": "portal"}, headers=auth_headers(token)
    )
    assert r.status_code == 200, r.text
    assert r.json()["user"]["account_id"] == "portal"

    # The new token carries the choice — that claim is the whole point.
    me = client.get("/auth/me", headers=auth_headers(r.json()["access_token"]))
    assert me.status_code == 200


def test_login_through_a_non_member_account_is_rejected(client):
    email = _two_account_user(client)

    r = client.post(
        "/auth/login",
        json={"email": email, "password": "hunter22", "account_id": ADMIN_ACCOUNT_ID},
    )
    # Same error as a bad password: memberships aren't probeable while
    # unauthenticated.
    assert r.status_code == 401


def test_selecting_a_non_member_account_is_forbidden(client):
    email = _two_account_user(client)
    token = _login(client, email)["access_token"]

    r = client.post(
        "/auth/me/account",
        json={"account_id": ADMIN_ACCOUNT_ID},
        headers=auth_headers(token),
    )
    assert r.status_code == 403




def test_naming_the_admin_account_never_grants_admin(client):
    """Privilege escalation regression.

    The login membership check used to be skipped for a user who belonged to
    no accounts, so any signup could name AUTH_ADMIN_ACCOUNT_ID and receive a
    token scoped to it. `is_admin` is derived from that scope, so the escalated
    token then passed every admin gate — in auth-service AND at the gateway.
    """
    register(client, "outsider@example.com", "Outsider")

    escalation = client.post(
        "/auth/login",
        json={
            "email": "outsider@example.com",
            "password": "hunter22",
            "account_id": ADMIN_ACCOUNT_ID,
        },
    )
    assert escalation.status_code == 401

    # And the honest path grants nothing either: no account, no admin.
    plain = client.post(
        "/auth/login", json={"email": "outsider@example.com", "password": "hunter22"}
    )
    assert plain.status_code == 200
    token = plain.json()["access_token"]
    assert plain.json()["user"]["is_admin"] is False
    assert client.get("/auth/accounts", headers=auth_headers(token)).status_code == 403


def test_the_token_scope_is_never_chosen_by_the_client(client):
    """A member of one account cannot have their token scoped to another."""
    email = _two_account_user(client)

    r = client.post(
        "/auth/login",
        json={"email": email, "password": "hunter22", "account_id": "not-mine"},
    )
    assert r.status_code == 401
