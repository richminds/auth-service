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


def _two_account_user(client, portless_emails) -> str:
    """A user belonging to two applications. Returns their email."""
    portless_emails("staff@portless.io")
    staff = admin_token(client, "staff@portless.io")
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


def test_login_reports_the_single_account_a_user_belongs_to(client, portless_emails):
    portless_emails("solo-staff@portless.io")
    staff = admin_token(client, "solo-staff@portless.io")
    _make_account(client, staff, "ingest", "Knowledge Ingest")
    _, user = register(client, "solo@example.com", "Solo User")
    client.patch(
        f"/auth/users/{user['user_id']}/accounts",
        json={"account_id": "ingest", "account_ids": []},
        headers=auth_headers(staff),
    )

    body = _login(client, "solo@example.com")
    assert [a["account_id"] for a in body["accounts"]] == ["ingest"]
    assert body["account_id"] == "ingest"


def test_login_lists_every_account_and_defaults_to_the_primary(client, portless_emails):
    email = _two_account_user(client, portless_emails)

    body = _login(client, email)
    assert [a["account_id"] for a in body["accounts"]] == ["ingest", "portal"]
    assert [a["name"] for a in body["accounts"]] == ["Knowledge Ingest", "Customer Portal"]
    # No account named at login → their default, so a single-account client
    # that never offers a picker still gets a usable token.
    assert body["account_id"] == "ingest"


def test_selecting_an_account_rescopes_the_token(client, portless_emails):
    email = _two_account_user(client, portless_emails)
    token = _login(client, email)["access_token"]

    r = client.post(
        "/auth/me/account", json={"account_id": "portal"}, headers=auth_headers(token)
    )
    assert r.status_code == 200, r.text
    assert r.json()["account_id"] == "portal"

    # The new token carries the choice — that claim is the whole point.
    me = client.get("/auth/me", headers=auth_headers(r.json()["access_token"]))
    assert me.status_code == 200


def test_login_through_a_non_member_account_is_rejected(client, portless_emails):
    email = _two_account_user(client, portless_emails)

    r = client.post(
        "/auth/login",
        json={"email": email, "password": "hunter22", "account_id": ADMIN_ACCOUNT_ID},
    )
    # Same error as a bad password: memberships aren't probeable while
    # unauthenticated.
    assert r.status_code == 401


def test_selecting_a_non_member_account_is_forbidden(client, portless_emails):
    email = _two_account_user(client, portless_emails)
    token = _login(client, email)["access_token"]

    r = client.post(
        "/auth/me/account",
        json={"account_id": ADMIN_ACCOUNT_ID},
        headers=auth_headers(token),
    )
    assert r.status_code == 403


def test_assigning_an_unknown_account_is_rejected(client, portless_emails):
    portless_emails("typo-staff@portless.io")
    staff = admin_token(client, "typo-staff@portless.io")
    _, user = register(client, "typo@example.com", "Typo User")

    r = client.patch(
        f"/auth/users/{user['user_id']}/accounts",
        json={"account_id": "no-such-app", "account_ids": []},
        headers=auth_headers(staff),
    )
    assert r.status_code == 404
