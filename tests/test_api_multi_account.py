"""Multi-account sign-in: one person, several applications, several RECORDS.

A user document is one person in one application, keyed unique on (email,
account_id). "Which applications is this person in" is therefore not a stored
field — it is the set of documents sharing their email, derived per request
(features/service.py::accounts_for_email).

The API is deliberately unchanged by that: staff still set membership with
PATCH /auth/users/{id}/accounts and still send one ordered list, login still
reports every application the person may work under, and the choice is still
exchanged for a token scoped to it (POST /auth/me/account). knowledge-service
filters its chunks and files on that token claim, which is why the choice has
to live in the token rather than in the client.
"""
from __future__ import annotations

from .conftest import (
    account_ids,
    admin_account_id,
    admin_token,
    auth_headers,
    create_account,
    register,
    seed_admin_account,
    selected_account,
)


def _login(client, email: str, password: str = "hunter22", **extra) -> dict:
    r = client.post("/auth/login", json={"email": email, "password": password, **extra})
    assert r.status_code == 200, r.text
    return r.json()


def _two_account_user(client) -> tuple[str, str, str]:
    """A person holding two applications — that is, TWO user records.

    Returns their email plus the two generated account IDs — the service mints
    those now, so a test cannot name them up front.

    They are registered with no account and then assigned both, which is the
    normal path: the registration record is REUSED for the first account and a
    second record is cloned for the other, so the user_id the administrator
    addressed keeps working.

    The administrator is created by registering into the admin app account —
    holding a record in it is the only thing that grants admin rights.
    """
    staff = admin_token(client)
    ingest = create_account(client, staff, "Knowledge Ingest")["account_id"]
    portal = create_account(client, staff, "Customer Portal")["account_id"]

    _, user = register(client, "multi@example.com", "Multi User")
    r = client.patch(
        f"/auth/users/{user['user_id']}/accounts",
        # One ordered list — the FIRST entry is the default a login gets.
        json={"account_ids": [ingest, portal]},
        headers=auth_headers(staff),
    )
    assert r.status_code == 200, r.text
    return "multi@example.com", ingest, portal


def test_login_lists_every_account_and_defaults_to_the_primary(client):
    email, ingest, portal = _two_account_user(client)

    body = _login(client, email)
    assert account_ids(body["user"]) == [ingest, portal]
    assert [a["name"] for a in body["user"]["accounts"]] == ["Knowledge Ingest", "Customer Portal"]
    # No account named at login → their default, so a single-account client
    # that never offers a picker still gets a usable token.
    assert selected_account(body["user"]) == ingest
    # Exactly one entry is marked: `selected` replaced the flat account_id, so
    # an ambiguous or absent mark would leave a client unable to tell which
    # account the token is actually scoped to.
    assert [a["selected"] for a in body["user"]["accounts"]] == [True, False]
    # The response shape did not change when storage split into per-account
    # records: membership is still `accounts` and nothing else.
    assert "account_id" not in body["user"]
    assert "account_ids" not in body["user"]


def test_a_single_account_is_reported_the_same_way(client):
    """One application is one record, and still one `accounts` entry.

    A person in exactly one application is the common case, and the response
    for them must look like the multi-account one with a shorter list — a
    client should not need a second code path for it.
    """
    staff = admin_token(client)
    only = create_account(client, staff, "Only App")["account_id"]
    _, user = register(client, "single@example.com", "Single User")

    r = client.patch(
        f"/auth/users/{user['user_id']}/accounts",
        json={"account_ids": [only]},
        headers=auth_headers(staff),
    )
    assert r.status_code == 200, r.text
    assert account_ids(r.json()) == [only]

    body = _login(client, "single@example.com")
    assert account_ids(body["user"]) == [only]
    # Scoped to it without naming it: the first entry is the default.
    assert selected_account(body["user"]) == only


def test_the_first_account_id_is_the_default(client):
    """Order still decides the default.

    With membership stored as documents there is no array position to read it
    from, so the default is the OLDEST record — and reconciliation reuses the
    registration record for the list's first entry, which is what makes the
    two agree.
    """
    staff = admin_token(client)
    first = create_account(client, staff, "First")["account_id"]
    second = create_account(client, staff, "Second")["account_id"]
    _, user = register(client, "ordered@example.com", "Ordered User")

    client.patch(
        f"/auth/users/{user['user_id']}/accounts",
        json={"account_ids": [second, first]},
        headers=auth_headers(staff),
    )
    body = _login(client, "ordered@example.com")
    assert account_ids(body["user"]) == [second, first]
    assert selected_account(body["user"]) == second


def test_selecting_an_account_rescopes_the_token(client):
    email, _ingest, portal = _two_account_user(client)
    token = _login(client, email)["access_token"]

    r = client.post(
        "/auth/me/account", json={"account_id": portal}, headers=auth_headers(token)
    )
    assert r.status_code == 200, r.text
    assert selected_account(r.json()["user"]) == portal

    # The new token carries the choice — that claim is the whole point — and
    # /auth/me must report the SWITCHED account, not the stored default, or a
    # client restoring a session would silently fall back to the wrong scope.
    me = client.get("/auth/me", headers=auth_headers(r.json()["access_token"]))
    assert me.status_code == 200
    assert selected_account(me.json()) == portal


def test_login_through_a_non_member_account_is_rejected(client):
    email, _ingest, _portal = _two_account_user(client)

    r = client.post(
        "/auth/login",
        json={"email": email, "password": "hunter22", "account_id": admin_account_id()},
    )
    # Same error as a bad password: memberships aren't probeable while
    # unauthenticated.
    assert r.status_code == 401


def test_selecting_a_non_member_account_is_forbidden(client):
    email, _ingest, _portal = _two_account_user(client)
    token = _login(client, email)["access_token"]

    r = client.post(
        "/auth/me/account",
        json={"account_id": admin_account_id()},
        headers=auth_headers(token),
    )
    assert r.status_code == 403




def test_naming_the_admin_account_never_grants_admin(client):
    """Privilege escalation regression.

    The login membership check used to be skipped for a user who belonged to
    no accounts, so any signup could name the admin account and receive a
    token scoped to it. `is_admin` is derived from that scope, so the escalated
    token then passed every admin gate — in auth-service AND at the gateway.
    """
    admin_id = seed_admin_account()
    register(client, "outsider@example.com", "Outsider")

    escalation = client.post(
        "/auth/login",
        json={
            "email": "outsider@example.com",
            "password": "hunter22",
            "account_id": admin_id,
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
    email, _ingest, _portal = _two_account_user(client)

    r = client.post(
        "/auth/login",
        json={"email": email, "password": "hunter22", "account_id": "not-mine"},
    )
    assert r.status_code == 401


def test_one_email_can_hold_two_applications_independently(client):
    """The reason the collection is keyed on (email, account_id).

    Registering an email that already exists in ANOTHER application is not a
    conflict — it is a second, independent record. The two hold separate
    passwords, which is the point: an application should not inherit the
    credential a person uses somewhere else.
    """
    staff = admin_token(client)
    first = create_account(client, staff, "First App")["account_id"]
    second = create_account(client, staff, "Second App")["account_id"]

    a = client.post(
        "/auth/register",
        json={
            "email": "shared@example.com",
            "name": "Shared",
            "password": "hunter22",
            "account_id": first,
        },
    )
    assert a.status_code == 201, a.text

    b = client.post(
        "/auth/register",
        json={
            "email": "shared@example.com",
            "name": "Shared Elsewhere",
            "password": "different-pw",
            "account_id": second,
        },
    )
    assert b.status_code == 201, b.text

    # Separate records, separate identities.
    assert a.json()["user"]["user_id"] != b.json()["user"]["user_id"]
    # But one person: each sees both applications offered.
    assert sorted(account_ids(b.json()["user"])) == sorted([first, second])

    # Each account's own password works only for that account.
    assert _login(client, "shared@example.com", "different-pw", account_id=second)
    wrong = client.post(
        "/auth/login",
        json={"email": "shared@example.com", "password": "different-pw", "account_id": first},
    )
    assert wrong.status_code == 401


def test_the_same_email_twice_in_one_application_is_still_rejected(client):
    """Uniqueness moved to the PAIR — it did not go away."""
    staff = admin_token(client)
    only = create_account(client, staff, "Only App")["account_id"]

    payload = {
        "email": "dupe@example.com",
        "name": "Dupe",
        "password": "hunter22",
        "account_id": only,
    }
    assert client.post("/auth/register", json=payload).status_code == 201
    again = client.post("/auth/register", json=payload)
    assert again.status_code == 409, again.text


def test_switching_accounts_switches_record(client):
    """The token's subject follows the record, because records are the user.

    Switching applications is not the same principal changing view — it is the
    person's OTHER record signing in, so `sub` changes. Anything downstream
    that keys on user_id sees a different user per application, which matches
    how their data is scoped.
    """
    import jwt

    email, ingest, portal = _two_account_user(client)
    before = _login(client, email)
    after = client.post(
        "/auth/me/account",
        json={"account_id": portal},
        headers=auth_headers(before["access_token"]),
    )
    assert after.status_code == 200, after.text

    def _claims(token: str) -> dict:
        return jwt.decode(token, options={"verify_signature": False})

    assert _claims(before["access_token"])["account_id"] == ingest
    assert _claims(after.json()["access_token"])["account_id"] == portal
    assert before["user"]["user_id"] != after.json()["user"]["user_id"]
    # Same person throughout — the email is what ties the records together.
    assert after.json()["user"]["email"] == email


def test_removing_an_account_deletes_only_that_record(client):
    """Reconciliation is per-document, and it must not touch the survivors."""
    email, ingest, portal = _two_account_user(client)
    # _two_account_user already created the administrator; sign in as them
    # rather than registering again (the admin account is closed after the
    # first self-registration).
    staff = _login(client, "admin@richminds.io")["access_token"]

    signed_in = _login(client, email, account_id=portal)
    user_id = signed_in["user"]["user_id"]

    r = client.patch(
        f"/auth/users/{user_id}/accounts",
        json={"account_ids": [ingest]},
        headers=auth_headers(staff),
    )
    assert r.status_code == 200, r.text
    assert account_ids(r.json()) == [ingest]

    # The dropped record is gone: that account can no longer be named.
    gone = client.post(
        "/auth/login",
        json={"email": email, "password": "hunter22", "account_id": portal},
    )
    assert gone.status_code == 401
    # The surviving record still works, with its password untouched.
    assert _login(client, email, account_id=ingest)


def test_removing_every_account_keeps_the_person(client):
    """An empty list means "no application", not "delete the human".

    Before the split an empty membership array left the user able to sign in
    with no scope; reconciling to zero records would silently turn a
    membership edit into account deletion, so one record is kept.
    """
    email, _ingest, _portal = _two_account_user(client)
    staff = _login(client, "admin@richminds.io")["access_token"]
    user_id = _login(client, email)["user"]["user_id"]

    r = client.patch(
        f"/auth/users/{user_id}/accounts",
        json={"account_ids": []},
        headers=auth_headers(staff),
    )
    assert r.status_code == 200, r.text
    assert account_ids(r.json()) == []

    still_there = _login(client, email)
    assert still_there["user"]["accounts"] == []
    assert still_there["user"]["is_admin"] is False


def test_assigning_accounts_reuses_the_registration_record(client):
    """A user registered with no account keeps their user_id when placed.

    Creating a fresh record instead would strand the id the administrator just
    addressed AND leave an accountless record behind — which a login naming no
    account would resolve to FIRST, signing the person in with no scope.
    """
    staff = admin_token(client)
    app_id = create_account(client, staff, "Placement")["account_id"]
    _, user = register(client, "placed@example.com", "Placed User")

    r = client.patch(
        f"/auth/users/{user['user_id']}/accounts",
        json={"account_ids": [app_id]},
        headers=auth_headers(staff),
    )
    assert r.status_code == 200, r.text
    assert r.json()["user_id"] == user["user_id"]

    body = _login(client, "placed@example.com")
    assert body["user"]["user_id"] == user["user_id"]
    assert selected_account(body["user"]) == app_id
