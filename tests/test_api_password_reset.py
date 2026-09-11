"""Password-reset flow — request a link, redeem it, and the ways it must fail.

The account scoping is the part worth the most attention. Users are keyed on
(email, account_id) with a password hash per record, so a reset has to name an
application; the tests below pin that a reset in one application leaves the
same person's record in another one untouched.

SMTP is never configured in the suite, so `request_password_reset` reports
"not dispatched" and the raw token comes back in `debug_token` — the same
development path an operator gets with AUTH_EXPOSE_RESET_TOKEN=true. That is
how these tests obtain a token without a mail server.
"""
from __future__ import annotations

import pytest

from features.config import auth_settings

from .conftest import ADMIN_ACCOUNT_ID, admin_token, auth_headers, create_account, register


@pytest.fixture(autouse=True)
def _expose_tokens():
    """Surface debug_token for the duration of each test.

    auth_settings is a module-level singleton built at import time, so this
    flips the attribute rather than the environment variable, and puts it back
    afterwards so nothing leaks into tests that assert it is off.
    """
    previous = auth_settings.expose_reset_token
    auth_settings.expose_reset_token = True
    yield
    auth_settings.expose_reset_token = previous


GENERIC = "If an account exists for that email, a password reset link has been sent."


def _forgot(client, email: str, account_id: str) -> dict:
    r = client.post(
        "/auth/forgot-password", json={"email": email, "account_id": account_id}
    )
    assert r.status_code == 200, r.text
    return r.json()


def _login(client, email: str, password: str, account_id: str | None = None):
    payload = {"email": email, "password": password}
    if account_id:
        payload["account_id"] = account_id
    return client.post("/auth/login", json=payload)


def _register_into(client, email: str, name: str, account_id: str, password="hunter22"):
    r = client.post(
        "/auth/register",
        json={"email": email, "name": name, "password": password, "account_id": account_id},
    )
    assert r.status_code == 201, r.text
    return r.json()


# ───────────────────────────────────────────────────────── happy path


def test_accountless_record_is_not_reachable_from_an_account(client):
    """register() with no account_id makes a record that belongs to no
    application, so naming one finds nothing — the same silent miss as an
    unknown address."""
    register(client, "reset@b.com", "R")
    assert _forgot(client, "reset@b.com", ADMIN_ACCOUNT_ID).get("debug_token") is None


def test_full_reset_cycle_for_a_record_in_an_account(client):
    token = admin_token(client)
    app_id = create_account(client, token, "Some App")["account_id"]
    _register_into(client, "user@b.com", "U", app_id)

    body = _forgot(client, "user@b.com", app_id)
    assert body["message"] == GENERIC
    raw = body["debug_token"]
    assert raw

    r = client.post("/auth/reset-password", json={"token": raw, "new_password": "brand-new-pw"})
    assert r.status_code == 200, r.text

    assert _login(client, "user@b.com", "brand-new-pw", app_id).status_code == 200
    assert _login(client, "user@b.com", "hunter22", app_id).status_code == 401


# ─────────────────────────────────────────────── account scoping


def test_reset_in_one_account_leaves_the_sibling_record_alone(client):
    """The whole reason forgot-password requires an account_id."""
    token = admin_token(client)
    first = create_account(client, token, "First App")["account_id"]
    second = create_account(client, token, "Second App")["account_id"]

    _register_into(client, "shared@b.com", "S", first, password="first-pw")
    _register_into(client, "shared@b.com", "S", second, password="second-pw")

    raw = _forgot(client, "shared@b.com", first)["debug_token"]
    assert raw
    assert (
        client.post(
            "/auth/reset-password", json={"token": raw, "new_password": "rotated-pw"}
        ).status_code
        == 200
    )

    # Reset record: new password works, old one doesn't.
    assert _login(client, "shared@b.com", "rotated-pw", first).status_code == 200
    assert _login(client, "shared@b.com", "first-pw", first).status_code == 401
    # Untouched record in the OTHER application: original password still works,
    # and the rotated one was never valid there.
    assert _login(client, "shared@b.com", "second-pw", second).status_code == 200
    assert _login(client, "shared@b.com", "rotated-pw", second).status_code == 401


def test_unknown_email_gets_the_same_answer_as_a_known_one(client):
    token = admin_token(client)
    app_id = create_account(client, token, "App")["account_id"]

    known = _forgot(client, "admin@richminds.io", ADMIN_ACCOUNT_ID)
    unknown = _forgot(client, "nobody@nowhere.com", app_id)

    assert known["message"] == unknown["message"] == GENERIC
    # No token for an address with no record in that application.
    assert unknown.get("debug_token") is None


def test_email_in_a_different_account_is_not_confirmed(client):
    """Membership of another application must not leak either."""
    token = admin_token(client)
    theirs = create_account(client, token, "Theirs")["account_id"]
    other = create_account(client, token, "Other")["account_id"]
    _register_into(client, "elsewhere@b.com", "E", theirs)

    body = _forgot(client, "elsewhere@b.com", other)
    assert body["message"] == GENERIC
    assert body.get("debug_token") is None


def test_disabled_application_cannot_start_a_reset(client):
    token = admin_token(client)
    app_id = create_account(client, token, "Retired App")["account_id"]
    _register_into(client, "member@b.com", "M", app_id)

    r = client.patch(
        f"/auth/accounts/{app_id}", json={"enabled": False}, headers=auth_headers(token)
    )
    assert r.status_code == 200, r.text

    body = _forgot(client, "member@b.com", app_id)
    assert body["message"] == GENERIC
    assert body.get("debug_token") is None


# ──────────────────────────────────────────────── token rejection


def test_unknown_token_is_400(client):
    r = client.post(
        "/auth/reset-password", json={"token": "not-a-real-token", "new_password": "whatever1"}
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_reset_token"


def test_token_cannot_be_used_twice(client):
    token = admin_token(client)
    app_id = create_account(client, token, "App")["account_id"]
    _register_into(client, "once@b.com", "O", app_id)

    raw = _forgot(client, "once@b.com", app_id)["debug_token"]
    assert (
        client.post(
            "/auth/reset-password", json={"token": raw, "new_password": "first-change"}
        ).status_code
        == 200
    )

    second = client.post(
        "/auth/reset-password", json={"token": raw, "new_password": "second-change"}
    )
    assert second.status_code == 400
    assert "already been used" in second.json()["error"]["message"]
    # And the password is still the one the first redemption set.
    assert _login(client, "once@b.com", "first-change", app_id).status_code == 200


def test_requesting_a_second_link_invalidates_the_first(client):
    """Otherwise every link ever mailed stays a live takeover until it expires."""
    token = admin_token(client)
    app_id = create_account(client, token, "App")["account_id"]
    _register_into(client, "twice@b.com", "T", app_id)

    first = _forgot(client, "twice@b.com", app_id)["debug_token"]
    second = _forgot(client, "twice@b.com", app_id)["debug_token"]
    assert first != second

    stale = client.post(
        "/auth/reset-password", json={"token": first, "new_password": "via-stale-link"}
    )
    assert stale.status_code == 400
    assert "already been used" in stale.json()["error"]["message"]

    assert (
        client.post(
            "/auth/reset-password", json={"token": second, "new_password": "via-fresh-link"}
        ).status_code
        == 200
    )
    assert _login(client, "twice@b.com", "via-fresh-link", app_id).status_code == 200


def test_expired_token_is_rejected(client):
    token = admin_token(client)
    app_id = create_account(client, token, "App")["account_id"]
    _register_into(client, "stale@b.com", "S", app_id)

    previous = auth_settings.password_reset_ttl_minutes
    auth_settings.password_reset_ttl_minutes = -1  # already expired when minted
    try:
        raw = _forgot(client, "stale@b.com", app_id)["debug_token"]
    finally:
        auth_settings.password_reset_ttl_minutes = previous

    r = client.post("/auth/reset-password", json={"token": raw, "new_password": "too-late-pw"})
    assert r.status_code == 400
    assert "expired" in r.json()["error"]["message"]
    assert _login(client, "stale@b.com", "hunter22", app_id).status_code == 200


def test_short_password_is_rejected_by_validation(client):
    """Matches RegisterRequest's minimum, so a reset can't set a password
    registration would have refused."""
    r = client.post("/auth/reset-password", json={"token": "x" * 20, "new_password": "short"})
    assert r.status_code == 422


def test_account_id_is_required(client):
    r = client.post("/auth/forgot-password", json={"email": "someone@b.com"})
    assert r.status_code == 422


def test_debug_token_is_withheld_when_not_opted_in(client):
    """The escape hatch is off by default — otherwise anyone could reset
    anyone's password just by asking."""
    token = admin_token(client)
    app_id = create_account(client, token, "App")["account_id"]
    _register_into(client, "hidden@b.com", "H", app_id)

    auth_settings.expose_reset_token = False
    body = _forgot(client, "hidden@b.com", app_id)
    assert body["message"] == GENERIC
    assert body.get("debug_token") is None


# ───────────────────────────────────────────────── link construction

# _reset_link is the one piece of this flow the HTTP tests above cannot see:
# with SMTP unconfigured the link is built and then discarded, so an empty or
# malformed one produces the same 200 as a good one. These pin it directly.


@pytest.mark.parametrize(
    "app_url, fallback, expected",
    [
        # An app account's app_url is its home, so the reset path is appended.
        ("https://console.example.com", "", "https://console.example.com/reset-password?token=T"),
        # Trailing slashes are the operator's, not ours.
        ("https://console.example.com/", "", "https://console.example.com/reset-password?token=T"),
        # Already pointing at the reset screen — don't double the path. This is
        # the shape AUTH_PASSWORD_RESET_URL inherits from makemerich's setting.
        (
            "https://console.example.com/reset-password",
            "",
            "https://console.example.com/reset-password?token=T",
        ),
        # No app_url on the account: fall back to the configured global.
        ("", "https://fallback.example.com", "https://fallback.example.com/reset-password?token=T"),
        # The account's own URL wins over the fallback.
        (
            "https://mine.example.com",
            "https://fallback.example.com",
            "https://mine.example.com/reset-password?token=T",
        ),
        # Neither configured: no link, so no email — the caller logs an error
        # rather than mailing something broken.
        ("", "", ""),
    ],
)
def test_reset_link_construction(app_url, fallback, expected):
    from features.password_reset import _reset_link

    previous = auth_settings.password_reset_url
    auth_settings.password_reset_url = fallback
    try:
        assert _reset_link(app_url, "T") == expected
    finally:
        auth_settings.password_reset_url = previous


def test_reset_link_preserves_an_existing_query_string():
    """A base that already carries a query gets & rather than a second ?."""
    from features.password_reset import _reset_link

    link = _reset_link("https://console.example.com/reset-password?src=email", "T")
    assert link == "https://console.example.com/reset-password?src=email&token=T"
