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


# ──────────────────────────────────────────────────── the role claim

def test_an_ordinary_users_token_carries_role_user(client):
    """Minted for the services downstream, not read here. llm-gateway and
    knowledge-service authorize their admin routes on this claim; with no such
    claim every caller resolved to "user" and those routes were unreachable for
    everyone, including real administrators."""
    from features.security import decode_token

    token, _ = register(client, "ordinary@b.com", "Ordinary")
    assert decode_token(token)["role"] == "user"


def test_an_admin_accounts_token_carries_role_admin(client):
    from features.security import decode_token

    from .conftest import admin_token

    assert decode_token(admin_token(client))["role"] == "admin"


def test_the_role_follows_the_account_the_token_is_scoped_to(client):
    """Administering one application does not make you an administrator of a
    session scoped to another — the claim is derived from the scoped account,
    exactly as UserPublic.is_admin is."""
    from features.security import decode_token

    from .conftest import admin_account_id, admin_token

    token = admin_token(client)
    claims = decode_token(token)
    assert claims["account_id"] == admin_account_id()
    assert claims["role"] == "admin"


# ─────────────────────────────────────────── POST /auth/refresh-token
#
# The endpoint exists so access tokens can stay short-lived — that lifetime IS
# this service's revocation latency — without signing users out every hour.
# It is the one endpoint that accepts an EXPIRED token, so most of what is
# tested here is the fence around that.

def _mint(user_id: str, **overrides):
    """A token for `user_id` with claims we control, so expiry and age can be
    tested without waiting an hour."""
    from features.security import create_access_token

    return create_access_token(
        subject=user_id,
        extra_claims={"account_id": None, "role": "user", **overrides.pop("claims", {})},
        **overrides,
    )


def test_refresh_returns_a_new_working_token(client):
    token, user = register(client, "refresh@b.com", "R")

    r = client.post("/auth/refresh-token", headers=auth_headers(token))

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"] and body["access_token"] != token
    assert body["user"]["email"] == "refresh@b.com"
    # The new token actually works.
    me = client.get("/auth/me", headers=auth_headers(body["access_token"]))
    assert me.status_code == 200
    assert me.json()["user_id"] == user["user_id"]


def test_refresh_accepts_an_EXPIRED_token(client):
    """The whole point — an hour-old token is exactly what a client presents."""
    _, user = register(client, "expired@b.com", "E")
    expired = _mint(user["user_id"], ttl_minutes=-5)

    # It is genuinely rejected everywhere else.
    assert client.get("/auth/me", headers=auth_headers(expired)).status_code == 401

    r = client.post("/auth/refresh-token", headers=auth_headers(expired))
    assert r.status_code == 200, r.text


def test_refresh_rotates_so_a_token_works_only_once(client):
    """A stolen token buys ONE refresh, not an endless session."""
    token, _ = register(client, "rotate@b.com", "Rot")

    first = client.post("/auth/refresh-token", headers=auth_headers(token))
    assert first.status_code == 200

    second = client.post("/auth/refresh-token", headers=auth_headers(token))
    assert second.status_code == 401


def test_a_logged_out_token_cannot_be_refreshed(client):
    """Otherwise logout would mean nothing — the discarded token could just be
    exchanged for a live one."""
    token, _ = register(client, "loggedout@b.com", "L")
    assert client.post("/auth/logout", headers=auth_headers(token)).status_code == 204

    r = client.post("/auth/refresh-token", headers=auth_headers(token))
    assert r.status_code == 401


def test_a_token_older_than_the_refresh_window_is_refused(client):
    """Expiry is waived, so this window is the ONLY bound on how stale a token
    may be — without it one recovered from an old log would still work.

    The window is measured from ``iat``, NOT from ``exp``: it is an idle
    timeout that slides forward on every refresh, so an active session never
    hits it while an abandoned one does. That is why this has to forge an old
    ``iat`` — a token minted now with a negative TTL is merely expired, which
    is the case refresh is supposed to ACCEPT.
    """
    from datetime import datetime, timezone

    from features.config import auth_settings

    _, user = register(client, "stale@b.com", "S")
    issued = datetime.now(timezone.utc).timestamp() - (
        auth_settings.refresh_ttl_minutes * 60 + 3600
    )
    ancient = _mint(user["user_id"], claims={"iat": int(issued), "exp": int(issued) + 3600})

    r = client.post("/auth/refresh-token", headers=auth_headers(ancient))
    assert r.status_code == 401


def test_a_token_expired_but_INSIDE_the_window_still_refreshes(client):
    """The boundary from the other side — long expired, recently issued."""
    from datetime import datetime, timezone

    _, user = register(client, "withinwindow@b.com", "W")
    issued = datetime.now(timezone.utc).timestamp() - 7200  # 2h ago
    token = _mint(user["user_id"], claims={"iat": int(issued), "exp": int(issued) + 60})

    r = client.post("/auth/refresh-token", headers=auth_headers(token))
    assert r.status_code == 200, r.text


def test_refresh_rejects_a_forged_token(client):
    r = client.post(
        "/auth/refresh-token", headers={"Authorization": "Bearer not.a.real.token"}
    )
    assert r.status_code == 401


def test_refresh_without_a_token_is_401(client):
    assert client.post("/auth/refresh-token").status_code == 401


def test_refresh_keeps_the_session_scoped_to_the_same_account(client):
    """Refreshing is not a place to silently move the session to another
    application — that is what POST /auth/me/account is for."""
    token, user = register(client, "scoped@b.com", "Sc")
    before = client.get("/auth/me", headers=auth_headers(token)).json()

    body = client.post("/auth/refresh-token", headers=auth_headers(token)).json()
    after = client.get("/auth/me", headers=auth_headers(body["access_token"])).json()

    assert [a["account_id"] for a in after["accounts"]] == [
        a["account_id"] for a in before["accounts"]
    ]
    assert after["is_admin"] == before["is_admin"]
