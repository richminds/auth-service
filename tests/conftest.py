"""Shared fixtures.

Every test runs against in-memory repositories — the suite never touches a
real MongoDB and never needs credentials. With AUTH_MONGO_URI unset,
``init_repository()`` (called from the app's lifespan) already falls back to
fresh ``InMemory*Repository`` instances, so a function-scoped ``client``
fixture that re-enters the TestClient context per test gets a clean slate for
free — no monkeypatching needed.

The env defaults below are set *before* any app import because settings
objects are module-level singletons built at import time; real environment
variables outrank .env in pydantic-settings, so this also keeps the suite
hermetic on a developer machine that has a fully populated .env.
"""
from __future__ import annotations

import os

os.environ.setdefault("AUTH_MONGO_URI", "")
os.environ.setdefault("AUTH_JWT_SECRET", "test-secret-not-for-production-use-only")
os.environ.setdefault("AUTH_PORTLESS_EMAILS", "")
os.environ.setdefault("AUTHSVC_ENVIRONMENT", "test")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from features.config import auth_settings  # noqa: E402


@pytest.fixture
def client():
    """TestClient against the real app — each test gets a fresh in-memory
    user/organization/revocation store via the lifespan's init_repository()."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def portless_emails(monkeypatch):
    """Set the platform-staff allowlist for the duration of one test.

    ``auth_settings`` is a module-level singleton built once at import time,
    so tests that need a specific allowlist value patch the attribute
    directly rather than the env var (which nothing re-reads after import).
    """

    def _set(raw: str) -> None:
        monkeypatch.setattr(auth_settings, "portless_emails_raw", raw)

    return _set


ADMIN_ACCOUNT_ID = "richminds"
"""Mirrors auth_settings.admin_account_id — membership of this app account is
what makes a user an administrator (features/dependencies.py::require_admin)."""


def register(client, email: str, name: str, password: str = "hunter22") -> tuple[str, dict]:
    r = client.post("/auth/register", json={"email": email, "name": name, "password": password})
    assert r.status_code == 201, r.text
    body = r.json()
    return body["access_token"], body["user"]


def admin_token(client, email: str = "admin@richminds.io", password: str = "hunter22") -> str:
    """Register the first administrator and return their token.

    Self-registration into the admin account is allowed exactly once per
    store (see service.register), and each test gets a fresh in-memory store,
    so this works once per test — call it before any other admin exists.
    """
    r = client.post(
        "/auth/register",
        json={
            "email": email,
            "name": "Admin",
            "password": password,
            "account_id": ADMIN_ACCOUNT_ID,
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["access_token"]


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
