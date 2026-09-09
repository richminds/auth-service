"""CORS origin handling.

Browser clients (knowledge-ingest-ui, the account-management console) call this
service cross-origin, and every call carries an Authorization header — so the
allowlist is what stands between a working console and a wall of blocked
requests. Vercel hands each deployment its own hostname, which is why the
regex exists alongside the exact list.
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app.config import service_settings
from app.main import create_app

# The pattern shipped in .env.example — anchored to the projects we own.
VERCEL_REGEX = r"^https://(account-management|knowledge-ingest-ui)[a-z0-9-]*\.vercel\.app$"


def _client(monkeypatch, *, origins: str = "", regex: str = "") -> TestClient:
    """An app built with a specific CORS configuration."""
    monkeypatch.setattr(service_settings, "cors_origins", origins)
    monkeypatch.setattr(service_settings, "cors_origin_regex", regex)
    return TestClient(create_app())


def _preflight(client: TestClient, origin: str):
    return client.options(
        "/auth/login",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )


# ─────────────────────────────────────────────── exact origins


def test_listed_origin_is_allowed(monkeypatch):
    c = _client(monkeypatch, origins="https://account-management.vercel.app")
    r = _preflight(c, "https://account-management.vercel.app")
    assert r.headers.get("access-control-allow-origin") == "https://account-management.vercel.app"


def test_unlisted_origin_is_not_allowed(monkeypatch):
    c = _client(monkeypatch, origins="https://account-management.vercel.app")
    r = _preflight(c, "https://somewhere-else.example.com")
    assert "access-control-allow-origin" not in r.headers


# ─────────────────────────────────────────────── regex, for per-deploy hostnames


@pytest.mark.parametrize(
    "origin",
    [
        # The production aliases the two UIs are actually served from.
        "https://knowledge-ingest-ui.vercel.app",
        "https://account-management-ui.vercel.app",
        "https://account-management.vercel.app",
        # Vercel mints one of these per deployment and per preview.
        "https://account-management-oxvwvjvdk-karpoora-sundarapandians-projects.vercel.app",
        "https://knowledge-ingest-ui-git-main-karpoora-sundarapandians-projects.vercel.app",
    ],
)
def test_regex_covers_every_deployment_hostname(monkeypatch, origin):
    c = _client(monkeypatch, regex=VERCEL_REGEX)
    assert _preflight(c, origin).headers.get("access-control-allow-origin") == origin


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.vercel.app",  # not one of our projects
        "https://account-management.attacker.com",  # our name, someone else's domain
        "https://account-management.vercel.app.evil.com",  # suffix attack
        "http://account-management.vercel.app",  # plaintext
    ],
)
def test_regex_rejects_lookalike_origins(monkeypatch, origin):
    """The anchors matter: an unanchored pattern would hand credentials to any
    of these."""
    c = _client(monkeypatch, regex=VERCEL_REGEX)
    assert "access-control-allow-origin" not in _preflight(c, origin).headers


def test_regex_and_exact_list_work_together(monkeypatch):
    c = _client(
        monkeypatch, origins="http://localhost:5176", regex=VERCEL_REGEX
    )
    assert _preflight(c, "http://localhost:5176").headers.get(
        "access-control-allow-origin"
    ) == "http://localhost:5176"
    deployed = "https://account-management-abc123-karpoora-sundarapandians-projects.vercel.app"
    assert _preflight(c, deployed).headers.get("access-control-allow-origin") == deployed


def test_no_cors_configured_means_no_cors_headers(monkeypatch):
    """Default-closed: service-to-service callers don't need CORS, so nothing
    is emitted until an origin is configured."""
    c = _client(monkeypatch)
    assert "access-control-allow-origin" not in _preflight(
        c, "https://account-management.vercel.app"
    ).headers


def test_shipped_regex_is_valid_and_anchored():
    """A stray unanchored change here would be a credential leak, not a typo."""
    re.compile(VERCEL_REGEX)
    assert VERCEL_REGEX.startswith("^") and VERCEL_REGEX.endswith("$")
