"""Tests for the platform-staff email allowlist."""
from __future__ import annotations

from features.config import auth_settings
from features.organization import is_portless_user


def test_listed_email_is_portless(monkeypatch):
    monkeypatch.setattr(auth_settings, "portless_emails_raw", "admin@portless.io")
    assert is_portless_user("admin@portless.io") is True


def test_unlisted_email_is_not_portless(monkeypatch):
    monkeypatch.setattr(auth_settings, "portless_emails_raw", "admin@portless.io")
    assert is_portless_user("someone-else@example.com") is False


def test_matching_is_case_and_whitespace_insensitive(monkeypatch):
    monkeypatch.setattr(auth_settings, "portless_emails_raw", "Admin@Portless.io")
    assert is_portless_user("  admin@portless.io  ") is True


def test_multiple_emails_comma_separated(monkeypatch):
    monkeypatch.setattr(auth_settings, "portless_emails_raw", "a@x.com,b@x.com")
    assert is_portless_user("a@x.com") is True
    assert is_portless_user("b@x.com") is True
    assert is_portless_user("c@x.com") is False


def test_empty_allowlist_matches_nobody(monkeypatch):
    monkeypatch.setattr(auth_settings, "portless_emails_raw", "")
    assert is_portless_user("anyone@example.com") is False
