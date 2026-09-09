"""Tests for auth business logic against in-memory repositories."""
from __future__ import annotations

import pytest

import features.repository as repository
import features.service as service
from features.config import auth_settings
from features.repository import (
    InMemoryRevocationRepository,
    InMemoryUserRepository,
)
from features.schemas import LoginRequest, RegisterRequest


@pytest.fixture(autouse=True)
def _repos(monkeypatch):
    monkeypatch.setattr(repository, "_user_repository", InMemoryUserRepository())
    monkeypatch.setattr(repository, "_revocation_repository", InMemoryRevocationRepository())


# ─────────────────────────────────────────────── register


async def test_register_lowercases_and_strips_email():
    resp = await service.register(RegisterRequest(email="  A@B.COM  ", name="A", password="hunter22"))
    assert resp.user.email == "a@b.com"


async def test_register_rejects_malformed_email():
    with pytest.raises(service.InvalidEmailError):
        await service.register(RegisterRequest(email="not-an-email", name="A", password="hunter22"))


async def test_register_rejects_duplicate_email():
    await service.register(RegisterRequest(email="a@b.com", name="A", password="hunter22"))
    with pytest.raises(service.EmailTakenError):
        await service.register(RegisterRequest(email="a@b.com", name="A2", password="hunter22"))


# ─────────────────────────────────────────────── login


async def test_login_succeeds_with_correct_password():
    await service.register(RegisterRequest(email="a@b.com", name="A", password="hunter22"))
    resp = await service.login(LoginRequest(email="a@b.com", password="hunter22"))
    assert resp.user.email == "a@b.com"


async def test_login_fails_with_wrong_password():
    await service.register(RegisterRequest(email="a@b.com", name="A", password="hunter22"))
    with pytest.raises(service.InvalidCredentialsError):
        await service.login(LoginRequest(email="a@b.com", password="wrong"))


async def test_login_fails_for_unknown_email():
    with pytest.raises(service.InvalidCredentialsError):
        await service.login(LoginRequest(email="nobody@example.com", password="hunter22"))


# ─────────────────────────────────────────────── logout / revocation


async def test_logout_revokes_the_token():
    from features.blacklist import is_token_revoked
    from features.security import create_access_token, decode_token

    token = create_access_token(subject="USR-1")
    await service.logout(token, "USR-1")
    jti = decode_token(token)["jti"]
    assert (await is_token_revoked(jti)) is True


async def test_logout_with_empty_token_is_a_no_op():
    await service.logout("", "USR-1")  # must not raise


# ─────────────────────────────────────────────── organizations


# ─────────────────────────────────────────────── self-service join


