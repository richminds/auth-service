"""Tests for auth business logic against in-memory repositories."""
from __future__ import annotations

import pytest

import features.repository as repository
import features.service as service
from features.config import auth_settings
from features.repository import (
    InMemoryOrganizationRepository,
    InMemoryRevocationRepository,
    InMemoryUserRepository,
)
from features.schemas import LoginRequest, RegisterRequest


@pytest.fixture(autouse=True)
def _repos(monkeypatch):
    monkeypatch.setattr(repository, "_user_repository", InMemoryUserRepository())
    monkeypatch.setattr(repository, "_org_repository", InMemoryOrganizationRepository())
    monkeypatch.setattr(repository, "_revocation_repository", InMemoryRevocationRepository())


# ─────────────────────────────────────────────── register


async def test_register_returns_a_token_and_user():
    resp = await service.register(RegisterRequest(email="a@b.com", name="A B", password="hunter22"))
    assert resp.access_token
    assert resp.user.email == "a@b.com"
    assert resp.user.org_id is None  # unassigned until a staff admin assigns one


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


async def test_portless_email_gets_reserved_org_id(monkeypatch):
    monkeypatch.setattr(auth_settings, "portless_emails_raw", "admin@portless.io")
    resp = await service.register(
        RegisterRequest(email="admin@portless.io", name="Admin", password="hunter22")
    )
    assert resp.user.org_id == "portless"
    assert resp.user.is_portless is True


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


async def test_create_and_list_organizations():
    org = await service.create_organization("Acme", created_by="USR-1")
    orgs = await service.list_organizations()
    assert org.org_id in [o.org_id for o in orgs]


async def test_assign_user_organization():
    resp = await service.register(RegisterRequest(email="a@b.com", name="A", password="hunter22"))
    org = await service.create_organization("Acme", created_by="USR-admin")
    updated = await service.assign_user_organization(resp.user.user_id, org.org_id)
    assert updated.org_id == org.org_id


async def test_assign_nonexistent_organization_raises():
    resp = await service.register(RegisterRequest(email="a@b.com", name="A", password="hunter22"))
    with pytest.raises(service.OrganizationNotFoundError):
        await service.assign_user_organization(resp.user.user_id, "ORG-GHOST")


async def test_assign_organization_to_nonexistent_user_raises():
    org = await service.create_organization("Acme", created_by="USR-admin")
    with pytest.raises(service.UserNotFoundError):
        await service.assign_user_organization("USR-GHOST", org.org_id)


async def test_find_or_create_organization_for_deal_creates_once():
    org1 = await service.find_or_create_organization_for_deal("Acme Corp", email="buyer@acme.com")
    org2 = await service.find_or_create_organization_for_deal("acme corp", email="buyer2@acme.com")
    assert org1.org_id == org2.org_id
    assert "buyer@acme.com" in org2.known_emails
    assert "buyer2@acme.com" in org2.known_emails
