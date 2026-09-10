"""Tests for the in-memory repositories (users, organizations, revocation)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from features.repository import (
    InMemoryRevocationRepository,
    InMemoryUserRepository,
)
from features.schemas import UserRecord


def _user(user_id="USR-1", email="a@b.com") -> UserRecord:
    return UserRecord(
        user_id=user_id, email=email, name="A B", password_hash="x",
        created_at=datetime.now(timezone.utc),
    )


# ─────────────────────────────────────────────── users


async def test_create_and_get_by_id():
    repo = InMemoryUserRepository()
    await repo.create(_user())
    found = await repo.get_by_id("USR-1")
    assert found is not None
    assert found.email == "a@b.com"


async def test_lookup_by_email_is_case_insensitive():
    repo = InMemoryUserRepository()
    await repo.create(_user(email="A@B.com"))
    assert (await repo.get_by_email_account("a@b.com", None)) is not None
    assert len(await repo.list_by_email("a@b.com")) == 1


async def test_the_same_email_may_hold_one_record_per_account():
    """The whole point of the split — and the pair is still unique."""
    repo = InMemoryUserRepository()
    await repo.create(_user("USR-1", "a@b.com").model_copy(update={"account_id": "acct-a"}))
    await repo.create(_user("USR-2", "a@b.com").model_copy(update={"account_id": "acct-b"}))

    assert len(await repo.list_by_email("a@b.com")) == 2
    a = await repo.get_by_email_account("a@b.com", "acct-a")
    b = await repo.get_by_email_account("a@b.com", "acct-b")
    assert (a.user_id, b.user_id) == ("USR-1", "USR-2")
    # Different records, so credentials really are independent.
    await repo.update_password_hash("USR-2", "changed")
    assert (await repo.get_by_id("USR-1")).password_hash == "x"


async def test_repeating_an_email_in_one_account_is_rejected():
    """In-memory mirrors what the compound unique index does in Mongo, so the
    duplicate path is exercised without a database."""
    import pytest

    from features.repository import DuplicateUserError

    repo = InMemoryUserRepository()
    await repo.create(_user("USR-1", "a@b.com").model_copy(update={"account_id": "acct-a"}))
    with pytest.raises(DuplicateUserError):
        await repo.create(_user("USR-2", "A@B.com").model_copy(update={"account_id": "acct-a"}))


async def test_get_by_id_miss_returns_none():
    repo = InMemoryUserRepository()
    assert (await repo.get_by_id("USR-GHOST")) is None


async def test_list_all_sorted_by_created_at():
    repo = InMemoryUserRepository()
    now = datetime.now(timezone.utc)
    older = _user("USR-1", "old@x.com").model_copy(update={"created_at": now - timedelta(days=1)})
    newer = _user("USR-2", "new@x.com").model_copy(update={"created_at": now})
    await repo.create(newer)
    await repo.create(older)
    users = await repo.list_all()
    assert [u.user_id for u in users] == ["USR-1", "USR-2"]


# ─────────────────────────────────────────────── organizations


# ─────────────────────────────────────────────── revocation


async def test_revoked_jti_is_revoked():
    repo = InMemoryRevocationRepository()
    await repo.revoke("jti-1", ttl_seconds=60)
    assert (await repo.is_revoked("jti-1")) is True


async def test_unrevoked_jti_is_not_revoked():
    repo = InMemoryRevocationRepository()
    assert (await repo.is_revoked("jti-never-seen")) is False


async def test_zero_or_negative_ttl_is_a_no_op():
    repo = InMemoryRevocationRepository()
    await repo.revoke("jti-1", ttl_seconds=0)
    assert (await repo.is_revoked("jti-1")) is False
