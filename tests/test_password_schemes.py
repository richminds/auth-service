"""Password hashing across schemes.

The point of supporting two: a user imported from an application that already
stores bcrypt (makemerich-backend) can sign in with their existing hash — no
password reset — and gets migrated to this service's current scheme on that
first successful login.
"""
from __future__ import annotations

import bcrypt
import pytest

from features.config import auth_settings
from features.security import hash_password, needs_rehash, verify_password

from .conftest import auth_headers, register

# ─────────────────────────────────────────────── what we write


def test_new_hashes_are_bcrypt():
    stored = hash_password("hunter22")
    assert stored.startswith("$2b$")


def test_round_trip():
    assert verify_password("hunter22", hash_password("hunter22")) is True


def test_wrong_password_fails():
    assert verify_password("wrong", hash_password("hunter22")) is False


def test_same_password_hashes_differently():
    assert hash_password("hunter22") != hash_password("hunter22")


def test_configured_cost_is_used():
    cost = int(hash_password("hunter22").split("$")[2])
    assert cost == auth_settings.bcrypt_rounds


# ─────────────────────────────────────────────── what we can still read


def test_verifies_a_hash_made_by_another_application():
    """Exactly how makemerich-backend writes them: bcrypt.hashpw + gensalt."""
    foreign = bcrypt.hashpw(b"hunter22", bcrypt.gensalt(rounds=12)).decode()
    assert verify_password("hunter22", foreign) is True
    assert verify_password("nope", foreign) is False


def test_verifies_legacy_pbkdf2_hashes():
    """Records written before the switch must keep working."""
    import hashlib

    salt = "0123456789abcdef0123456789abcdef"
    rounds = 240_000
    dk = hashlib.pbkdf2_hmac("sha256", b"hunter22", salt.encode(), rounds)
    legacy = f"pbkdf2_sha256${rounds}${salt}${dk.hex()}"

    assert verify_password("hunter22", legacy) is True
    assert verify_password("wrong", legacy) is False


@pytest.mark.parametrize("junk", ["", "not-a-hash", "$2b$broken", "pbkdf2_sha256$oops"])
def test_malformed_stored_hash_is_a_failed_login_not_a_crash(junk):
    assert verify_password("hunter22", junk) is False


def test_long_passwords_are_trimmed_like_the_source_application():
    """bcrypt caps at 72 bytes and makemerich-backend trims before hashing;
    trimming differently would fail to verify imported hashes."""
    long_password = "a" * 100
    stored = hash_password(long_password)
    assert verify_password(long_password, stored) is True
    # First 72 bytes are what actually got hashed, by both implementations.
    assert verify_password("a" * 72, stored) is True


def test_multibyte_password_is_not_split_mid_character():
    password = "é" * 50  # 100 bytes
    assert verify_password(password, hash_password(password)) is True


# ─────────────────────────────────────────────── rehash on login


def test_needs_rehash_flags_legacy_and_weak_hashes():
    assert needs_rehash("pbkdf2_sha256$240000$abc$def") is True
    assert needs_rehash(bcrypt.hashpw(b"x", bcrypt.gensalt(rounds=4)).decode()) is True
    assert needs_rehash(hash_password("hunter22")) is False


def test_login_upgrades_a_legacy_hash_in_place(client, monkeypatch):
    """A pbkdf2 user signs in normally and quietly ends up on bcrypt."""
    import hashlib

    from features.repository import get_repository

    register(client, "legacy@example.com", "Legacy User")

    # Rewrite their stored hash to the old scheme, as an un-migrated record.
    salt = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    dk = hashlib.pbkdf2_hmac("sha256", b"hunter22", salt.encode(), 240_000)
    legacy = f"pbkdf2_sha256$240000${salt}${dk.hex()}"

    import asyncio

    repo = get_repository()
    user = asyncio.get_event_loop().run_until_complete(
        repo.get_by_email("legacy@example.com")
    )
    asyncio.get_event_loop().run_until_complete(
        repo.update_password_hash(user.user_id, legacy)
    )

    r = client.post(
        "/auth/login", json={"email": "legacy@example.com", "password": "hunter22"}
    )
    assert r.status_code == 200, r.text

    upgraded = asyncio.get_event_loop().run_until_complete(
        repo.get_by_email("legacy@example.com")
    )
    assert upgraded.password_hash.startswith("$2b$")
    # And the password still works against the new hash.
    assert client.post(
        "/auth/login", json={"email": "legacy@example.com", "password": "hunter22"}
    ).status_code == 200


def test_imported_bcrypt_user_can_sign_in(client):
    """The migration case end to end: a user record carrying a foreign bcrypt
    hash logs in through the normal endpoint."""
    import asyncio
    from datetime import UTC, datetime

    from features.repository import get_repository
    from features.schemas import UserRecord

    foreign_hash = bcrypt.hashpw(b"their-old-password", bcrypt.gensalt(rounds=12)).decode()
    imported = UserRecord(
        user_id="507f1f77bcf86cd799439011",  # an ObjectId, as another app would key it
        email="imported@example.com",
        name="Imported User",
        password_hash=foreign_hash,
        created_at=datetime.now(UTC),
    )
    asyncio.get_event_loop().run_until_complete(get_repository().create(imported))

    r = client.post(
        "/auth/login",
        json={"email": "imported@example.com", "password": "their-old-password"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["user"]["user_id"] == "507f1f77bcf86cd799439011"

    # And the token works.
    token = r.json()["access_token"]
    assert client.get("/auth/me", headers=auth_headers(token)).status_code == 200
