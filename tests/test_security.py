"""Tests for JWT signing/verification and password hashing."""
from __future__ import annotations

import jwt
import pytest

from features.security import create_access_token, decode_token, hash_password, verify_password


# ─────────────────────────────────────────────── password hashing


def test_hash_is_not_the_plaintext():
    assert hash_password("hunter22") != "hunter22"


def test_verify_correct_password():
    assert verify_password("hunter22", hash_password("hunter22")) is True


def test_verify_wrong_password():
    assert verify_password("wrong", hash_password("hunter22")) is False


def test_same_password_hashes_differently_each_time():
    """Random salt per call — two hashes of the same password must differ."""
    assert hash_password("hunter22") != hash_password("hunter22")


def test_verify_rejects_malformed_stored_hash():
    assert verify_password("hunter22", "not-a-valid-hash") is False


# ─────────────────────────────────────────────── JWT


def test_token_round_trip():
    token = create_access_token(subject="USR-1")
    claims = decode_token(token)
    assert claims["sub"] == "USR-1"


def test_token_carries_extra_claims():
    token = create_access_token(subject="USR-1", extra_claims={"email": "a@b.com", "account_id": "acme"})
    claims = decode_token(token)
    assert claims["email"] == "a@b.com"
    assert claims["account_id"] == "acme"


def test_each_token_has_a_unique_jti():
    t1 = create_access_token(subject="USR-1")
    t2 = create_access_token(subject="USR-1")
    assert decode_token(t1)["jti"] != decode_token(t2)["jti"]


def test_expired_token_raises():
    token = create_access_token(subject="USR-1", ttl_minutes=-1)
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_token(token)


def test_tampered_token_raises():
    token = create_access_token(subject="USR-1")
    with pytest.raises(jwt.InvalidTokenError):
        decode_token(token + "tampered")
