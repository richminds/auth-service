"""Auth primitives — JWT signing/verification and password hashing.

  • JWT   — PyJWT, HS256.
  • Hash  — bcrypt for new passwords; pbkdf2-sha256 still verified.

**Two hash schemes are readable, one is written.** ``verify_password``
dispatches on the stored hash's own prefix, so this service accepts:

    $2b$12$...              bcrypt — what it writes now, and the format
                            makemerich-backend already stores. Importing that
                            application's users is a straight copy of the
                            existing hash: nobody resets a password.
    pbkdf2_sha256$r$s$h     the scheme this service used originally.

``hash_password`` always writes bcrypt, and ``needs_rehash`` reports a stored
hash that isn't the current scheme/cost. features/service.py::login upgrades
those in place on a successful sign-in, so old hashes migrate as people log
in rather than needing a reset — the same mechanism that carries imported
bcrypt users forward if the cost factor is later raised.

Why bcrypt over pbkdf2: pbkdf2 uses almost no memory, so it parallelises
cheaply on GPUs; bcrypt's ~4 KB working set blunts that considerably. (Argon2id
would be better still, but needs a compiled dependency and buys less than the
migration compatibility bcrypt gives us here.)
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt  # PyJWT

from .config import auth_settings

logger = logging.getLogger(__name__)

# Legacy scheme — still verified, never written. The round count travels in
# each stored hash, so old records keep verifying at whatever they were made
# with regardless of this value.
_PBKDF2_ALGO = "sha256"

# bcrypt rejects (rather than truncates) anything past 72 bytes, and
# makemerich-backend trims to the same boundary before hashing — so an
# imported hash of a long password only verifies if we trim identically.
_BCRYPT_MAX_BYTES = 72


def _truncate_password(password: str) -> bytes:
    """Trim to bcrypt's 72-byte limit without splitting a multi-byte char.

    Mirrors makemerich-backend's app/auth/service.py::_truncate_password
    exactly; a different trim would silently fail to verify imported hashes
    of passwords longer than 72 bytes.
    """
    raw = password.encode("utf-8")
    if len(raw) <= _BCRYPT_MAX_BYTES:
        return raw
    trimmed = raw[:_BCRYPT_MAX_BYTES]
    while trimmed:
        try:
            trimmed.decode("utf-8")
            return trimmed
        except UnicodeDecodeError:
            trimmed = trimmed[:-1]
    return raw[:_BCRYPT_MAX_BYTES]


def _is_bcrypt(stored: str) -> bool:
    """bcrypt hashes are '$2<variant>$<cost>$...'; $2a/$2b/$2y are all in the wild."""
    return stored.startswith(("$2a$", "$2b$", "$2y$"))


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        _truncate_password(password), bcrypt.gensalt(rounds=auth_settings.bcrypt_rounds)
    ).decode("utf-8")


def verify_password(password: str, stored: str) -> bool:
    """True when `password` matches `stored`, whichever scheme wrote it."""
    if not stored:
        return False
    try:
        if _is_bcrypt(stored):
            return bcrypt.checkpw(_truncate_password(password), stored.encode("utf-8"))
        return _verify_pbkdf2(password, stored)
    except (ValueError, TypeError) as exc:
        # A malformed/corrupt stored hash is a failed login, not a 500.
        logger.warning("Password verification failed on a malformed hash: %s", exc)
        return False


def _verify_pbkdf2(password: str, stored: str) -> bool:
    scheme, rounds_s, salt, expected = stored.split("$", 3)
    dk = hashlib.pbkdf2_hmac(
        scheme.replace("pbkdf2_", ""), password.encode(), salt.encode(), int(rounds_s)
    )
    # constant-time compare to avoid timing leaks
    return hmac.compare_digest(dk.hex(), expected)


def needs_rehash(stored: str) -> bool:
    """True when a *verified* hash should be rewritten with current settings.

    Covers both a legacy pbkdf2 record and a bcrypt one made at a lower cost
    than we now use (including hashes imported from another application).
    """
    if not _is_bcrypt(stored):
        return True
    try:
        cost = int(stored.split("$")[2])
    except (IndexError, ValueError):
        return True
    return cost < auth_settings.bcrypt_rounds


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

def create_access_token(
    subject: str,
    extra_claims: dict[str, Any] | None = None,
    ttl_minutes: int | None = None,
) -> str:
    """Issue a signed HS256 access token. `subject` becomes the `sub` claim.

    Every token gets a unique `jti` — JWTs are otherwise stateless, so logout
    (see features/blacklist.py) has nothing else to key a revocation entry on.
    """
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "iss": auth_settings.jwt_issuer,
        "aud": auth_settings.jwt_audience,
        "jti": secrets.token_hex(16),
        "iat": now,
        "exp": now + timedelta(minutes=ttl_minutes or auth_settings.access_ttl_minutes),
        **(extra_claims or {}),
    }
    return jwt.encode(payload, auth_settings.jwt_secret, algorithm=auth_settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    """Verify signature + expiry + issuer/audience. Raises jwt.PyJWTError on any failure."""
    return jwt.decode(
        token,
        auth_settings.jwt_secret,
        algorithms=[auth_settings.jwt_algorithm],
        issuer=auth_settings.jwt_issuer,
        audience=auth_settings.jwt_audience,
    )
