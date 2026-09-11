"""Logout / token revocation.

Access tokens are stateless JWTs, so "logging out" a specific token means
recording its `jti` (see security.py::create_access_token) in a short-lived
blacklist that every subsequent request is checked against. The entry's TTL
is set to the token's own remaining lifetime, so it expires from the store at
the same moment the token itself would have stopped being valid anyway.

Thin wrapper over features.repository.RevocationRepository — same function
names (revoke_token / is_token_revoked) as the source implementation's
shared/auth/blacklist.py, so callers migrating from an in-process import to
this module change nothing but the import path.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .repository import get_revocation_repository


async def revoke_token(jti: str, exp: int, ttl_seconds: int | None = None) -> None:
    """Blacklist a token's `jti` until its natural expiry (`exp`, epoch seconds).

    ``ttl_seconds`` overrides that, and refresh-token rotation needs it to.
    The default is right for logout — a token past `exp` is refused by
    ``decode_token`` anyway, so blacklisting it would buy nothing — but
    ``POST /auth/refresh-token`` accepts an ALREADY-EXPIRED token by design.
    Revoking one of those with the exp-derived TTL computes a negative value
    and returns here having written nothing, which would silently make
    rotation a no-op and let the same token be refreshed forever. The caller
    passes the remaining refresh window instead, which is exactly how long the
    entry has to outlive the token to be worth anything.
    """
    if ttl_seconds is None:
        ttl_seconds = int(exp - datetime.now(timezone.utc).timestamp())
    if ttl_seconds <= 0:
        return  # nothing left to blacklist
    await get_revocation_repository().revoke(jti, ttl_seconds)


async def is_token_revoked(jti: str | None) -> bool:
    """True if this token's `jti` was revoked (and hasn't naturally expired)."""
    if not jti:
        return False
    return await get_revocation_repository().is_revoked(jti)
