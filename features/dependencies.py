"""FastAPI auth dependencies + the request-scoped current user.

Any route can scope itself to the authenticated caller::

    from features.dependencies import get_current_user, AuthUser

    @router.get("/things")
    async def list_things(user: AuthUser = Depends(get_current_user)):
        return await service.list_for_owner(user.user_id)

Decodes the Authorization header directly (no global middleware stashing the
user on request.state first) — this service has exactly two access levels
(any authenticated user, or platform staff), fully expressed by these two
dependencies, so a blanket middleware isn't needed the way the source
implementation used one to gate an entire monolith's unrelated routes.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel

from .blacklist import is_token_revoked
from .security import decode_token


class AuthUser(BaseModel):
    user_id: str
    email: str | None = None
    name: str | None = None
    org_id: str | None = None
    is_portless: bool = False
    """True for platform staff (see features/organization.py) — such callers
    bypass per-organization data filtering everywhere."""


def _user_from_claims(claims: dict) -> AuthUser:
    return AuthUser(
        user_id=str(claims.get("sub")),
        email=claims.get("email"),
        name=claims.get("name"),
        org_id=claims.get("org_id"),
        is_portless=bool(claims.get("is_portless", False)),
    )


async def get_current_user(request: Request) -> AuthUser:
    """Return the authenticated user or raise 401."""
    cached = getattr(request.state, "user", None)
    if isinstance(cached, AuthUser):
        return cached

    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth.split(" ", 1)[1].strip()
    try:
        claims = decode_token(token)
    except Exception as exc:  # noqa: BLE001 — any decode/expiry failure → 401
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if await is_token_revoked(claims.get("jti")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked — please log in again",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = _user_from_claims(claims)
    request.state.user = user
    return user


def require_org_scope(user: AuthUser) -> str | None:
    """Resolve the org filter a data-owning endpoint should apply.

    Returns ``None`` for platform staff (unrestricted) or the caller's
    ``org_id`` otherwise. Raises 403 for a non-staff caller with no
    ``org_id`` — a real, expected state for a newly self-registered user who
    hasn't been assigned to an organization yet — instead of silently
    treating a missing filter as "show everything."
    """
    if user.is_portless:
        return None
    if not user.org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is not yet assigned to an organization. "
                   "Contact an administrator.",
        )
    return user.org_id


def require_portless(user: AuthUser = Depends(get_current_user)) -> AuthUser:
    """FastAPI dependency: 403s unless the caller is platform staff.

    Use to gate features reserved for platform staff (organization admin) —
    see features/organization.py::is_portless_user.
    """
    if not user.is_portless:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This feature is restricted to platform staff.",
        )
    return user
