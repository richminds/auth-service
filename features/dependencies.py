"""FastAPI auth dependencies + the request-scoped current user.

Any route can scope itself to the authenticated caller::

    from features.dependencies import get_current_user, AuthUser

    @router.get("/things")
    async def list_things(user: AuthUser = Depends(get_current_user)):
        return await service.list_for_owner(user.user_id)

Decodes the Authorization header directly (no global middleware stashing the
user on request.state first) — this service has exactly two access levels
(any authenticated user, or an administrator), fully expressed by these two
dependencies, so a blanket middleware isn't needed the way the source
implementation used one to gate an entire monolith's unrelated routes.

"Administrator" means membership of the configured admin app account. There
is no separate platform-staff allowlist and no organization scope: an account
is the only thing a user belongs to.
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
    account_id: str | None = None
    """The application this user belongs to (an app account) and their only
    scope. Membership of the configured admin app account is what
    require_admin checks; downstream services filter their data on this."""


def _user_from_claims(claims: dict) -> AuthUser:
    return AuthUser(
        user_id=str(claims.get("sub")),
        email=claims.get("email"),
        name=claims.get("name"),
        account_id=claims.get("account_id"),
    )


async def get_current_user(request: Request) -> AuthUser:
    """Return the authenticated user or raise 401.

    Every token this service accepts is one it issued itself
    (features/security.py) — there is a single token format, so a single
    verifier.
    """
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
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = _user_from_claims(claims)
    jti = claims.get("jti")

    if await is_token_revoked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked — please log in again",
            headers={"WWW-Authenticate": "Bearer"},
        )

    request.state.user = user
    return user


def require_admin(user: AuthUser = Depends(get_current_user)) -> AuthUser:
    """FastAPI dependency: 403s unless the caller belongs to the admin app
    account (``AUTH_ADMIN_ACCOUNT_ID``, the RichMinds admin application).

    This is the gate on app-account and user administration. Admin means "a
    member of the admin application" — a fact about the user's own record,
    not an email on a deploy-time list.
    """
    from .config import auth_settings

    if not user.account_id or user.account_id != auth_settings.admin_account_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This feature is restricted to administrators.",
        )
    return user
