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

"Administrator" means membership of an admin-type app account
(features/app_accounts.py::is_admin_account), carried in the token as
``role``. There is no configured admin ID, no separate platform-staff
allowlist and no organization scope: an account is the only thing a user
belongs to.
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
    scope. Downstream services filter their data on this; ``role`` is derived
    from it at sign-in."""
    role: str = "user"
    """"admin" when the scoped account is admin-type, else "user" — minted into
    the token by service._token_for from the account record, and what
    require_admin checks. Defaults to "user" so a token without the claim
    (none this service mints) can never be an administrator by omission."""


def _user_from_claims(claims: dict) -> AuthUser:
    return AuthUser(
        user_id=str(claims.get("sub")),
        email=claims.get("email"),
        name=claims.get("name"),
        account_id=claims.get("account_id"),
        role=str(claims.get("role") or "user"),
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
    """FastAPI dependency: 403s unless the caller's session is scoped to an
    admin-type app account.

    This is the gate on app-account and user administration. Admin means "a
    member of an admin application" — a property of the account the user's
    record belongs to (features/app_accounts.py::is_admin_account), not an
    email on a deploy-time list and not an ID in this service's config.

    Read from the token's ``role`` claim, which service._token_for derives
    from that account record at sign-in, rather than re-fetched per request:
    the claim is signed, revocation was already checked above, and it is the
    same claim llm-gateway and knowledge-service gate their own admin routes
    on — so all three agree on who is an administrator for the life of a
    token.
    """
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This feature is restricted to administrators.",
        )
    return user
