"""HTTP routes for the Auth service.

1:1 port of the calling application's ``backend/services/auth/router.py`` —
same paths, same status codes, same access model. Business logic stays in
``features/service.py``; this layer only translates HTTP <-> the core.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status

from features import service
from features.dependencies import AuthUser, get_current_user, require_portless
from features.schemas import (
    AssignUserOrgRequest,
    CreateOrganizationRequest,
    LoginRequest,
    OrganizationRecord,
    RegisterRequest,
    TokenResponse,
    UserPublic,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/health")
async def auth_health() -> dict[str, str]:
    return {"status": "ok", "service": "auth"}


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest) -> TokenResponse:
    return await service.register(payload)


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest) -> TokenResponse:
    return await service.login(payload)


@router.get("/me", response_model=UserPublic)
async def me(user: AuthUser = Depends(get_current_user)) -> UserPublic:
    """Return the current user's profile (validates the bearer token)."""
    found = await service.get_user(user.user_id)
    if found is None:
        # Token valid but user no longer exists — return token claims as fallback.
        return UserPublic(
            user_id=user.user_id,
            email=user.email or "",
            name=user.name or "",
            org_id=user.org_id,
            is_portless=user.is_portless,
        )
    return found


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def logout(request: Request, user: AuthUser = Depends(get_current_user)) -> None:
    """Revoke the bearer token used for this request (see service.logout).

    Reachable by every logged-in user, staff or not — logging out isn't a
    staff-only feature.
    """
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.split(" ", 1)[1].strip() if auth_header.lower().startswith("bearer ") else ""
    await service.logout(token, user.user_id)


# ---------------------------------------------------------------------------
# Organization admin — platform staff only (see require_portless)
# ---------------------------------------------------------------------------

@router.post(
    "/organizations",
    response_model=OrganizationRecord,
    status_code=status.HTTP_201_CREATED,
)
async def create_organization(
    payload: CreateOrganizationRequest,
    user: AuthUser = Depends(require_portless),
) -> OrganizationRecord:
    """Create a new organization."""
    return await service.create_organization(payload.name, created_by=user.user_id)


@router.get("/organizations", response_model=list[OrganizationRecord])
async def list_organizations(_: AuthUser = Depends(require_portless)) -> list[OrganizationRecord]:
    """List every organization."""
    return await service.list_organizations()


@router.get("/users", response_model=list[UserPublic])
async def list_users(_: AuthUser = Depends(require_portless)) -> list[UserPublic]:
    """List every registered user, including their current org assignment."""
    return await service.list_users()


@router.patch("/users/{user_id}/organization", response_model=UserPublic)
async def assign_user_organization(
    user_id: str,
    payload: AssignUserOrgRequest,
    _: AuthUser = Depends(require_portless),
) -> UserPublic:
    """Assign a user to an organization."""
    return await service.assign_user_organization(user_id, payload.org_id)
