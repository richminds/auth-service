"""HTTP routes for the Auth service.

1:1 port of the calling application's ``backend/services/auth/router.py`` —
same paths, same status codes, same access model. Business logic stays in
``features/service.py``; this layer only translates HTTP <-> the core.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status

from features import app_accounts, service
from features.dependencies import AuthUser, get_current_user, require_admin, require_portless
from features.schemas import (
    AppAccountRecord,
    AssignUserOrgRequest,
    CreateAppAccountRequest,
    CreateOrganizationRequest,
    LoginRequest,
    OrganizationRecord,
    RegisterRequest,
    RenameOrganizationRequest,
    TokenResponse,
    UpdateAppAccountRequest,
    UserPublic,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/health")
async def auth_health() -> dict[str, str]:
    return {"status": "ok", "service": "auth"}


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest) -> TokenResponse:
    """Register a new user.

    ``payload.org_id`` is optional — give it to join that organization
    immediately (must already exist, see POST /auth/organizations/register).
    Omit it to sign up as a guest and join one later via
    POST /auth/me/organization.
    """
    return await service.register(payload)


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest) -> TokenResponse:
    """Log in.

    One endpoint for every application. ``payload.account_id`` names the
    application the login is for: it must not be disabled, and the user must
    belong to it (see features/service.py::login). Credentials themselves are
    always checked against this service's own user store — this service is
    the source of truth for identity, it doesn't reach into an application's
    private database.
    """
    if payload.account_id:
        await app_accounts.assert_login_allowed(payload.account_id)

    return await service.login(payload)


@router.get("/me", response_model=UserPublic)
async def me(user: AuthUser = Depends(get_current_user)) -> UserPublic:
    """Return the current user's profile (validates the bearer token)."""
    found = await service.get_user(user.user_id)
    if found is None:
        # Token valid but user no longer exists in this service's own store
        # (e.g. an app account whose users live elsewhere) — fall back to the
        # token's claims.
        from features.config import auth_settings

        return UserPublic(
            user_id=user.user_id,
            email=user.email or "",
            name=user.name or "",
            account_id=user.account_id,
            org_id=user.org_id,
            is_admin=bool(user.account_id) and user.account_id == auth_settings.admin_account_id,
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
# Organization self-service — no staff gate. Public creation so a new
# organization can obtain an org_id before anyone has signed up under it;
# the join endpoint lets a signed-up guest attach themselves to one
# afterwards, one-way (guest -> assigned), without staff involvement.
# ---------------------------------------------------------------------------

@router.post(
    "/organizations/register",
    response_model=OrganizationRecord,
    status_code=status.HTTP_201_CREATED,
)
async def register_organization(payload: CreateOrganizationRequest) -> OrganizationRecord:
    """Self-serve organization creation — no auth required.

    Returns the new org_id for the caller to hand out to teammates (e.g. in
    the signup form) or pass to POST /auth/register directly.
    """
    return await service.create_organization(payload.name, created_by="self-serve")


@router.post("/me/organization", response_model=TokenResponse)
async def join_my_organization(
    payload: AssignUserOrgRequest,
    user: AuthUser = Depends(get_current_user),
) -> TokenResponse:
    """Attach the current (guest) user to an organization missed at signup.

    Only works while the account is still unassigned (org_id is None) — once
    a user belongs to an organization, changing it is staff-only (see
    PATCH /auth/users/{user_id}/organization) so a user can't unilaterally
    hop into another organization's scoped data.
    """
    return await service.join_organization(user.user_id, payload.org_id)


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


@router.patch("/organizations/{org_id}", response_model=OrganizationRecord)
async def rename_organization(
    org_id: str,
    payload: RenameOrganizationRequest,
    _: AuthUser = Depends(require_portless),
) -> OrganizationRecord:
    """Rename an organization. 404 if org_id doesn't exist."""
    return await service.rename_organization(org_id, payload.name)


@router.delete(
    "/organizations/{org_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None
)
async def delete_organization(
    org_id: str,
    _: AuthUser = Depends(require_portless),
) -> None:
    """Delete an organization.

    404 if org_id doesn't exist, 409 if it still has member users (reassign
    or remove them first — see PATCH /auth/users/{user_id}/organization), 403
    for the reserved Guest/Portless system organizations (see
    features/service.py::delete_organization).
    """
    await service.delete_organization(org_id)


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


# ---------------------------------------------------------------------------
# App accounts — the applications registered against this service. Platform
# staff only.
#
# Distinct from the organization endpoints above: an organization is a TENANT
# users belong to, an app account is an APPLICATION that authenticates against
# this service. Separate concepts, separate collections — see
# features/app_accounts.py.
# ---------------------------------------------------------------------------

@router.post(
    "/accounts",
    response_model=AppAccountRecord,
    status_code=status.HTTP_201_CREATED,
)
async def register_app_account(
    payload: CreateAppAccountRequest,
    user: AuthUser = Depends(require_admin),
) -> AppAccountRecord:
    """Register an application. 409 if the account_id is already taken.

    ``account_id`` is supplied by the caller, not generated: it is the value
    the application will send as LoginRequest.account_id, so it has to be a
    value that application already knows.
    """
    return await app_accounts.create_app_account(
        payload.account_id,
        payload.name,
        payload.description,
        created_by=user.user_id,
        app_type=payload.app_type,
        app_url=payload.app_url,
    )


@router.get("/accounts", response_model=list[AppAccountRecord])
async def list_app_accounts(_: AuthUser = Depends(require_admin)) -> list[AppAccountRecord]:
    """List every registered application."""
    return await app_accounts.list_app_accounts()


@router.get("/accounts/{account_id}", response_model=AppAccountRecord)
async def get_app_account(
    account_id: str,
    _: AuthUser = Depends(require_admin),
) -> AppAccountRecord:
    return await app_accounts.get_app_account(account_id)


@router.patch("/accounts/{account_id}", response_model=AppAccountRecord)
async def update_app_account(
    account_id: str,
    payload: UpdateAppAccountRequest,
    _: AuthUser = Depends(require_admin),
) -> AppAccountRecord:
    """Partial update of name/description/type/url/enabled. ``account_id`` is
    immutable."""
    return await app_accounts.update_app_account(
        account_id,
        name=payload.name,
        description=payload.description,
        app_type=payload.app_type,
        app_url=payload.app_url,
        enabled=payload.enabled,
    )


@router.delete(
    "/accounts/{account_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None
)
async def delete_app_account(
    account_id: str,
    _: AuthUser = Depends(require_admin),
) -> None:
    """Deregister an application. 404 if the account_id doesn't exist.

    This removes the record only — it does not touch users who belong to
    this application, and it frees the ID for reuse. Prefer PATCH with
    ``enabled: false`` to take an application out of service reversibly.
    """
    await app_accounts.delete_app_account(account_id)
