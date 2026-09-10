"""HTTP routes for the Auth service.

1:1 port of the calling application's ``backend/services/auth/router.py`` —
same paths, same status codes, same access model. Business logic stays in
``features/service.py``; this layer only translates HTTP <-> the core.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status

from features import app_accounts, service
from features.dependencies import AuthUser, get_current_user, require_admin
from features.schemas import (
    AppAccountRecord,
    AssignUserAccountsRequest,
    CreateAppAccountRequest,
    LoginAccount,
    LoginRequest,
    RegisterRequest,
    SelectAccountRequest,
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
    """Register a new user record, in ONE application.

    ``payload.account_id`` is optional and is the record's only scope — the
    application it belongs to. Omit it for a user who is not tied to one yet;
    an administrator can assign accounts later via
    PATCH /auth/users/{user_id}/accounts.

    An email that already exists in a DIFFERENT application is not a conflict:
    it creates a second, independent record with its own user_id and its own
    password. 409 is returned only for the same email in the same application.
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

    The response lists every application this user may sign in through
    (``accounts``) — only after the password has been verified, so an
    unauthenticated caller can't probe an email's memberships. More than one
    entry means the client should let the user pick, then exchange the choice
    via POST /auth/me/account.
    """
    if payload.account_id:
        await app_accounts.assert_login_allowed(payload.account_id)

    return await service.login(payload)


@router.post("/me/account", response_model=TokenResponse)
async def select_my_account(
    payload: SelectAccountRequest,
    user: AuthUser = Depends(get_current_user),
) -> TokenResponse:
    """Re-issue the caller's token scoped to one of their own applications.

    The second half of a multi-account sign-in: 403 if the user doesn't belong
    to that application, or if it's disabled. Needed as its own endpoint
    because the account is a token claim — downstream services scope their
    data on it, so switching means a new token, not a client-side flag.
    """
    return await service.select_account(user.user_id, payload.account_id)


@router.get("/me", response_model=UserPublic)
async def me(user: AuthUser = Depends(get_current_user)) -> UserPublic:
    """Return the current user's profile (validates the bearer token)."""
    # Pass the token's account so `selected`/`is_admin` describe THIS session,
    # not the user's stored default — they differ after POST /auth/me/account.
    found = await service.get_user(user.user_id, scoped_account_id=user.account_id)
    if found is None:
        # Token valid but user no longer exists in this service's own store
        # (e.g. an app account whose users live elsewhere) — fall back to the
        # token's claims.
        from features.config import auth_settings

        # The flat account_id is gone from the response, so the token's account
        # has to be reported the way every other path reports it: as the
        # selected entry of `accounts`. There is no record to look up a display
        # name in on this path, so the ID stands in for it.
        accounts = (
            [LoginAccount(account_id=user.account_id, name=user.account_id, selected=True)]
            if user.account_id
            else []
        )
        return UserPublic(
            user_id=user.user_id,
            email=user.email or "",
            name=user.name or "",
            accounts=accounts,
            is_admin=bool(user.account_id) and user.account_id == auth_settings.admin_account_id,
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
# User administration — administrators only (see require_admin)
#
# A user's only scope is the app account their record belongs to; there is no
# organization or tenant to manage. One record is one person in one account,
# so "membership" is which records exist — set through the accounts endpoint
# below and nowhere else.
# ---------------------------------------------------------------------------

@router.get("/users", response_model=list[UserPublic])
async def list_users(_: AuthUser = Depends(require_admin)) -> list[UserPublic]:
    """List every user RECORD, including the account membership behind it.

    One row per (email, account) pair: a person who holds two applications
    appears twice, with a different user_id each time, because those really
    are two separately credentialed records. Each row still carries the full
    ``accounts`` list, so the rows for one person can be related to each other.
    """
    return await service.list_users()


@router.patch("/users/{user_id}/accounts", response_model=UserPublic)
async def assign_user_accounts(
    user_id: str,
    payload: AssignUserAccountsRequest,
    _: AuthUser = Depends(require_admin),
) -> UserPublic:
    """Set which applications a user may sign in through.

    The list is a desired end state, and the service reconciles the person's
    user records to match it: an account they lack gets a new record (cloning
    this record's name and password hash so they can sign in at once), and an
    account dropped from the list has its record DELETED along with its
    credentials. Accounts already held are untouched — their passwords are
    independent and a membership edit must not reset them.

    ``user_id`` names one of the person's records; the reconciliation applies
    to every record sharing its email. The FIRST entry is their default (what
    a login naming no account resolves to), and more than one makes the
    sign-in account picker appear. An empty list removes them from every
    application, deleting all of their records. 404 if any ID isn't a
    registered app account.
    """
    return await service.assign_user_accounts(user_id, payload.account_ids)


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
    """Register an application and mint its ID.

    ``account_id`` is generated, not supplied: it is an authorization key —
    the value the application sends as LoginRequest.account_id and the value
    downstream services scope their data on — so it must not be guessable.
    The created record in the response carries the UUID to put into that
    application's configuration.
    """
    return await app_accounts.create_app_account(
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
