"""Auth business logic — register, authenticate, issue tokens, organization admin."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from uuid import uuid4

from .blacklist import revoke_token
from .organization import GUEST_ORG_ID, PORTLESS_ORG_ID, is_portless_user
from .repository import get_org_repository, get_repository
from .schemas import (
    LoginAccount,
    LoginRequest,
    OrganizationRecord,
    RegisterRequest,
    TokenResponse,
    UserPublic,
    UserRecord,
)
from .security import (
    create_access_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
)

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class EmailTakenError(Exception):
    """Raised when registering an email that already exists (409)."""


class InvalidEmailError(Exception):
    """Raised on malformed email (422)."""


class InvalidCredentialsError(Exception):
    """Raised on bad login (401)."""


class OrganizationNotFoundError(Exception):
    """Raised when assigning a user to an org_id that doesn't exist (404)."""


class UserNotFoundError(Exception):
    """Raised when assigning an org to a user_id that doesn't exist (404)."""


class AlreadyAssignedError(Exception):
    """Raised when a user who already belongs to an organization calls the
    self-service join endpoint (409) — changing an existing assignment stays
    a staff-only action (see assign_user_organization)."""


class AccountNotAllowedError(Exception):
    """Raised when a signed-in user asks for a token scoped to an app account
    they don't belong to (403). Distinct from the login-time check, which
    reports the same error as a bad password because the caller there is
    still unauthenticated."""


class OrganizationHasMembersError(Exception):
    """Raised when deleting an organization that still has member users (409)
    — deleting it out from under them would leave their `org_id` dangling,
    which require_org_scope has no defined behaviour for. Reassign or remove
    every member first (see assign_user_organization)."""


class OrganizationProtectedError(Exception):
    """Raised when deleting one of the two reserved system organizations
    (403) — GUEST_ORG_ID (every unassigned signup lands there) and
    PORTLESS_ORG_ID (every platform-staff signup lands there). Deleting
    either breaks register()/ensure_guest_organization() for every caller,
    not just this organization's members."""


def _new_user_id() -> str:
    return f"USR-{uuid4().hex[:12].upper()}"


def _new_org_id() -> str:
    return f"ORG-{uuid4().hex[:12].upper()}"


def _token_for(
    user: UserRecord,
    account_id: str | None = None,
    accounts: list[LoginAccount] | None = None,
) -> TokenResponse:
    scoped_account_id = account_id or user.account_id
    token = create_access_token(
        subject=user.user_id,
        extra_claims={
            "email": user.email,
            "name": user.name,
            # The application this token is scoped to. require_admin reads
            # this, and knowledge-service scopes its data on it, so it has to
            # travel in the token rather than be re-fetched.
            "account_id": scoped_account_id,
            "org_id": user.org_id,
            "is_portless": is_portless_user(user.email),
        },
    )
    return TokenResponse(
        access_token=token,
        user=UserPublic.from_record(user),
        account_id=scoped_account_id,
        accounts=accounts or [],
    )


def effective_account_ids(user: UserRecord) -> list[str]:
    """Every app account ``user`` may sign in through, primary one first.

    The single place ``account_id`` (primary) and ``account_ids`` (additional)
    are combined, so membership means the same thing at login, at account
    switch, and in the list offered to the client.
    """
    ordered = [user.account_id, *user.account_ids]
    seen: list[str] = []
    for account_id in ordered:
        if account_id and account_id not in seen:
            seen.append(account_id)
    return seen


async def _login_accounts(account_ids: list[str]) -> list[LoginAccount]:
    """Resolve display names for the accounts offered at login.

    An ID with no app-account record (registered before the collection
    existed) still appears, named after itself — dropping it would lock the
    user out of the only account they have.
    """
    from .repository import get_app_account_repository

    repo = get_app_account_repository()
    out: list[LoginAccount] = []
    for account_id in account_ids:
        record = await repo.get(account_id)
        if record is not None and not record.enabled:
            continue
        out.append(LoginAccount(account_id=account_id, name=record.name if record else account_id))
    return out


async def register(req: RegisterRequest) -> TokenResponse:
    """Register a new user.

    A platform-staff email (AUTH_PORTLESS_EMAILS) always gets the reserved
    staff org_id, regardless of what ``req.org_id`` says. Otherwise, if the
    caller supplied ``org_id`` it must reference an existing organization —
    the new account joins it directly. If it's omitted, the account lands in
    the shared Guest organization (see ensure_guest_organization) instead of
    staying unassigned; it can move to a real one later via
    join_organization (self-service, while still on Guest) or
    assign_user_organization (staff, any time).
    """
    email = req.email.strip().lower()
    if not _EMAIL_RE.match(email):
        raise InvalidEmailError(f"{req.email!r} is not a valid email address")

    repo = get_repository()
    if await repo.get_by_email(email) is not None:
        raise EmailTakenError(f"An account with {email!r} already exists")

    # The application the user belongs to. Validated so a typo can't quietly
    # create a user tied to an application that doesn't exist — including a
    # near-miss on the admin account, which would hand out nothing but
    # confusion later.
    if req.account_id:
        from .app_accounts import AdminAccountClosedError, AppAccountNotFoundError
        from .config import auth_settings
        from .repository import get_app_account_repository

        if await get_app_account_repository().get(req.account_id) is None:
            raise AppAccountNotFoundError(f"App account {req.account_id!r} not found")

        # Registration is public, so joining the admin account cannot be. Allow
        # it exactly once, to create the first administrator on a fresh
        # deployment; after that the account is closed to self-registration and
        # further admins have to be made deliberately. Without this, anyone who
        # knows the admin account_id could sign up as an administrator.
        if req.account_id == auth_settings.admin_account_id:
            existing_admins = [
                u for u in await repo.list_all() if u.account_id == auth_settings.admin_account_id
            ]
            if existing_admins:
                raise AdminAccountClosedError(
                    "The administrator account is not open to self-registration"
                )
            logger.warning(
                "Auth: bootstrapping the FIRST administrator (%s) into account %s",
                email,
                req.account_id,
            )

    if is_portless_user(email):
        org_id = PORTLESS_ORG_ID
    elif req.org_id and req.org_id != GUEST_ORG_ID:
        if await get_org_repository().get(req.org_id) is None:
            raise OrganizationNotFoundError(f"Organization {req.org_id!r} not found")
        org_id = req.org_id
    else:
        # Omitted, or explicitly "Guest" (what the UI's default sends) — either
        # way, bootstrap it rather than doing a plain existence check, so the
        # very first signup ever made against an empty database still works.
        await ensure_guest_organization()
        org_id = GUEST_ORG_ID

    user = UserRecord(
        user_id=_new_user_id(),
        email=email,
        name=req.name.strip(),
        password_hash=hash_password(req.password),
        account_id=req.account_id,
        org_id=org_id,
        created_at=datetime.now(timezone.utc),
    )
    await repo.create(user)
    logger.info(
        "Auth: registered user %s (%s) account=%s org=%s",
        user.user_id,
        email,
        req.account_id,
        org_id,
    )
    return _token_for(user)


async def ensure_guest_organization() -> OrganizationRecord:
    """Idempotently ensure the shared Guest organization exists.

    Called on every guest signup (register() with no org_id) and, best
    effort, at service startup — either way it's a single lookup once the
    record exists. Handles losing a create race against a concurrent caller
    (e.g. two guest signups on a cold start) by re-fetching instead of
    surfacing a spurious 500.
    """
    org_repo = get_org_repository()
    existing = await org_repo.get(GUEST_ORG_ID)
    if existing is not None:
        return existing

    org = OrganizationRecord(
        org_id=GUEST_ORG_ID,
        name=GUEST_ORG_ID,
        created_by="system:bootstrap",
        created_at=datetime.now(timezone.utc),
    )
    try:
        await org_repo.create(org)
    except Exception:  # noqa: BLE001 — lost a create race; the winner is fine to use
        winner = await org_repo.get(GUEST_ORG_ID)
        if winner is not None:
            return winner
        raise
    logger.info("Auth: bootstrapped the shared Guest organization (org_id=%s)", GUEST_ORG_ID)
    return org


async def login(req: LoginRequest) -> TokenResponse:
    repo = get_repository()
    user = await repo.get_by_email(req.email.strip().lower())
    # Always run verify to keep timing roughly constant whether or not the user exists.
    if user is None or not verify_password(req.password, user.password_hash):
        raise InvalidCredentialsError("Invalid email or password")

    # The credentials are valid — but for WHICH application? When the caller
    # names an account, a user who does not belong to it must not be let in
    # through it. Without this, account_id would only pick a login
    # implementation and never actually mean anything.
    #
    # Users predating account_id have none at all; those are allowed through
    # any application rather than being locked out of everything. Tightening
    # that is a migration, not a code change — see the README.
    allowed = effective_account_ids(user)
    if req.account_id and allowed and req.account_id not in allowed:
        logger.warning(
            "Auth: %s belongs to accounts %s but tried to sign in via %s",
            user.user_id,
            allowed,
            req.account_id,
        )
        # Same error as a bad password: which accounts a user belongs to
        # isn't something an unauthenticated caller should be able to probe.
        raise InvalidCredentialsError("Invalid email or password")

    # Upgrade a stale hash now that we hold the plaintext — a legacy pbkdf2
    # record, or a bcrypt one imported at a lower cost than we write today.
    # Doing it on login is what lets another application's users be imported
    # with their existing hashes and migrate to our scheme without a reset.
    # Best effort: a failed rewrite must never fail the sign-in.
    if needs_rehash(user.password_hash):
        try:
            await repo.update_password_hash(user.user_id, hash_password(req.password))
            logger.info("Auth: upgraded stored password hash for %s", user.user_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Auth: could not upgrade password hash for %s: %s", user.user_id, exc)

    logger.info("Auth: login OK for %s (account=%s)", user.user_id, req.account_id)
    accounts = await _login_accounts(allowed)
    # Scope the token to the account the caller named, or — when they named
    # none — the user's default one. A user with several accounts gets a token
    # for the default plus the full list, so the client can offer a choice and
    # exchange it via select_account without asking for the password again.
    selected = req.account_id or (accounts[0].account_id if accounts else None)
    return _token_for(user, account_id=selected, accounts=accounts)


async def select_account(user_id: str, account_id: str) -> TokenResponse:
    """Re-issue the caller's token scoped to one of their own app accounts.

    The post-login half of multi-account sign-in: the account is baked into
    the token's claims (knowledge-service scopes its data on it), so switching
    means a new token. Membership is re-checked against the stored record
    rather than trusted from the request.
    """
    user = await get_repository().get_by_id(user_id)
    if user is None:
        raise UserNotFoundError(f"User {user_id!r} not found")

    allowed = effective_account_ids(user)
    if account_id not in allowed:
        raise AccountNotAllowedError(f"You do not belong to application {account_id!r}")

    from .app_accounts import assert_login_allowed

    await assert_login_allowed(account_id)

    logger.info("Auth: user %s switched to account %s", user_id, account_id)
    return _token_for(user, account_id=account_id, accounts=await _login_accounts(allowed))


async def logout(token: str, user_id: str) -> None:
    """Revoke ``token`` (see features/blacklist.py) so it can't be reused.

    Best-effort: the router's ``get_current_user`` dependency already proved
    the token was valid, so a decode failure here would be unexpected —
    still, logout should never fail from the client's perspective (it's
    discarding the token locally either way), so any error is logged and
    swallowed rather than raised.
    """
    if not token:
        return
    try:
        claims = decode_token(token)
        await revoke_token(claims["jti"], claims["exp"])
        logger.info("Auth: user %s logged out (token revoked)", user_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Auth: logout for user %s could not revoke token: %s", user_id, exc)


async def get_user(user_id: str) -> UserPublic | None:
    user = await get_repository().get_by_id(user_id)
    return UserPublic.from_record(user) if user else None


# ---------------------------------------------------------------------------
# Organization admin — callers are gated to platform staff at the router
# (features.dependencies.require_portless), not re-checked here.
# ---------------------------------------------------------------------------

async def create_organization(name: str, created_by: str) -> OrganizationRecord:
    org = OrganizationRecord(
        org_id=_new_org_id(),
        name=name.strip(),
        created_by=created_by,
        created_at=datetime.now(timezone.utc),
    )
    await get_org_repository().create(org)
    logger.info("Auth: organization %s (%r) created by %s", org.org_id, org.name, created_by)
    return org


async def list_organizations() -> list[OrganizationRecord]:
    return await get_org_repository().list_all()


async def rename_organization(org_id: str, name: str) -> OrganizationRecord:
    updated = await get_org_repository().rename(org_id, name.strip())
    if updated is None:
        raise OrganizationNotFoundError(f"Organization {org_id!r} not found")
    logger.info("Auth: organization %s renamed to %r", org_id, updated.name)
    return updated


async def delete_organization(org_id: str) -> None:
    if org_id in (GUEST_ORG_ID, PORTLESS_ORG_ID):
        raise OrganizationProtectedError(
            f"Organization {org_id!r} is a reserved system organization"
        )
    if await get_org_repository().get(org_id) is None:
        raise OrganizationNotFoundError(f"Organization {org_id!r} not found")

    members = [u for u in await get_repository().list_all() if u.org_id == org_id]
    if members:
        raise OrganizationHasMembersError(
            f"Organization {org_id!r} still has {len(members)} member(s) — "
            "reassign or remove them first"
        )

    await get_org_repository().delete(org_id)
    logger.info("Auth: organization %s deleted", org_id)


async def list_users() -> list[UserPublic]:
    users = await get_repository().list_all()
    return [UserPublic.from_record(u) for u in users]


async def assign_user_organization(user_id: str, org_id: str) -> UserPublic:
    """Assign an existing user to an existing organization."""
    if await get_org_repository().get(org_id) is None:
        raise OrganizationNotFoundError(f"Organization {org_id!r} not found")

    updated = await get_repository().update_org(user_id, org_id)
    if updated is None:
        raise UserNotFoundError(f"User {user_id!r} not found")

    logger.info("Auth: user %s assigned to organization %s", user_id, org_id)
    return UserPublic.from_record(updated)


async def assign_user_accounts(
    user_id: str, account_id: str | None, account_ids: list[str]
) -> UserPublic:
    """Set which app accounts a user may sign in through (staff only).

    Every ID is validated against the app-account collection first, so a typo
    can't leave a user pointed at an application that doesn't exist — they'd
    only find out at the account picker.
    """
    from .app_accounts import AppAccountNotFoundError
    from .repository import get_app_account_repository

    repo = get_app_account_repository()
    extras: list[str] = []
    for candidate in [account_id, *account_ids]:
        if not candidate:
            continue
        if await repo.get(candidate) is None:
            raise AppAccountNotFoundError(f"App account {candidate!r} not found")
        if candidate != account_id and candidate not in extras:
            extras.append(candidate)

    updated = await get_repository().update_accounts(user_id, account_id, extras)
    if updated is None:
        raise UserNotFoundError(f"User {user_id!r} not found")

    logger.info("Auth: user %s accounts set to %s", user_id, effective_account_ids(updated))
    return UserPublic.from_record(updated)


async def join_organization(user_id: str, org_id: str) -> TokenResponse:
    """Self-service: let the caller attach their own account to a real
    organization — for a signup that landed on the shared Guest org (the
    register() default) or, for an older record, was never assigned at all.
    Only usable while the account is still on Guest or unassigned (org_id is
    GUEST_ORG_ID or None); once on a real organization, changing it is
    staff-only (see assign_user_organization) so a user can't unilaterally
    hop between organizations' scoped data.

    Returns a fresh TokenResponse (not just UserPublic) since org_id is baked
    into the access token's claims — the caller needs a new token to reach
    org-scoped endpoints without logging in again.
    """
    user = await get_repository().get_by_id(user_id)
    if user is None:
        raise UserNotFoundError(f"User {user_id!r} not found")

    if user.org_id is not None and user.org_id != GUEST_ORG_ID:
        raise AlreadyAssignedError(
            f"User {user_id!r} already belongs to organization {user.org_id!r}; "
            "contact an administrator to change it"
        )

    if await get_org_repository().get(org_id) is None:
        raise OrganizationNotFoundError(f"Organization {org_id!r} not found")

    updated = await get_repository().update_org(user_id, org_id)
    if updated is None:
        raise UserNotFoundError(f"User {user_id!r} not found")

    logger.info("Auth: user %s self-joined organization %s", user_id, org_id)
    return _token_for(updated)


async def find_or_create_organization_for_deal(name: str, email: str | None = None) -> OrganizationRecord:
    """Best-effort auto-provisioning: find an org by name (case-insensitive)
    or create one, then register ``email`` as a known communication email.

    Ported for future callers (e.g. a deal-signing service) to invoke over a
    network call — nothing in this service calls it yet. In the source
    monolith it's called in-process when a deal is signed, so a staff admin
    can later match a signup from that email to the right organization.
    ``created_by`` is a "system:*" marker rather than a real user_id since
    this isn't a staff-initiated action.
    """
    org_repo = get_org_repository()
    org = await org_repo.get_by_name(name)
    if org is None:
        org = OrganizationRecord(
            org_id=_new_org_id(),
            name=name.strip(),
            created_by="system:deal-signed",
            created_at=datetime.now(timezone.utc),
        )
        await org_repo.create(org)
        logger.info("Auth: organization %s (%r) auto-created from a signed deal", org.org_id, org.name)

    if email:
        updated = await org_repo.add_known_email(org.org_id, email)
        if updated is not None:
            org = updated

    return org
