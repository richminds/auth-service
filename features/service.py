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
    LoginRequest,
    OrganizationRecord,
    RegisterRequest,
    TokenResponse,
    UserPublic,
    UserRecord,
)
from .security import create_access_token, decode_token, hash_password, verify_password

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


def _new_user_id() -> str:
    return f"USR-{uuid4().hex[:12].upper()}"


def _new_org_id() -> str:
    return f"ORG-{uuid4().hex[:12].upper()}"


def _token_for(user: UserRecord) -> TokenResponse:
    token = create_access_token(
        subject=user.user_id,
        extra_claims={
            "email": user.email,
            "name": user.name,
            "org_id": user.org_id,
            "is_portless": is_portless_user(user.email),
        },
    )
    return TokenResponse(access_token=token, user=UserPublic.from_record(user))


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

    if is_portless_user(email):
        org_id = PORTLESS_ORG_ID
    elif req.org_id:
        if await get_org_repository().get(req.org_id) is None:
            raise OrganizationNotFoundError(f"Organization {req.org_id!r} not found")
        org_id = req.org_id
    else:
        await ensure_guest_organization()
        org_id = GUEST_ORG_ID

    user = UserRecord(
        user_id=_new_user_id(),
        email=email,
        name=req.name.strip(),
        password_hash=hash_password(req.password),
        org_id=org_id,
        created_at=datetime.now(timezone.utc),
    )
    await repo.create(user)
    logger.info("Auth: registered user %s (%s) org=%s", user.user_id, email, org_id)
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
    logger.info("Auth: login OK for %s", user.user_id)
    return _token_for(user)


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
