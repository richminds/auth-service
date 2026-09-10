"""Auth business logic — register, authenticate, issue tokens, manage accounts.

A user's only scope is the APP ACCOUNT they belong to. There is no separate
organization or tenant: downstream services filter their data on
``account_id``, which travels in the token.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from uuid import uuid4

from .blacklist import revoke_token
from .repository import get_repository
from .schemas import (
    LoginAccount,
    LoginRequest,
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


class UserNotFoundError(Exception):
    """Raised when an operation names a user_id that doesn't exist (404)."""


class AccountNotAllowedError(Exception):
    """Raised when a signed-in user asks for a token scoped to an app account
    they don't belong to (403). Distinct from the login-time check, which
    reports the same error as a bad password because the caller there is
    still unauthenticated."""


def _new_user_id() -> str:
    return f"USR-{uuid4().hex[:12].upper()}"


def _role_for(account_id: str | None) -> str:
    """"admin" for a session scoped to the admin app account, else "user".

    The single derivation of administrator-ness in this service, shared with
    ``UserPublic.from_record``. Membership of the configured admin app account
    is the whole rule — there is no separate staff allowlist.
    """
    # Imported here rather than at module scope, matching the other settings
    # reads in this module: the settings singleton is built at import time, and
    # a module-level import would pin it before the test suite's environment is
    # in place.
    from .config import auth_settings

    return (
        "admin"
        if account_id and account_id == auth_settings.admin_account_id
        else "user"
    )


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
            # The application this token is scoped to, and the only scope there
            # is: require_admin reads it, and downstream services filter their
            # data on it, so it travels in the token rather than being
            # re-fetched on every request.
            "account_id": scoped_account_id,
            # Derived from the SCOPED account, exactly as UserPublic.is_admin
            # is (features/schemas.py) — a user who administers one application
            # is not an administrator of a session scoped to another.
            #
            # This service does not read the claim; it is minted for the
            # services that do. llm-gateway and knowledge-service authorize
            # their admin routes on a token's "role", and with no such claim
            # every caller resolved to "user" and those routes were
            # unreachable for everyone. Named "role" rather than "is_admin"
            # because that is the key those services already look for.
            "role": _role_for(scoped_account_id),
        },
    )
    # The account membership lives on the user and nowhere else — the envelope
    # used to repeat account_id/accounts alongside it, which meant two copies
    # that could disagree and no way for a client to tell which was right.
    scoped = user.model_copy(update={"account_id": scoped_account_id})
    return TokenResponse(
        access_token=token,
        user=UserPublic.from_record(scoped, accounts=accounts),
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

    ``req.account_id`` is the only scope a user has. It is optional — a user
    created without one belongs to no application yet and can be assigned to
    one later by an administrator (see assign_user_accounts).
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

    user = UserRecord(
        user_id=_new_user_id(),
        email=email,
        name=req.name.strip(),
        password_hash=hash_password(req.password),
        account_id=req.account_id,
        created_at=datetime.now(timezone.utc),
    )
    await repo.create(user)
    logger.info(
        "Auth: registered user %s (%s) account=%s", user.user_id, email, req.account_id
    )
    return _token_for(user, accounts=await _login_accounts(effective_account_ids(user)))


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
    # This check has NO exemption for users with no accounts, and that matters:
    # it used to skip entirely when `allowed` was empty, so that any user
    # without a membership could name any account — including the ADMIN one —
    # and be issued a token scoped to it. Since is_admin is derived from
    # `account_id == AUTH_ADMIN_ACCOUNT_ID`, that turned "anyone who can sign
    # up" into "anyone who can become an administrator". A user with no
    # accounts can still sign in; they just cannot claim one.
    allowed = effective_account_ids(user)
    if req.account_id and req.account_id not in allowed:
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
    #
    # Both branches can only produce an account this user belongs to: the
    # named one was checked against `allowed` above, and `accounts` is derived
    # from `allowed`. The token's account scope is therefore never something
    # the client chose for itself.
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
# User administration — callers are gated to administrators at the router
# (features.dependencies.require_admin), not re-checked here.
# ---------------------------------------------------------------------------

async def list_users() -> list[UserPublic]:
    users = await get_repository().list_all()
    return [UserPublic.from_record(u) for u in users]


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
