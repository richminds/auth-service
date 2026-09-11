"""Auth business logic — register, authenticate, issue tokens, manage accounts.

A user's only scope is the APP ACCOUNT they belong to. There is no separate
organization or tenant: downstream services filter their data on
``account_id``, which travels in the token.

**A user record is one person in one account.** The same email in two
applications is two records (features/schemas.py::UserRecord), so "which
accounts does this person have" is not a stored field — it is a query on the
email, and every function here that needs it goes through
``accounts_for_email``. Keeping that one derivation is what stops the answer
from differing between login, /auth/me, the account switcher and the admin
console's user list.

The cost of the split is that an email no longer names a single record, so
every entry point has to say WHICH record it means. Login resolves it from
the named account, or by trying the email's records when none is named;
account switching resolves the sibling record for the target account; and the
token's ``sub`` is always the specific record the caller authenticated as.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from uuid import uuid4

from .blacklist import is_token_revoked, revoke_token
from .repository import DuplicateUserError, get_repository
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
    decode_token_ignoring_expiry,
    hash_password,
    needs_rehash,
    verify_password,
)

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# A real bcrypt hash of a value nothing can supply, used to spend the same time
# on an unknown email as on a wrong password. Computed once at import: hashing
# per failed login would itself be a timing signal, and a cheap placeholder
# would not match the cost of the verify it stands in for.
_DUMMY_HASH = hash_password("not-a-password-" + uuid4().hex)


class EmailTakenError(Exception):
    """Raised when registering an email that already exists IN THAT ACCOUNT (409).

    Scoped to the account, not global: the same email registering into a
    different application is the supported case now, not a conflict. Also
    raised when the unique index rejects a pair that two concurrent
    registrations both believed was free.
    """


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
    # Defaults to the record's OWN account: a record belongs to exactly one
    # application, so the document the caller authenticated as is the scope.
    # Callers that resolved a sibling record pass the account explicitly.
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
    # The scoped account is a property of this token, not of the user record,
    # so it is passed to from_record rather than written onto a copy of the
    # record — which is what the old flat account_id field forced.
    return TokenResponse(
        access_token=token,
        user=UserPublic.from_record(
            user, accounts=accounts, scoped_account_id=scoped_account_id
        ),
    )


async def accounts_for_email(email: str) -> list[UserRecord]:
    """Every user record sharing ``email``, oldest first.

    The single derivation of "which applications is this person in". Membership
    used to be an array on one document; it is now the set of documents that
    exist, so this query IS the membership and there is no stored copy that can
    disagree with it.

    Oldest first because the ordering has to come from somewhere and creation
    order is the only thing left once the array is gone: the first record made
    for an email is that person's default account, which is what a login naming
    no account resolves to.
    """
    return await get_repository().list_by_email(email.strip().lower())


async def _login_accounts(records: list[UserRecord]) -> list[LoginAccount]:
    """Resolve display names for the accounts offered at login.

    Takes the records rather than a list of IDs because the records are now
    where membership lives — passing IDs would mean a caller had already
    flattened them and could pass a set that no document backs.

    A record whose account has no app-account entry (registered before the
    collection existed) still appears, named after itself: dropping it would
    lock the user out of the only account they have. A record whose account is
    DISABLED is dropped — that is what disabling is for.

    A record with no account at all contributes no entry; the user can sign in,
    they just have nothing to select.
    """
    from .repository import get_app_account_repository

    repo = get_app_account_repository()
    out: list[LoginAccount] = []
    seen: set[str] = set()
    for record in records:
        account_id = record.account_id
        if not account_id or account_id in seen:
            continue
        account = await repo.get(account_id)
        if account is not None and not account.enabled:
            continue
        seen.add(account_id)
        out.append(
            LoginAccount(account_id=account_id, name=account.name if account else account_id)
        )
    return out


async def register(req: RegisterRequest) -> TokenResponse:
    """Register a user INTO ONE APPLICATION.

    ``req.account_id`` is the only scope a user has, and it is now the scope of
    the DOCUMENT: registering an email that already exists in a different
    application creates a second, independent record rather than failing. That
    is the point of the split — the same person can hold an account in two
    applications that do not otherwise trust each other, with separate
    credentials.

    What is still refused is the same email twice in the SAME application.
    """
    email = req.email.strip().lower()
    if not _EMAIL_RE.match(email):
        raise InvalidEmailError(f"{req.email!r} is not a valid email address")

    repo = get_repository()
    # Scoped to the account, not the email. The unique (email, account_id)
    # index is the real authority — this check only turns the common case into
    # a clean 409 without a round trip through a driver exception.
    if await repo.get_by_email_account(email, req.account_id) is not None:
        where = f"in application {req.account_id!r}" if req.account_id else "with no application"
        raise EmailTakenError(f"{email!r} already has an account {where}")

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
        #
        # "Is there an admin already" is now simply "does a record exist in the
        # admin account" — one property of one document, where it used to mean
        # scanning every user's membership array.
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
        # Singular: this document is this person in this one application.
        account_id=req.account_id or None,
        created_at=datetime.now(timezone.utc),
    )
    try:
        await repo.create(user)
    except DuplicateUserError as exc:
        # Lost a race with a concurrent registration of the same pair. The
        # index caught it; report the same 409 the pre-check would have.
        raise EmailTakenError(str(exc)) from exc

    logger.info(
        "Auth: registered user %s (%s) account=%s", user.user_id, email, req.account_id
    )
    # The person's OTHER accounts are included: registering a second account
    # for an existing email should show them both, the same as a login would.
    return _token_for(user, accounts=await _login_accounts(await accounts_for_email(email)))


async def login(req: LoginRequest) -> TokenResponse:
    """Authenticate, and resolve WHICH of the caller's records they are.

    An email can now back several records, so a login has to pick one before
    it can check a password at all:

    * ``account_id`` named — the record for that account, and only that one. A
      user with no record there is refused exactly as a bad password is, so an
      unauthenticated caller cannot probe which applications an email is in.
    * no ``account_id`` — try the email's records oldest first and sign in as
      the first whose password verifies. Records hold independent hashes and
      may legitimately have different passwords, so checking only the oldest
      would reject a correct password for a newer account. The cost is one
      bcrypt per record, bounded by how many applications one person is in.

    This replaced a membership check against an array. That check had no
    exemption for users with no accounts, and the split needs none: naming an
    account resolves to a record IN that account or to nothing at all, so
    there is no path that issues an admin-scoped token to someone with no
    record in the admin account.
    """
    email = req.email.strip().lower()
    repo = get_repository()

    if req.account_id:
        found = await repo.get_by_email_account(email, req.account_id)
        candidates = [found] if found is not None else []
    else:
        candidates = await accounts_for_email(email)

    user: UserRecord | None = None
    for candidate in candidates:
        if verify_password(req.password, candidate.password_hash):
            user = candidate
            break

    if user is None:
        # Burn one verify when there was nothing to check, so a missing email
        # costs roughly what a wrong password does. Only when there were no
        # candidates — otherwise the loop above already paid that cost.
        if not candidates:
            verify_password(req.password, _DUMMY_HASH)
        if req.account_id:
            logger.warning("Auth: failed login for %s via account %s", email, req.account_id)
        # Same error either way: which applications an email belongs to isn't
        # something an unauthenticated caller should be able to probe.
        raise InvalidCredentialsError("Invalid email or password")

    # Upgrade a stale hash now that we hold the plaintext — a legacy pbkdf2
    # record, or a bcrypt one imported at a lower cost than we write today.
    # Doing it on login is what lets another application's users be imported
    # with their existing hashes and migrate to our scheme without a reset.
    # Only the record actually signed in to is rewritten: siblings carry their
    # own hashes and are none of this login's business.
    # Best effort: a failed rewrite must never fail the sign-in.
    if needs_rehash(user.password_hash):
        try:
            await repo.update_password_hash(user.user_id, hash_password(req.password))
            logger.info("Auth: upgraded stored password hash for %s", user.user_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Auth: could not upgrade password hash for %s: %s", user.user_id, exc)

    logger.info("Auth: login OK for %s (account=%s)", user.user_id, user.account_id)
    # Built from the person's records so the client can offer every application
    # they hold and exchange the choice via select_account without asking for
    # the password again. The token is scoped to the record that actually
    # authenticated — by construction one whose password this caller proved.
    accounts = await _login_accounts(await accounts_for_email(email))
    return _token_for(user, accounts=accounts)


async def select_account(user_id: str, account_id: str) -> TokenResponse:
    """Re-issue the caller's token as their record in another of their accounts.

    The post-login half of multi-account sign-in. What changes is bigger than
    it used to be: switching accounts now means switching to a DIFFERENT user
    record, so the new token's ``sub`` is that record's ``user_id``, not the
    one that called this. That follows from records being per-account — the
    caller is not "the same user viewing another account", they are a
    different principal in a different application who happens to share an
    email.

    The switch is authorised by the email alone, deliberately: the caller
    already proved they hold this email's credentials at login, and the target
    record is one of that email's own records. No password is asked for again,
    exactly as before.
    """
    repo = get_repository()
    current = await repo.get_by_id(user_id)
    if current is None:
        raise UserNotFoundError(f"User {user_id!r} not found")

    target = await repo.get_by_email_account(current.email, account_id)
    if target is None:
        # The person holds no record in that application. Reported to an
        # authenticated caller as a plain 403 — unlike at login, they have
        # already proved who they are, so there is nothing left to leak.
        raise AccountNotAllowedError(f"You do not belong to application {account_id!r}")

    from .app_accounts import assert_login_allowed

    await assert_login_allowed(account_id)

    logger.info(
        "Auth: %s switched to account %s as %s", user_id, account_id, target.user_id
    )
    accounts = await _login_accounts(await accounts_for_email(current.email))
    return _token_for(target, accounts=accounts)


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


async def refresh_token(token: str) -> TokenResponse:
    """Exchange a recently-expired access token for a fresh one.

    Access tokens are deliberately short-lived (``AUTH_ACCESS_TTL_MINUTES``,
    an hour) because that interval IS the revocation latency — a logged-out
    token keeps working for at most that long. Without this endpoint the only
    way to keep a session alive would be to lengthen that window for everyone,
    trading revocation speed for convenience. This separates the two: tokens
    stay short-lived, and an active client exchanges quietly.

    Five checks, and each one is load-bearing:

    1. Signature, issuer and audience must verify. Only expiry is waived
       (``decode_token_ignoring_expiry``) — the whole point is that the token
       has probably expired.
    2. The token must not be REVOKED. This is what makes logout final: without
       it a token discarded at sign-out could be exchanged for a live one, and
       logging out would mean nothing.
    3. The token must be within the refresh window (``AUTH_REFRESH_TTL_MINUTES``
       from ``iat``). Since expiry is waived, this is the only thing bounding
       how stale a token may be — otherwise one recovered from a log a year
       later would still work. A window of 0 disables refresh altogether.
    4. The user record must still exist. It is re-read rather than trusted from
       the claims, so a deleted user's token cannot be renewed, and the new
       token carries their CURRENT email, name and account rather than
       whatever was true when they signed in.
    5. The old token is REVOKED before the new one is issued — rotation. Each
       token is therefore exchangeable exactly once. A stolen token buys one
       refresh at most, and if the attacker spends it the legitimate user's
       next exchange fails and forces a visible re-login, rather than the two
       of them sharing a session indefinitely.

    Every failure raises InvalidCredentialsError → 401, deliberately without
    saying which check failed: the caller's only useful response is to sign in
    again, and distinguishing "expired too long ago" from "revoked" would tell
    an attacker holding a token something about its history.
    """
    # Imported inside the function, as _role_for and register do — this module
    # is imported by config-adjacent code and keeps the dependency one-way.
    from .config import auth_settings

    if not token:
        raise InvalidCredentialsError("No token supplied")

    if auth_settings.refresh_ttl_minutes <= 0:
        raise InvalidCredentialsError("Token refresh is disabled")

    try:
        claims = decode_token_ignoring_expiry(token)
    except Exception as exc:  # noqa: BLE001 — any decode failure is a 401
        raise InvalidCredentialsError("Invalid token") from exc

    jti = claims.get("jti")
    if await is_token_revoked(jti):
        raise InvalidCredentialsError("Token is no longer valid")

    issued_at = claims.get("iat")
    if not issued_at:
        # Every token this service mints carries iat; one without it predates
        # the claim or was not minted here, and either way there is nothing to
        # measure the refresh window against.
        raise InvalidCredentialsError("Token cannot be refreshed")

    age_seconds = datetime.now(timezone.utc).timestamp() - float(issued_at)
    if age_seconds > auth_settings.refresh_ttl_minutes * 60:
        raise InvalidCredentialsError("Token is too old to refresh")

    user = await get_repository().get_by_id(str(claims.get("sub")))
    if user is None:
        raise InvalidCredentialsError("Token cannot be refreshed")

    # Rotation, BEFORE the new token exists so a failure here cannot leave two
    # usable tokens. The TTL is the remaining refresh window rather than the
    # token's own exp, which is in the past — see features/blacklist.py.
    if jti:
        remaining = int(auth_settings.refresh_ttl_minutes * 60 - age_seconds)
        await revoke_token(jti, claims.get("exp", 0), ttl_seconds=remaining)

    logger.info("Auth: refreshed token for %s", user.user_id)
    # Scoped to the account the OLD token named, so a refresh never silently
    # moves the session to a different application — the user picked that with
    # POST /auth/me/account and refreshing is not a place to change it.
    accounts = await _login_accounts(await accounts_for_email(user.email))
    return _token_for(user, account_id=claims.get("account_id"), accounts=accounts)


async def get_user(user_id: str, scoped_account_id: str | None = None) -> UserPublic | None:
    """The user behind a valid token, for GET /auth/me.

    ``accounts`` is resolved from the caller's sibling records rather than left
    empty: it is the only account information in the response, and a client
    restoring a session from a stored token would otherwise see a user with no
    accounts at all.

    ``scoped_account_id`` is the caller's token claim. It should equal the
    record's own ``account_id`` now that a record is per-account, but it is
    still honoured rather than ignored: a token minted before the split, or one
    naming an account the record has since been moved out of, must not silently
    report a different scope than the token actually carries.
    """
    user = await get_repository().get_by_id(user_id)
    if user is None:
        return None
    return UserPublic.from_record(
        user,
        accounts=await _login_accounts(await accounts_for_email(user.email)),
        scoped_account_id=scoped_account_id,
    )


# ---------------------------------------------------------------------------
# User administration — callers are gated to administrators at the router
# (features.dependencies.require_admin), not re-checked here.
# ---------------------------------------------------------------------------

async def list_users() -> list[UserPublic]:
    """Every user record, for the administration console.

    One row per RECORD, not per person: an email in two applications appears
    twice, with a different ``user_id`` each time. That is the honest view now
    — the two rows are separately deletable, separately credentialed, and an
    administrator acting on one must be able to say which.

    Each row's ``accounts`` still lists every application that person holds, so
    the relationship between the rows is visible; ``selected`` marks the row's
    own account.
    """
    users = await get_repository().list_all()
    # One membership query per distinct email rather than per record: a console
    # listing every user would otherwise re-run the same query for each of a
    # person's records.
    by_email: dict[str, list[LoginAccount]] = {}
    out: list[UserPublic] = []
    for u in users:
        key = u.email.lower()
        if key not in by_email:
            by_email[key] = await _login_accounts(await accounts_for_email(u.email))
        out.append(
            UserPublic.from_record(u, accounts=by_email[key], scoped_account_id=u.account_id)
        )
    return out


async def assign_user_accounts(user_id: str, account_ids: list[str]) -> UserPublic:
    """Reconcile which applications a person can sign in to (staff only).

    The request is still an ordered list, but it is now a desired END STATE
    that this function makes true by moving, creating and deleting DOCUMENTS:

    * a record that already sits in a wanted account is left completely alone —
      its password is independent and a membership edit must not reset it;
    * a record belonging to NO application is REUSED for the first wanted
      account it can take, rather than being left behind while a new record is
      made beside it. That matters: registration without an account is the
      normal way a user is created before staff place them, and creating a
      second document would strand the ``user_id`` the administrator just
      addressed — and leave an accountless record that a login with no
      ``account_id`` would resolve to first, silently signing the person in
      with no scope at all;
    * a wanted account with nothing to reuse gets a NEW record, cloning name
      and password hash so the person can sign in immediately rather than being
      locked out of an application they were just granted;
    * a record whose account is not in the list is DELETED, together with its
      credentials and anything keyed on its ``user_id``.

    An EMPTY list does not delete the person: their oldest record is kept and
    moved to no application, and the rest are removed. That preserves what an
    empty membership meant before the split — they can still sign in, they
    just cannot claim an account — instead of silently turning a membership
    edit into account deletion.

    Order sets the default, since a login naming no account resolves the
    email's records oldest first.

    ``user_id`` names ONE of the person's records; reconciliation applies to
    every record sharing its email, because that is what ties them together.
    Every ID is validated against the app-account collection first, so a typo
    cannot leave a person pointed at an application that does not exist.

    Returns the record named by ``user_id`` when it survived, otherwise the
    oldest surviving one — an administrator who removes the very account they
    addressed should still get the resulting user back, not a 404.
    """
    from .app_accounts import AppAccountNotFoundError
    from .repository import get_app_account_repository

    repo = get_repository()
    anchor = await repo.get_by_id(user_id)
    if anchor is None:
        raise UserNotFoundError(f"User {user_id!r} not found")

    accounts_repo = get_app_account_repository()
    cleaned: list[str] = []
    for candidate in account_ids:
        if not candidate or candidate in cleaned:
            continue
        if await accounts_repo.get(candidate) is None:
            raise AppAccountNotFoundError(f"App account {candidate!r} not found")
        cleaned.append(candidate)

    existing = await accounts_for_email(anchor.email)
    held = {r.account_id: r for r in existing if r.account_id}
    # Oldest first, and the addressed record ahead of its peers: if only one
    # accountless record can be reused, it should be the one the administrator
    # actually named.
    spare = sorted(
        (r for r in existing if not r.account_id),
        key=lambda r: (r.user_id != anchor.user_id, r.created_at),
    )

    if not cleaned:
        # Keep one record so the person still exists, belonging to nothing.
        keeper = spare[0] if spare else existing[0]
        if keeper.account_id is not None:
            await repo.update_account(keeper.user_id, None)
        for record in existing:
            if record.user_id != keeper.user_id:
                await repo.delete_by_id(record.user_id)
        logger.info("Auth: %s removed from every application", anchor.email)
        surviving = await accounts_for_email(anchor.email)
        result = surviving[0] if surviving else anchor
        return UserPublic.from_record(result, accounts=[], scoped_account_id=None)

    moved: list[str] = []
    created: list[str] = []
    # Reuse and create BEFORE deleting. If a write fails the person keeps what
    # they had; the other order could delete their last record and then fail to
    # make its replacement, leaving them with no way in at all.
    for account_id in cleaned:
        if account_id in held:
            continue
        if spare:
            reused = spare.pop(0)
            try:
                await repo.update_account(reused.user_id, account_id)
            except DuplicateUserError:
                spare.insert(0, reused)
                continue
            held[account_id] = reused.model_copy(update={"account_id": account_id})
            moved.append(account_id)
            continue
        clone = UserRecord(
            user_id=_new_user_id(),
            email=anchor.email,
            name=anchor.name,
            # Cloned, not blank and not regenerated: the person must be able to
            # sign in to the account they were just given. The two hashes are
            # independent from this moment on — changing one never touches the
            # other.
            password_hash=anchor.password_hash,
            account_id=account_id,
            created_at=datetime.now(timezone.utc),
        )
        try:
            await repo.create(clone)
        except DuplicateUserError:
            # Raced with another grant of the same pair; the winner is fine.
            continue
        created.append(account_id)

    wanted = set(cleaned)
    removed: list[str] = []
    for account_id, record in list(held.items()):
        if account_id not in wanted and await repo.delete_by_id(record.user_id):
            removed.append(account_id)
    # Any accountless record not reused above is surplus: it would otherwise be
    # what a login naming no account resolves to first.
    for leftover in spare:
        await repo.delete_by_id(leftover.user_id)

    logger.info(
        "Auth: %s reconciled to %s (moved=%s created=%s removed=%s)",
        anchor.email,
        cleaned,
        moved,
        created,
        removed,
    )

    surviving = await accounts_for_email(anchor.email)
    result = next((r for r in surviving if r.user_id == anchor.user_id), None)
    if result is None:
        result = surviving[0] if surviving else anchor
    return UserPublic.from_record(
        result,
        accounts=await _login_accounts(surviving),
        scoped_account_id=result.account_id,
    )
