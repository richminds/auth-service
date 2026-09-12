"""App accounts — the applications registered against this service.

An **app account is an application**, not a tenant. The RichMinds admin
console, and anything onboarded later, each register once here; the
`account_id` recorded is the value that application sends as
``LoginRequest.account_id`` when its users sign in
(app/controllers/auth_controller.py::login).

That ID is a **UUID generated here** (features/account_ids.py), not a slug the
caller picks. Registering an application therefore returns the ID to put in
its config, rather than confirming one the caller already chose.

Stored in its own collection (``app_accounts``). An app account is the ONLY
scope a user has: it names the application they authenticate against, and it
is the value downstream services filter their data on.

Registering an application is what lets its users name it at login: the
account must exist and be enabled, and the user must belong to it (see
assert_login_allowed here and features/service.py::login). This service is
the source of truth for identity — it authenticates against its own user
store and never reaches into an application's private database.

**The admin account is the one whose ``app_type`` is ``ADMIN``.** That is the
whole definition of administrator in this service (is_admin_account below):
a user is an admin when the account their record belongs to carries that
type. Nothing is configured — no ID to compare against, nothing to keep in
step between environments — and so ``admin`` is the one type the API refuses
to assign (features/schemas.py): an existing administrator must not be able
to mint further admin accounts, or promote an application's entire user base,
by picking a value from a dropdown.

NO account is created at startup. ``ensure_admin_account`` still exists, but
it is an operator's command — run once, against a fresh deployment — never
something the service does coming up. Everything else, the guest account
included, is registered through create_app_account.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from .account_ids import new_account_uuid
from .repository import get_app_account_repository
from .schemas import AppAccountRecord, AppType

logger = logging.getLogger(__name__)


class AppAccountExistsError(Exception):
    """Raised when registering an account_id that is already taken (409)."""


class AppAccountNotFoundError(Exception):
    """Raised when reading/updating/deleting an unknown account_id (404)."""


class AdminAccountClosedError(Exception):
    """Raised when self-registering into the admin app account after the first
    admin already exists (403) — see service.register."""


class AppAccountDisabledError(Exception):
    """Raised when logging in for an app account that has been disabled (403)."""


class AdminAccountTypeFixedError(Exception):
    """Raised on an attempt to change an admin-type account's ``app_type``
    (403). The type is what confers administrator on its members, so changing
    it would demote every administrator at once — the caller included — with
    nobody left able to undo it."""


async def is_admin_account(account_id: str | None) -> bool:
    """Whether ``account_id`` names an admin-type app account.

    THE definition of administrator in this service: a user is an admin when
    the account their record belongs to has ``app_type == AppType.ADMIN``. It
    is a property of the account record, not a configured ID — the service
    never has to be told which account is the admin one. Every other
    derivation (the token's ``role`` claim, ``UserPublic.is_admin``,
    ``require_admin``) traces back here.

    An unknown or missing account is simply not an admin account.
    """
    if not account_id:
        return False
    account = await get_app_account_repository().get(account_id)
    return account is not None and account.app_type == AppType.ADMIN


async def admin_account_ids() -> set[str]:
    """Every admin-type account's ID, for callers classifying many records at
    once (the console's user list) without a lookup per row."""
    return {
        a.account_id
        for a in await get_app_account_repository().list_all()
        if a.app_type == AppType.ADMIN
    }


async def assert_login_allowed(account_id: str) -> None:
    """Refuse a login for a registered-but-disabled application.

    Checked before credentials, which is what makes `enabled` mean something
    rather than being a label.

    An account_id with no record is deliberately allowed through: applications
    predate this collection, and failing them closed would take working logins
    offline. Once every application is registered, this can become a hard
    existence check — see the README.
    """
    account = await get_app_account_repository().get(account_id)
    if account is None:
        logger.warning(
            "Auth: login for unregistered app account %r — allowed for now, register it",
            account_id,
        )
        return
    if not account.enabled:
        raise AppAccountDisabledError(f"Application {account_id!r} is disabled")


ADMIN_ACCOUNT_NAME = "RichMinds"
"""Display name of the bootstrapped admin account — the platform's own admin
console. A label, not an identifier: nothing looks an account up by name."""


async def ensure_admin_account() -> AppAccountRecord:
    """Idempotently create the admin app account. **Operator-invoked only.**

    Holding a record in an admin-type account is the only thing that grants
    administrative access (is_admin_account), so one has to exist before
    anyone can be tied to it — and it cannot be created through
    POST /auth/accounts: that route requires the administrator this account
    is a prerequisite for, and it refuses ``app_type=admin`` outright
    (features/schemas.py) so an existing administrator cannot mint more admin
    accounts by accident.

    This function is how that cycle is broken, and the service never calls it
    at startup: an operator does, once, on a fresh deployment (the README
    shows how). That is the difference between an account existing because
    someone asked for it and one existing because a process restarted.

    Its ID is MINTED, like every other account's. Nothing here needs to know
    it in advance — the gate is the account's type, not its ID — so the value
    is read off the returned record and put in the admin console's
    configuration (VITE_ADMIN_ACCOUNT_ID), exactly as any other application
    learns its own ID. Idempotent on "an admin-type account already exists":
    a repeat run returns that account rather than minting a second one. Two
    runs racing each other could each mint one, so run it once, from one
    place — it is an operator's step, not a startup hook.
    """
    repo = get_app_account_repository()
    existing = [a for a in await repo.list_all() if a.app_type == AppType.ADMIN]
    if existing:
        return min(existing, key=lambda a: a.created_at)

    account = AppAccountRecord(
        account_id=new_account_uuid(),
        name=ADMIN_ACCOUNT_NAME,
        description="Maintains all the app accounts.",
        app_type=AppType.ADMIN,
        created_by="system:bootstrap",
        created_at=datetime.now(UTC),
    )
    await repo.create(account)
    logger.info(
        "Auth: bootstrapped the admin app account (account_id=%s) — this is the value "
        "for the admin console's VITE_ADMIN_ACCOUNT_ID",
        account.account_id,
    )
    return account


# There is no ensure_guest_account. The knowledge-ingest console's public
# "Create User" button names an account somebody registered through
# POST /auth/accounts, configured into that console as VITE_GUEST_ACCOUNT_ID —
# minted, like every account's ID, so it differs per environment. With no such
# account registered the button's sign-ups 404 (service.register validates
# the ID), which is the visible, correct outcome rather than something to
# paper over with a bootstrap.


async def create_app_account(
    name: str,
    description: str,
    created_by: str,
    app_type: AppType = AppType.OTHER,
    app_url: str = "",
) -> AppAccountRecord:
    """Register an application and mint its ID.

    The ID is generated rather than accepted from the caller: it is an
    authorization key (applications name it at login, downstream services
    scope data on it), and a caller-chosen one would be guessable. The
    returned ``account_id`` is what goes into the application's config.

    A UUID collision is not a real possibility, but the repository's unique
    index is still the authority — the retry loop keeps a freak duplicate from
    surfacing as a 500.
    """
    repo = get_app_account_repository()
    account_id = new_account_uuid()
    while await repo.get(account_id) is not None:  # pragma: no cover — 1 in 2^122
        account_id = new_account_uuid()

    account = AppAccountRecord(
        account_id=account_id,
        name=name.strip(),
        description=description.strip(),
        app_type=app_type,
        app_url=app_url.strip(),
        created_by=created_by,
        created_at=datetime.now(UTC),
    )
    await repo.create(account)
    logger.info("Auth: app account %s (%r) registered by %s", account_id, account.name, created_by)
    return account


async def list_app_accounts() -> list[AppAccountRecord]:
    return [a for a in await get_app_account_repository().list_all()]


async def get_app_account(account_id: str) -> AppAccountRecord:
    account = await get_app_account_repository().get(account_id)
    if account is None:
        raise AppAccountNotFoundError(f"App account {account_id!r} not found")
    return account


async def update_app_account(
    account_id: str,
    *,
    name: str | None = None,
    description: str | None = None,
    app_type: AppType | None = None,
    app_url: str | None = None,
    enabled: bool | None = None,
) -> AppAccountRecord:
    """Partial update. account_id is immutable — applications send it, so
    changing it would break their logins; re-register instead."""
    changes: dict = {}
    if name is not None:
        changes["name"] = name.strip()
    if description is not None:
        changes["description"] = description.strip()
    if app_type is not None:
        # The admin account's type is what makes its members administrators,
        # so changing it would demote every one of them at once — the caller
        # included — with no administrator left to undo it. Refused here and
        # not only at the schema, so a caller that is not the HTTP layer gets
        # the same answer.
        current = await get_app_account(account_id)
        if current.app_type == AppType.ADMIN and app_type != AppType.ADMIN:
            raise AdminAccountTypeFixedError(
                f"App account {account_id!r} is the administrator account; its type is fixed"
            )
        # Kept as the enum so the in-memory repo's model_copy() (which doesn't
        # validate) stores a correctly-typed value; the Mongo repo encodes it
        # on the way out, the same as it does datetimes.
        changes["app_type"] = app_type
    if app_url is not None:
        changes["app_url"] = app_url.strip()
    if enabled is not None:
        changes["enabled"] = enabled

    if not changes:
        return await get_app_account(account_id)

    changes["updated_at"] = datetime.now(UTC)
    updated = await get_app_account_repository().update(account_id, changes)
    if updated is None:
        raise AppAccountNotFoundError(f"App account {account_id!r} not found")

    logger.info("Auth: app account %s updated (%s)", account_id, ", ".join(sorted(changes)))
    return updated


async def delete_app_account(account_id: str) -> None:
    if not await get_app_account_repository().delete(account_id):
        raise AppAccountNotFoundError(f"App account {account_id!r} not found")
    logger.info("Auth: app account %s deleted", account_id)
