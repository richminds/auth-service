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


async def ensure_admin_account() -> AppAccountRecord:
    """Idempotently ensure the admin app account exists.

    Membership of this account is the only thing that grants administrative
    access (features/dependencies.py::require_admin), so it has to exist before
    anyone can be tied to it — otherwise there is no way to create the first
    admin. Bootstrapped at startup, same shape as the user bootstrap.
    """
    from .config import auth_settings

    repo = get_app_account_repository()
    existing = await repo.get(auth_settings.admin_account_id)
    if existing is not None:
        return existing

    account = AppAccountRecord(
        account_id=auth_settings.admin_account_id,
        # Derived from this slug (features/account_ids.py), so a freshly
        # bootstrapped database and one put through the backfill agree on the
        # admin account's ID instead of diverging.
        legacy_account_id="richminds",
        name="RichMinds",
        description="Administrators of this auth service.",
        created_by="system:bootstrap",
        created_at=datetime.now(UTC),
    )
    try:
        await repo.create(account)
    except Exception:  # noqa: BLE001 — lost a create race; the winner is fine
        winner = await repo.get(auth_settings.admin_account_id)
        if winner is not None:
            return winner
        raise
    logger.info("Auth: bootstrapped the admin app account (account_id=%s)", account.account_id)
    return account


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
