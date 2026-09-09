"""Auth persistence — users, organizations, and revoked-token collections.

Three backends per entity behind a Protocol: InMemory* (process-local, used
when no Mongo URI resolves) and Mongo* (Motor, selected once a URI resolves).
All three share ONE Motor connection (features/mongo_connection.py) rather
than opening a separate pool per concern.

Persists into the configured AUTH_MONGO_URI / AUTH_MONGO_DB_NAME database —
by default the SAME shared database the calling application's monolith uses
(see features/config.py), in its own `users` / `organizations` collections,
plus a `revoked_tokens` collection (TTL-indexed) that the source
implementation instead kept in a generic app-wide cache.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol, runtime_checkable

from .config import auth_settings
from .schemas import AppAccountRecord, OrganizationRecord, UserRecord

logger = logging.getLogger(__name__)

_user_repository: "UserRepository | None" = None
_org_repository: "OrganizationRepository | None" = None
_revocation_repository: "RevocationRepository | None" = None
_app_account_repository: "AppAccountRepository | None" = None


@runtime_checkable
class UserRepository(Protocol):
    async def get_by_email(self, email: str) -> UserRecord | None: ...
    async def get_by_id(self, user_id: str) -> UserRecord | None: ...
    async def create(self, user: UserRecord) -> None: ...
    async def list_all(self) -> list[UserRecord]: ...
    async def update_org(self, user_id: str, org_id: str) -> UserRecord | None: ...
    async def update_accounts(
        self, user_id: str, account_id: str | None, account_ids: list[str]
    ) -> UserRecord | None: ...
    async def update_password_hash(self, user_id: str, password_hash: str) -> None: ...


@runtime_checkable
class OrganizationRepository(Protocol):
    async def create(self, org: OrganizationRecord) -> None: ...
    async def get(self, org_id: str) -> OrganizationRecord | None: ...
    async def get_by_name(self, name: str) -> OrganizationRecord | None: ...
    async def list_all(self) -> list[OrganizationRecord]: ...
    async def add_known_email(self, org_id: str, email: str) -> OrganizationRecord | None: ...
    async def rename(self, org_id: str, name: str) -> OrganizationRecord | None: ...
    async def delete(self, org_id: str) -> bool: ...


@runtime_checkable
class RevocationRepository(Protocol):
    async def revoke(self, jti: str, ttl_seconds: int) -> None: ...
    async def is_revoked(self, jti: str) -> bool: ...


@runtime_checkable
class AppAccountRepository(Protocol):
    """Registered applications — separate storage from organizations (tenants).
    See features/schemas.py::AppAccountRecord for why they aren't the same."""

    async def create(self, account: AppAccountRecord) -> None: ...
    async def get(self, account_id: str) -> AppAccountRecord | None: ...
    async def list_all(self) -> list[AppAccountRecord]: ...
    async def update(self, account_id: str, changes: dict) -> AppAccountRecord | None: ...
    async def delete(self, account_id: str) -> bool: ...


# ---------------------------------------------------------------------------
# In-memory
# ---------------------------------------------------------------------------

class InMemoryUserRepository:
    def __init__(self) -> None:
        self._by_id: dict[str, UserRecord] = {}

    async def get_by_email(self, email: str) -> UserRecord | None:
        key = email.strip().lower()
        for u in self._by_id.values():
            if u.email.lower() == key:
                return u
        return None

    async def get_by_id(self, user_id: str) -> UserRecord | None:
        return self._by_id.get(user_id)

    async def create(self, user: UserRecord) -> None:
        self._by_id[user.user_id] = user

    async def list_all(self) -> list[UserRecord]:
        return sorted(self._by_id.values(), key=lambda u: u.created_at)

    async def update_org(self, user_id: str, org_id: str) -> UserRecord | None:
        user = self._by_id.get(user_id)
        if user is None:
            return None
        updated = user.model_copy(update={"org_id": org_id})
        self._by_id[user_id] = updated
        return updated

    async def update_accounts(
        self, user_id: str, account_id: str | None, account_ids: list[str]
    ) -> UserRecord | None:
        user = self._by_id.get(user_id)
        if user is None:
            return None
        updated = user.model_copy(
            update={"account_id": account_id, "account_ids": list(account_ids)}
        )
        self._by_id[user_id] = updated
        return updated

    async def update_password_hash(self, user_id: str, password_hash: str) -> None:
        user = self._by_id.get(user_id)
        if user is not None:
            self._by_id[user_id] = user.model_copy(update={"password_hash": password_hash})


class InMemoryOrganizationRepository:
    def __init__(self) -> None:
        self._by_id: dict[str, OrganizationRecord] = {}

    async def create(self, org: OrganizationRecord) -> None:
        self._by_id[org.org_id] = org

    async def get(self, org_id: str) -> OrganizationRecord | None:
        return self._by_id.get(org_id)

    async def get_by_name(self, name: str) -> OrganizationRecord | None:
        key = name.strip().lower()
        for o in self._by_id.values():
            if o.name.strip().lower() == key:
                return o
        return None

    async def list_all(self) -> list[OrganizationRecord]:
        return sorted(self._by_id.values(), key=lambda o: o.created_at)

    async def add_known_email(self, org_id: str, email: str) -> OrganizationRecord | None:
        org = self._by_id.get(org_id)
        if org is None:
            return None
        email = email.strip().lower()
        if email in org.known_emails:
            return org
        updated = org.model_copy(update={"known_emails": [*org.known_emails, email]})
        self._by_id[org_id] = updated
        return updated

    async def rename(self, org_id: str, name: str) -> OrganizationRecord | None:
        org = self._by_id.get(org_id)
        if org is None:
            return None
        updated = org.model_copy(update={"name": name})
        self._by_id[org_id] = updated
        return updated

    async def delete(self, org_id: str) -> bool:
        return self._by_id.pop(org_id, None) is not None


class InMemoryAppAccountRepository:
    def __init__(self) -> None:
        self._by_id: dict[str, AppAccountRecord] = {}

    async def create(self, account: AppAccountRecord) -> None:
        if account.account_id in self._by_id:
            raise ValueError(f"App account {account.account_id!r} already exists")
        self._by_id[account.account_id] = account

    async def get(self, account_id: str) -> AppAccountRecord | None:
        return self._by_id.get(account_id)

    async def list_all(self) -> list[AppAccountRecord]:
        return sorted(self._by_id.values(), key=lambda a: a.created_at)

    async def update(self, account_id: str, changes: dict) -> AppAccountRecord | None:
        account = self._by_id.get(account_id)
        if account is None:
            return None
        updated = account.model_copy(update=changes)
        self._by_id[account_id] = updated
        return updated

    async def delete(self, account_id: str) -> bool:
        return self._by_id.pop(account_id, None) is not None


class InMemoryRevocationRepository:
    """Process-local dict with manual expiry. Lost on restart."""

    def __init__(self) -> None:
        self._store: dict[str, datetime] = {}

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        from datetime import timedelta

        self._store[jti] = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

    async def is_revoked(self, jti: str) -> bool:
        expires_at = self._store.get(jti)
        if expires_at is None:
            return False
        if expires_at <= datetime.now(timezone.utc):
            self._store.pop(jti, None)
            return False
        return True


# ---------------------------------------------------------------------------
# MongoDB (Motor)
# ---------------------------------------------------------------------------

class MongoUserRepository:
    def __init__(self, col) -> None:
        self._col = col

    async def get_by_email(self, email: str) -> UserRecord | None:
        d = await self._col.find_one({"email": email.strip().lower()})
        if d is None:
            return None
        d.pop("_id", None)
        return UserRecord(**d)

    async def get_by_id(self, user_id: str) -> UserRecord | None:
        d = await self._col.find_one({"user_id": user_id})
        if d is None:
            return None
        d.pop("_id", None)
        return UserRecord(**d)

    async def create(self, user: UserRecord) -> None:
        doc = user.model_dump(mode="json")
        doc["email"] = doc["email"].strip().lower()
        await self._col.insert_one(doc)

    async def list_all(self) -> list[UserRecord]:
        cursor = self._col.find({}).sort("created_at", 1)
        docs = await cursor.to_list(length=10_000)
        users = []
        for d in docs:
            d.pop("_id", None)
            try:
                users.append(UserRecord(**d))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping malformed user document: %s", exc)
        return users

    async def update_org(self, user_id: str, org_id: str) -> UserRecord | None:
        from pymongo import ReturnDocument

        d = await self._col.find_one_and_update(
            {"user_id": user_id},
            {"$set": {"org_id": org_id}},
            return_document=ReturnDocument.AFTER,
        )
        if d is None:
            return None
        d.pop("_id", None)
        return UserRecord(**d)

    async def update_accounts(
        self, user_id: str, account_id: str | None, account_ids: list[str]
    ) -> UserRecord | None:
        from pymongo import ReturnDocument

        d = await self._col.find_one_and_update(
            {"user_id": user_id},
            {"$set": {"account_id": account_id, "account_ids": list(account_ids)}},
            return_document=ReturnDocument.AFTER,
        )
        if d is None:
            return None
        d.pop("_id", None)
        return UserRecord(**d)

    async def update_password_hash(self, user_id: str, password_hash: str) -> None:
        await self._col.update_one(
            {"user_id": user_id}, {"$set": {"password_hash": password_hash}}
        )


class MongoOrganizationRepository:
    def __init__(self, col) -> None:
        self._col = col

    async def create(self, org: OrganizationRecord) -> None:
        await self._col.insert_one(org.model_dump(mode="json"))

    async def get(self, org_id: str) -> OrganizationRecord | None:
        d = await self._col.find_one({"org_id": org_id})
        if d is None:
            return None
        d.pop("_id", None)
        return OrganizationRecord(**d)

    async def get_by_name(self, name: str) -> OrganizationRecord | None:
        import re

        d = await self._col.find_one(
            {"name": {"$regex": f"^{re.escape(name.strip())}$", "$options": "i"}}
        )
        if d is None:
            return None
        d.pop("_id", None)
        return OrganizationRecord(**d)

    async def list_all(self) -> list[OrganizationRecord]:
        cursor = self._col.find({}).sort("created_at", 1)
        docs = await cursor.to_list(length=10_000)
        orgs = []
        for d in docs:
            d.pop("_id", None)
            try:
                orgs.append(OrganizationRecord(**d))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping malformed organization document: %s", exc)
        return orgs

    async def add_known_email(self, org_id: str, email: str) -> OrganizationRecord | None:
        from pymongo import ReturnDocument

        d = await self._col.find_one_and_update(
            {"org_id": org_id},
            {"$addToSet": {"known_emails": email.strip().lower()}},
            return_document=ReturnDocument.AFTER,
        )
        if d is None:
            return None
        d.pop("_id", None)
        return OrganizationRecord(**d)

    async def rename(self, org_id: str, name: str) -> OrganizationRecord | None:
        from pymongo import ReturnDocument

        d = await self._col.find_one_and_update(
            {"org_id": org_id},
            {"$set": {"name": name}},
            return_document=ReturnDocument.AFTER,
        )
        if d is None:
            return None
        d.pop("_id", None)
        return OrganizationRecord(**d)

    async def delete(self, org_id: str) -> bool:
        result = await self._col.delete_one({"org_id": org_id})
        return result.deleted_count > 0


class MongoAppAccountRepository:
    def __init__(self, col) -> None:
        self._col = col

    async def create(self, account: AppAccountRecord) -> None:
        # Relies on the unique index on account_id (init_repository) to reject
        # a duplicate that slipped past the service-layer existence check.
        await self._col.insert_one(account.model_dump(mode="json"))

    async def get(self, account_id: str) -> AppAccountRecord | None:
        d = await self._col.find_one({"account_id": account_id})
        if d is None:
            return None
        d.pop("_id", None)
        return AppAccountRecord(**d)

    async def list_all(self) -> list[AppAccountRecord]:
        cursor = self._col.find({}).sort("created_at", 1)
        docs = await cursor.to_list(length=10_000)
        accounts = []
        for d in docs:
            d.pop("_id", None)
            try:
                accounts.append(AppAccountRecord(**d))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping malformed app account document: %s", exc)
        return accounts

    async def update(self, account_id: str, changes: dict) -> AppAccountRecord | None:
        from pymongo import ReturnDocument

        # create() writes via model_dump(mode="json"), so datetimes are ISO
        # strings and enums are their plain values. Match that here rather than
        # mixing in BSON dates or enum objects.
        def _encode(v):
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, Enum):
                return v.value
            return v

        encoded = {k: _encode(v) for k, v in changes.items()}
        d = await self._col.find_one_and_update(
            {"account_id": account_id},
            {"$set": encoded},
            return_document=ReturnDocument.AFTER,
        )
        if d is None:
            return None
        d.pop("_id", None)
        return AppAccountRecord(**d)

    async def delete(self, account_id: str) -> bool:
        result = await self._col.delete_one({"account_id": account_id})
        return result.deleted_count > 0


class MongoRevocationRepository:
    """TTL-indexed collection — a revoked entry expires at the same moment the
    token itself would have stopped being valid anyway, so it never grows
    unbounded. Index is created once in init_repository()."""

    def __init__(self, col) -> None:
        self._col = col

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        from datetime import timedelta

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        await self._col.replace_one(
            {"_id": jti}, {"_id": jti, "expires_at": expires_at}, upsert=True
        )

    async def is_revoked(self, jti: str) -> bool:
        d = await self._col.find_one({"_id": jti})
        if d is None:
            return False
        expires_at = d.get("expires_at")
        if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if isinstance(expires_at, datetime) and expires_at <= datetime.now(timezone.utc):
            return False
        return True


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

async def init_repository() -> None:
    """Initialise the process-wide repositories. Idempotent-ish: safe to call
    once at startup; falls back to in-memory storage on any Mongo failure."""
    global _user_repository, _org_repository, _revocation_repository, _app_account_repository

    if not auth_settings.mongo_uri:
        logger.warning(
            "Neither AUTH_MONGO_URI nor MONGO_URI is set — Auth service falling "
            "back to in-memory storage. Data will not survive a restart."
        )
        _user_repository = InMemoryUserRepository()
        _org_repository = InMemoryOrganizationRepository()
        _revocation_repository = InMemoryRevocationRepository()
        _app_account_repository = InMemoryAppAccountRepository()
        return

    try:
        from pymongo import ASCENDING, IndexModel

        from .mongo_connection import get_connection

        conn = await get_connection()

        users_col = conn.get_collection(auth_settings.users_collection)
        await users_col.create_indexes([
            IndexModel([("user_id", ASCENDING)], unique=True, name="user_id_unique"),
            IndexModel([("email", ASCENDING)], unique=True, name="email_unique"),
        ])
        _user_repository = MongoUserRepository(users_col)

        orgs_col = conn.get_collection(auth_settings.organizations_collection)
        await orgs_col.create_indexes([
            IndexModel([("org_id", ASCENDING)], unique=True, name="org_id_unique"),
        ])
        _org_repository = MongoOrganizationRepository(orgs_col)

        revoked_col = conn.get_collection(auth_settings.revoked_tokens_collection)
        await revoked_col.create_indexes([
            IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0, name="ttl_expires_at"),
        ])
        _revocation_repository = MongoRevocationRepository(revoked_col)

        app_accounts_col = conn.get_collection(auth_settings.app_accounts_collection)
        await app_accounts_col.create_indexes([
            IndexModel([("account_id", ASCENDING)], unique=True, name="account_id_unique"),
        ])
        _app_account_repository = MongoAppAccountRepository(app_accounts_col)

        logger.info("Auth repository: MongoDB (db=%s)", conn.db_name)
    except Exception as exc:  # noqa: BLE001
        logger.error("Auth: MongoDB connection failed (%s) — falling back to in-memory.", exc)
        _user_repository = InMemoryUserRepository()
        _org_repository = InMemoryOrganizationRepository()
        _revocation_repository = InMemoryRevocationRepository()
        _app_account_repository = InMemoryAppAccountRepository()


async def close_repository() -> None:
    from .mongo_connection import close_connection

    await close_connection()


def get_repository() -> UserRepository:
    if _user_repository is None:
        raise RuntimeError("Auth repository not initialised — call init_repository() at startup.")
    return _user_repository


def get_org_repository() -> OrganizationRepository:
    if _org_repository is None:
        raise RuntimeError("Auth repository not initialised — call init_repository() at startup.")
    return _org_repository


def get_revocation_repository() -> RevocationRepository:
    if _revocation_repository is None:
        raise RuntimeError("Auth repository not initialised — call init_repository() at startup.")
    return _revocation_repository


def get_app_account_repository() -> AppAccountRepository:
    if _app_account_repository is None:
        raise RuntimeError("Auth repository not initialised — call init_repository() at startup.")
    return _app_account_repository
