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
from typing import Protocol, runtime_checkable

from .config import auth_settings
from .schemas import OrganizationRecord, UserRecord

logger = logging.getLogger(__name__)

_user_repository: "UserRepository | None" = None
_org_repository: "OrganizationRepository | None" = None
_revocation_repository: "RevocationRepository | None" = None


@runtime_checkable
class UserRepository(Protocol):
    async def get_by_email(self, email: str) -> UserRecord | None: ...
    async def get_by_id(self, user_id: str) -> UserRecord | None: ...
    async def create(self, user: UserRecord) -> None: ...
    async def list_all(self) -> list[UserRecord]: ...
    async def update_org(self, user_id: str, org_id: str) -> UserRecord | None: ...


@runtime_checkable
class OrganizationRepository(Protocol):
    async def create(self, org: OrganizationRecord) -> None: ...
    async def get(self, org_id: str) -> OrganizationRecord | None: ...
    async def get_by_name(self, name: str) -> OrganizationRecord | None: ...
    async def list_all(self) -> list[OrganizationRecord]: ...
    async def add_known_email(self, org_id: str, email: str) -> OrganizationRecord | None: ...


@runtime_checkable
class RevocationRepository(Protocol):
    async def revoke(self, jti: str, ttl_seconds: int) -> None: ...
    async def is_revoked(self, jti: str) -> bool: ...


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
    global _user_repository, _org_repository, _revocation_repository

    if not auth_settings.mongo_uri:
        logger.warning(
            "Neither AUTH_MONGO_URI nor MONGO_URI is set — Auth service falling "
            "back to in-memory storage. Data will not survive a restart."
        )
        _user_repository = InMemoryUserRepository()
        _org_repository = InMemoryOrganizationRepository()
        _revocation_repository = InMemoryRevocationRepository()
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

        logger.info("Auth repository: MongoDB (db=%s)", conn.db_name)
    except Exception as exc:  # noqa: BLE001
        logger.error("Auth: MongoDB connection failed (%s) — falling back to in-memory.", exc)
        _user_repository = InMemoryUserRepository()
        _org_repository = InMemoryOrganizationRepository()
        _revocation_repository = InMemoryRevocationRepository()


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
