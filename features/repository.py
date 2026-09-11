"""Auth persistence — users, app accounts, and revoked-token collections.

Three backends per entity behind a Protocol: InMemory* (process-local, used
when no Mongo URI resolves) and Mongo* (Motor, selected once a URI resolves).
All three share ONE Motor connection (features/mongo_connection.py) rather
than opening a separate pool per concern.

Persists into the configured AUTH_MONGO_URI / AUTH_MONGO_DB_NAME database —
by default the SAME shared database the calling application's monolith uses
(see features/config.py), in its own `users` / `app_accounts` collections,
plus a `revoked_tokens` collection (TTL-indexed) that the source
implementation instead kept in a generic app-wide cache.

**`users` is keyed on (email, account_id), not email.** One document is one
person in one application, so the same email may appear once per account. The
unique index is the compound pair; the old email-only unique index is DROPPED
at startup if it is still there, because leaving it would silently forbid the
second account and surface as a duplicate-key error nobody asked for.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol, runtime_checkable

from .config import auth_settings
from .schemas import AppAccountRecord, PasswordResetTokenRecord, UserRecord

logger = logging.getLogger(__name__)

_user_repository: "UserRepository | None" = None
_revocation_repository: "RevocationRepository | None" = None
_app_account_repository: "AppAccountRepository | None" = None
_password_reset_repository: "PasswordResetRepository | None" = None


class DuplicateUserError(Exception):
    """The (email, account_id) pair is already taken.

    Raised by ``create`` so the service layer sees one exception whichever
    backend is in play, rather than a pymongo DuplicateKeyError from one and a
    ValueError from the other. Under the old email-only unique index this
    condition was checked only in application code, so a race between two
    registrations surfaced as an unhandled 500; now it is a typed error the
    controller maps to 409.
    """


@runtime_checkable
class UserRepository(Protocol):
    """User documents, keyed on (email, account_id).

    ``get_by_email`` is deliberately absent: with one document per account an
    email no longer identifies a single record, and a method that returned
    "the" user for an email would have to pick one arbitrarily. Callers ask
    either for every record sharing an email (``list_by_email``) or for the
    one record in a named account (``get_by_email_account``), which forces the
    ambiguity to be resolved at the call site where the answer is known.
    """

    async def list_by_email(self, email: str) -> list[UserRecord]: ...
    async def get_by_email_account(
        self, email: str, account_id: str | None
    ) -> UserRecord | None: ...
    async def get_by_id(self, user_id: str) -> UserRecord | None: ...
    async def create(self, user: UserRecord) -> None: ...
    async def delete_by_id(self, user_id: str) -> bool: ...
    async def list_all(self) -> list[UserRecord]: ...
    async def update_account(self, user_id: str, account_id: str | None) -> UserRecord | None: ...
    async def update_password_hash(self, user_id: str, password_hash: str) -> None: ...


@runtime_checkable
@runtime_checkable
class RevocationRepository(Protocol):
    async def revoke(self, jti: str, ttl_seconds: int) -> None: ...
    async def is_revoked(self, jti: str) -> bool: ...


@runtime_checkable
class AppAccountRepository(Protocol):
    """Registered applications — the value a user's account_id points at."""

    async def create(self, account: AppAccountRecord) -> None: ...
    async def get(self, account_id: str) -> AppAccountRecord | None: ...
    async def list_all(self) -> list[AppAccountRecord]: ...
    async def update(self, account_id: str, changes: dict) -> AppAccountRecord | None: ...
    async def delete(self, account_id: str) -> bool: ...


@runtime_checkable
class PasswordResetRepository(Protocol):
    """Issued password-reset tokens, keyed on the SHA-256 hash of the raw token.

    Keyed on the hash rather than an id because that is the only thing a
    redemption request can present: the client holds the raw token, hashes are
    what we stored, and looking one up IS the authentication step.
    """

    async def create(self, record: PasswordResetTokenRecord) -> None: ...
    async def get_by_hash(self, token_hash: str) -> PasswordResetTokenRecord | None: ...
    async def mark_used(self, token_hash: str, used_at: datetime) -> None: ...
    async def invalidate_for_user(self, user_id: str, used_at: datetime) -> int: ...


# ---------------------------------------------------------------------------
# In-memory
# ---------------------------------------------------------------------------

class InMemoryUserRepository:
    """Process-local mirror of the Mongo behaviour, compound key included —
    ``create`` raises DuplicateUserError on a repeated (email, account_id) so
    tests exercise the same rejection the unique index performs in Mongo."""

    def __init__(self) -> None:
        self._by_id: dict[str, UserRecord] = {}

    @staticmethod
    def _key(email: str, account_id: str | None) -> tuple[str, str | None]:
        return (email.strip().lower(), account_id or None)

    async def list_by_email(self, email: str) -> list[UserRecord]:
        key = email.strip().lower()
        return sorted(
            (u for u in self._by_id.values() if u.email.lower() == key),
            key=lambda u: u.created_at,
        )

    async def get_by_email_account(
        self, email: str, account_id: str | None
    ) -> UserRecord | None:
        want = self._key(email, account_id)
        for u in self._by_id.values():
            if self._key(u.email, u.account_id) == want:
                return u
        return None

    async def get_by_id(self, user_id: str) -> UserRecord | None:
        return self._by_id.get(user_id)

    async def create(self, user: UserRecord) -> None:
        if await self.get_by_email_account(user.email, user.account_id) is not None:
            raise DuplicateUserError(
                f"{user.email!r} already has a record in account {user.account_id!r}"
            )
        self._by_id[user.user_id] = user

    async def delete_by_id(self, user_id: str) -> bool:
        return self._by_id.pop(user_id, None) is not None

    async def list_all(self) -> list[UserRecord]:
        return sorted(self._by_id.values(), key=lambda u: u.created_at)

    async def update_account(self, user_id: str, account_id: str | None) -> UserRecord | None:
        user = self._by_id.get(user_id)
        if user is None:
            return None
        if account_id is not None:
            clash = await self.get_by_email_account(user.email, account_id)
            if clash is not None and clash.user_id != user_id:
                raise DuplicateUserError(
                    f"{user.email!r} already has a record in account {account_id!r}"
                )
        updated = user.model_copy(update={"account_id": account_id})
        self._by_id[user_id] = updated
        return updated

    async def update_password_hash(self, user_id: str, password_hash: str) -> None:
        user = self._by_id.get(user_id)
        if user is not None:
            self._by_id[user_id] = user.model_copy(update={"password_hash": password_hash})


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


class InMemoryPasswordResetRepository:
    """Process-local mirror. Expiry is enforced by the service layer reading
    ``expires_at``, not by eviction, so an expired token can still be found and
    reported as expired rather than as invalid."""

    def __init__(self) -> None:
        self._by_hash: dict[str, PasswordResetTokenRecord] = {}

    async def create(self, record: PasswordResetTokenRecord) -> None:
        self._by_hash[record.token_hash] = record

    async def get_by_hash(self, token_hash: str) -> PasswordResetTokenRecord | None:
        return self._by_hash.get(token_hash)

    async def mark_used(self, token_hash: str, used_at: datetime) -> None:
        record = self._by_hash.get(token_hash)
        if record is not None:
            self._by_hash[token_hash] = record.model_copy(update={"used_at": used_at})

    async def invalidate_for_user(self, user_id: str, used_at: datetime) -> int:
        count = 0
        for token_hash, record in list(self._by_hash.items()):
            if record.user_id == user_id and record.used_at is None:
                self._by_hash[token_hash] = record.model_copy(update={"used_at": used_at})
                count += 1
        return count


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

    async def list_by_email(self, email: str) -> list[UserRecord]:
        """Every record sharing an email, oldest first.

        Oldest-first is load-bearing, not cosmetic: it is what makes "the
        user's default account" a stable, derivable fact now that no array
        holds the ordering. The first record created for an email is the one a
        login naming no account resolves to.
        """
        cursor = self._col.find({"email": email.strip().lower()}).sort("created_at", 1)
        docs = await cursor.to_list(length=1_000)
        out: list[UserRecord] = []
        for d in docs:
            d.pop("_id", None)
            try:
                out.append(UserRecord(**d))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping malformed user document: %s", exc)
        return out

    async def get_by_email_account(
        self, email: str, account_id: str | None
    ) -> UserRecord | None:
        # A record with no account is stored with account_id absent OR null
        # depending on when it was written, so match both rather than only the
        # shape this version happens to produce.
        criteria: dict = {"email": email.strip().lower()}
        if account_id:
            criteria["account_id"] = account_id
        else:
            criteria["$or"] = [{"account_id": None}, {"account_id": {"$exists": False}}]
        d = await self._col.find_one(criteria)
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
        try:
            await self._col.insert_one(doc)
        except Exception as exc:  # noqa: BLE001
            # The unique (email, account_id) index is the authority, not the
            # service's prior existence check — two concurrent registrations
            # both pass that check and one of them lands here. Translating it
            # keeps that race a 409 instead of the 500 it used to be.
            from pymongo.errors import DuplicateKeyError

            if isinstance(exc, DuplicateKeyError):
                raise DuplicateUserError(
                    f"{user.email!r} already has a record in account {user.account_id!r}"
                ) from exc
            raise

    async def delete_by_id(self, user_id: str) -> bool:
        result = await self._col.delete_one({"user_id": user_id})
        return result.deleted_count > 0

    async def update_account(self, user_id: str, account_id: str | None) -> UserRecord | None:
        """Move one record to a different application.

        Also clears any leftover ``account_ids`` array, so a record written
        before the split cannot keep a stale membership list beside the field
        that now decides everything.
        """
        from pymongo import ReturnDocument
        from pymongo.errors import DuplicateKeyError

        try:
            d = await self._col.find_one_and_update(
                {"user_id": user_id},
                {"$set": {"account_id": account_id}, "$unset": {"account_ids": ""}},
                return_document=ReturnDocument.AFTER,
            )
        except DuplicateKeyError as exc:
            raise DuplicateUserError(
                f"a record already exists in account {account_id!r} for this email"
            ) from exc
        if d is None:
            return None
        d.pop("_id", None)
        return UserRecord(**d)

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

    async def update_password_hash(self, user_id: str, password_hash: str) -> None:
        await self._col.update_one(
            {"user_id": user_id}, {"$set": {"password_hash": password_hash}}
        )


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


class MongoPasswordResetRepository:
    """TTL-indexed on ``expires_at`` so redeemed and abandoned tokens both age
    out on their own. The index is created once in init_repository().

    Mongo's TTL monitor runs about once a minute, so a token can outlive its
    ``expires_at`` in the collection by up to that long. Expiry is therefore
    ALSO checked in the service layer against the stored timestamp — the index
    is housekeeping, not the security control.
    """

    def __init__(self, col) -> None:
        self._col = col

    async def create(self, record: PasswordResetTokenRecord) -> None:
        doc = record.model_dump(mode="json")
        doc["email"] = doc["email"].strip().lower()
        await self._col.insert_one(doc)

    async def get_by_hash(self, token_hash: str) -> PasswordResetTokenRecord | None:
        d = await self._col.find_one({"token_hash": token_hash})
        if d is None:
            return None
        d.pop("_id", None)
        return PasswordResetTokenRecord(**d)

    async def mark_used(self, token_hash: str, used_at: datetime) -> None:
        await self._col.update_one(
            {"token_hash": token_hash}, {"$set": {"used_at": used_at.isoformat()}}
        )

    async def invalidate_for_user(self, user_id: str, used_at: datetime) -> int:
        result = await self._col.update_many(
            {"user_id": user_id, "used_at": None},
            {"$set": {"used_at": used_at.isoformat()}},
        )
        return result.modified_count


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

async def _ensure_user_indexes(col, ascending, index_model) -> None:
    """Put the `users` collection on the (email, account_id) unique key.

    Two steps, and the order matters. The email-only unique index has to go
    FIRST: while it exists, a second record for the same email in a different
    account is rejected by the server, which is precisely the thing this
    version exists to allow. Creating the compound index without dropping the
    old one would leave the stricter rule in force and the change would look
    like it silently did nothing.

    Dropping is best-effort and idempotent — a fresh deployment has no such
    index, and a second process may have dropped it a moment ago. Neither is
    an error worth failing startup over, so both are swallowed; anything else
    is logged and re-raised, because a users collection whose constraints we
    could not establish is not something to start serving on.

    The compound index is created after, and is itself the enforcement: it
    rejects a repeat of a pair even when two registrations race past the
    service's existence check. `account_id` is nullable, and Mongo indexes a
    missing field as null, so a user who belongs to no application yet is
    still limited to one such record per email — which is what we want.
    """
    from pymongo.errors import OperationFailure

    try:
        await col.drop_index("email_unique")
        logger.info(
            "Auth: dropped the legacy email-only unique index — users are now "
            "keyed on (email, account_id), so one email may exist once per account."
        )
    except OperationFailure as exc:
        # IndexNotFound (27) / NamespaceNotFound (26): nothing to drop.
        if exc.code not in (26, 27):
            logger.error("Auth: could not drop the legacy email_unique index: %s", exc)
            raise

    await col.create_indexes([
        index_model([("user_id", ascending)], unique=True, name="user_id_unique"),
        index_model(
            [("email", ascending), ("account_id", ascending)],
            unique=True,
            name="email_account_unique",
        ),
    ])


async def init_repository() -> None:
    """Initialise the process-wide repositories. Idempotent-ish: safe to call
    once at startup; falls back to in-memory storage on any Mongo failure."""
    global _user_repository, _revocation_repository, _app_account_repository
    global _password_reset_repository

    if not auth_settings.mongo_uri:
        logger.warning(
            "Neither AUTH_MONGO_URI nor MONGO_URI is set — Auth service falling "
            "back to in-memory storage. Data will not survive a restart."
        )
        _user_repository = InMemoryUserRepository()
        _revocation_repository = InMemoryRevocationRepository()
        _app_account_repository = InMemoryAppAccountRepository()
        _password_reset_repository = InMemoryPasswordResetRepository()
        return

    try:
        from pymongo import ASCENDING, IndexModel

        from .mongo_connection import get_connection

        conn = await get_connection()

        users_col = conn.get_collection(auth_settings.users_collection)
        await _ensure_user_indexes(users_col, ASCENDING, IndexModel)
        _user_repository = MongoUserRepository(users_col)

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

        reset_col = conn.get_collection(auth_settings.password_reset_tokens_collection)
        await reset_col.create_indexes([
            IndexModel([("token_hash", ASCENDING)], unique=True, name="token_hash_unique"),
            IndexModel([("user_id", ASCENDING)], name="user_id"),
            IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0, name="ttl_expires_at"),
        ])
        _password_reset_repository = MongoPasswordResetRepository(reset_col)

        logger.info("Auth repository: MongoDB (db=%s)", conn.db_name)
    except Exception as exc:  # noqa: BLE001
        logger.error("Auth: MongoDB connection failed (%s) — falling back to in-memory.", exc)
        _user_repository = InMemoryUserRepository()
        _revocation_repository = InMemoryRevocationRepository()
        _app_account_repository = InMemoryAppAccountRepository()
        _password_reset_repository = InMemoryPasswordResetRepository()


async def close_repository() -> None:
    from .mongo_connection import close_connection

    await close_connection()


def get_repository() -> UserRepository:
    if _user_repository is None:
        raise RuntimeError("Auth repository not initialised — call init_repository() at startup.")
    return _user_repository


def get_revocation_repository() -> RevocationRepository:
    if _revocation_repository is None:
        raise RuntimeError("Auth repository not initialised — call init_repository() at startup.")
    return _revocation_repository


def get_app_account_repository() -> AppAccountRepository:
    if _app_account_repository is None:
        raise RuntimeError("Auth repository not initialised — call init_repository() at startup.")
    return _app_account_repository

def get_password_reset_repository() -> PasswordResetRepository:
    if _password_reset_repository is None:
        raise RuntimeError("Auth repository not initialised — call init_repository() at startup.")
    return _password_reset_repository

