"""MongoDB connection manager for the Auth service.

One Motor client shared by the user, organization, and revoked-token
repositories (features/repository.py) — a single pool, not one per concern,
unlike the source implementation's separate blacklist store (which reused a
generic app-wide TTL cache). This service has exactly one storage dependency,
so one connection is simpler and there is nothing else to share it with.

Usage::

    from features.mongo_connection import get_connection

    conn = await get_connection()              # uses auth_settings defaults
    col  = conn.get_collection("users")
    healthy = await conn.ping()
    # at app shutdown:
    await conn.close()
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

_connection: "MongoConnection | None" = None
_lock = asyncio.Lock()


async def get_connection(uri: str | None = None, db_name: str | None = None) -> "MongoConnection":
    """Return (or create) the shared MongoConnection. Safe to call concurrently."""
    from .config import auth_settings

    global _connection
    resolved_uri = uri or auth_settings.mongo_uri
    resolved_db = db_name or auth_settings.mongo_db_name

    async with _lock:
        if _connection is None:
            _connection = MongoConnection(uri=resolved_uri, db_name=resolved_db)
            await _connection.connect()
            logger.info("MongoDB connection established: db=%s", resolved_db)
        return _connection


def get_connection_sync(uri: str | None = None, db_name: str | None = None) -> "MongoConnection":
    """Create a MongoConnection synchronously (Motor client is lazy-connect).

    Use this in __init__ methods; call connect() explicitly to warm it up.
    """
    from .config import auth_settings

    global _connection
    if _connection is not None:
        return _connection
    resolved_uri = uri or auth_settings.mongo_uri
    resolved_db = db_name or auth_settings.mongo_db_name
    _connection = MongoConnection(uri=resolved_uri, db_name=resolved_db)
    return _connection


async def close_connection() -> None:
    global _connection
    if _connection is not None:
        await _connection.close()
        _connection = None


class MongoConnection:
    """Thin wrapper around a Motor AsyncIOMotorClient."""

    def __init__(self, uri: str, db_name: str) -> None:
        import motor.motor_asyncio

        self._uri = uri
        self._db_name = db_name
        self._client = motor.motor_asyncio.AsyncIOMotorClient(
            uri, serverSelectionTimeoutMS=5_000, connectTimeoutMS=5_000
        )
        self._db = self._client[db_name]

    async def connect(self) -> None:
        """Force the connection and verify it is reachable."""
        await self._client.admin.command("ping")

    async def close(self) -> None:
        self._client.close()

    def get_collection(self, name: str) -> Any:
        return self._db[name]

    @property
    def db_name(self) -> str:
        return self._db_name

    async def ping(self) -> bool:
        try:
            await self._client.admin.command("ping")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("MongoDB ping failed: %s", exc)
            return False

    def __repr__(self) -> str:
        return f"MongoConnection(db={self._db_name!r})"
