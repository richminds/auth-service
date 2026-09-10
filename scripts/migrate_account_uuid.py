"""One-way backfill: app account IDs from readable slugs to UUIDs.

``account_id`` used to be a caller-chosen slug ("richminds", "ingest"). It is
now a UUID (features/account_ids.py). The value is not confined to
auth-service — it is written into every downstream record that is scoped by
account — so flipping the code without rewriting the data would leave existing
rows pointing at an identifier nothing issues any more. Concretely, until this
script runs:

  * knowledge-service compares a chunk's ``metadata.account_id`` to the token's
    account (rag/authorization.py::is_authorized_document), so every already-
    ingested document would stop matching and silently vanish from results;
  * llm-gateway's per-account usage stats would split each application's
    history across two identifiers.

WHAT IT TOUCHES (three databases, five collections)

  auth-service      app_accounts   account_id            -> uuid
                    users          account_id (and any legacy
                                   account_ids array)    -> uuid
  knowledge-service chunks         metadata.account_id   -> uuid
                    parent_docs    metadata.account_id   -> uuid
                    graph_chunks   metadata.account_id   -> uuid
  llm-gateway       llm_requests   metadata.account_id   -> uuid

The new ID is ``uuid5(ACCOUNT_NAMESPACE, slug)`` — derived, not random, so this
script and a freshly bootstrapped database agree on what "richminds" is and so
a re-run computes the same answer.

SAFETY

Dry-run by default: it reports what it would change and writes nothing. Pass
``--apply`` to commit. It prints the resolved URI host and database names
before doing anything, because in this workspace a local ``.env`` can point at
the deployed Atlas cluster — read that line before typing ``--apply``.

Idempotent: a value that is already a UUID is left alone, so a partial or
repeated run converges rather than double-encoding.

USAGE

    python scripts/migrate_account_uuid.py                  # dry run
    python scripts/migrate_account_uuid.py --apply          # commit
    python scripts/migrate_account_uuid.py --apply --yes    # no prompt (CI)
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

# Read the same .env the service reads (features/config.py points pydantic at
# it). Without this the script sees only the raw process environment and would
# either abort or, worse, target a different cluster than the running service.
# Real environment variables still win, so CI can override.
try:
    from dotenv import load_dotenv

    load_dotenv(_ROOT / ".env", override=False)
except ImportError:  # pragma: no cover — python-dotenv ships with pydantic-settings
    pass

from features.account_ids import account_uuid_for  # noqa: E402

try:
    from motor.motor_asyncio import AsyncIOMotorClient
except ImportError:  # pragma: no cover
    print("motor is required: pip install motor", file=sys.stderr)
    raise SystemExit(2) from None


# Collections whose account scope lives at `metadata.account_id`, per database.
# Kept as data rather than code so adding a downstream store is one line.
DOWNSTREAM = {
    "knowledge": ("chunks", "parent_docs", "graph_chunks"),
    "gateway": ("llm_requests",),
}


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return False
    return True


def _safe_host(uri: str) -> str:
    """Host of a Mongo URI with any credentials stripped — safe to print."""
    if not uri:
        return "(unset)"
    try:
        netloc = urlsplit(uri).netloc
        return netloc.rsplit("@", 1)[-1] or "(unparseable)"
    except Exception:  # noqa: BLE001
        return "(unparseable)"


class Plan:
    """Accumulates intended changes so a dry run reports the same work an
    apply would do, rather than the two paths drifting apart."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.writes = 0

    def add(self, what: str, count: int) -> None:
        self.lines.append(f"  {count:>7,}  {what}")
        self.writes += count

    def render(self) -> str:
        return "\n".join(self.lines) if self.lines else "  (nothing to change)"


async def build_mapping(auth_db) -> dict[str, str]:
    """slug -> uuid for every app account that still has a slug ID.

    Derived from the account records themselves rather than a hardcoded list,
    so an account registered after this change was written is still covered.
    """
    mapping: dict[str, str] = {}
    async for doc in auth_db["app_accounts"].find({}, {"account_id": 1}):
        current = str(doc.get("account_id") or "")
        if current and not _is_uuid(current):
            mapping[current] = account_uuid_for(current)
    return mapping


async def migrate_app_accounts(auth_db, mapping: dict[str, str], plan: Plan, apply: bool) -> None:
    col = auth_db["app_accounts"]
    for slug, new_id in mapping.items():
        # The admin account may ALREADY exist under its new UUID: the service
        # bootstraps it at startup, so any run of the new code before this
        # script leaves both the old slug record and a fresh UUID one. Keep the
        # UUID record (it is what the running service uses) and drop the slug
        # one rather than failing on the unique index.
        clash = await col.find_one({"account_id": new_id})
        if clash is not None:
            plan.add(f"app_accounts: drop superseded slug record {slug!r}", 1)
            if apply:
                await col.delete_one({"account_id": slug})
            continue

        plan.add(f"app_accounts: {slug!r} -> {new_id}", 1)
        if apply:
            # The old slug is NOT recorded on the migrated document: an account
            # is its UUID and its name, and keeping the slug invited treating
            # it as a second identifier.
            await col.update_one(
                {"account_id": slug},
                {"$set": {"account_id": new_id}, "$unset": {"legacy_account_id": ""}},
            )


async def migrate_users(auth_db, mapping: dict[str, str], plan: Plan, apply: bool) -> None:
    """Rewrite slugs to UUIDs wherever a user record names an account.

    This script only changes the VALUE of an account id, never the shape of the
    record. A user document holds its account in a flat ``account_id`` (one
    record per account — features/schemas.py), and records written before that
    split may still hold an ``account_ids`` array; both are rewritten in place
    so this can run on a database in either shape.

    Turning an array record into per-account records is a different job with
    different consequences (it creates and deletes documents), and it lives in
    scripts/migrate_user_account_split.py. Run this one first so the split
    script sees UUIDs everywhere, then that one.
    """
    col = auth_db["users"]
    for slug, new_id in mapping.items():
        # The flat field — the shape the service writes today.
        n = await col.count_documents({"account_id": slug})
        if n:
            plan.add(f"users.account_id: {slug!r} -> {new_id}", n)
            if apply:
                await col.update_many(
                    {"account_id": slug}, {"$set": {"account_id": new_id}}
                )

        # Pre-split records that still carry the array. Rewritten so the split
        # script has a UUID to work from; `$` updates the first match, so loop
        # until none are left rather than assuming one entry per document.
        while True:
            n = await col.count_documents({"account_ids": slug})
            if not n:
                break
            plan.add(f"users.account_ids[]: {slug!r} -> {new_id}", n)
            if not apply:
                break
            await col.update_many({"account_ids": slug}, {"$set": {"account_ids.$": new_id}})

    remaining = await col.count_documents({"account_ids": {"$exists": True}})
    if remaining:
        plan.add(
            "users still holding an account_ids array "
            "(run migrate_user_account_split.py next)",
            0,
        )


async def migrate_metadata(db, collections, mapping, plan, apply, label) -> None:
    for name in collections:
        if name not in await db.list_collection_names():
            continue
        col = db[name]
        for slug, new_id in mapping.items():
            n = await col.count_documents({"metadata.account_id": slug})
            if not n:
                continue
            plan.add(f"{label}.{name}: {slug!r} -> {new_id}", n)
            if apply:
                await col.update_many(
                    {"metadata.account_id": slug},
                    {"$set": {"metadata.account_id": new_id}},
                )


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apply", action="store_true", help="commit changes (default: dry run)")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = ap.parse_args()

    auth_uri = os.getenv("AUTH_MONGO_URI") or os.getenv("MONGO_URI") or ""
    know_uri = os.getenv("RAG_MONGO_URI") or os.getenv("MONGO_URI") or ""
    gw_uri = os.getenv("LLM_MONGO_URI") or os.getenv("MONGO_URI") or ""
    auth_db_name = os.getenv("AUTH_MONGO_DB_NAME") or os.getenv("MONGO_DB_NAME") or "app"
    know_db_name = (
        os.getenv("RAG_MONGO_DB_NAME") or os.getenv("MONGO_DB_NAME") or "knowledge_service"
    )
    gw_db_name = os.getenv("LLM_MONGO_DB_NAME") or os.getenv("MONGO_DB_NAME") or "llm_gateway"

    if not auth_uri:
        print("AUTH_MONGO_URI (or MONGO_URI) is not set — nothing to migrate.", file=sys.stderr)
        return 2

    mode = "APPLY (writes)" if args.apply else "DRY RUN (no writes)"
    print(f"\n  Mode:       {mode}")
    print(f"  auth:       {_safe_host(auth_uri)} / {auth_db_name}")
    print(f"  knowledge:  {_safe_host(know_uri)} / {know_db_name}")
    print(f"  gateway:    {_safe_host(gw_uri)} / {gw_db_name}\n")

    if args.apply and not args.yes:
        if input("  Type 'migrate' to proceed: ").strip() != "migrate":
            print("  Aborted.")
            return 1
        print()

    auth_client = AsyncIOMotorClient(auth_uri)
    know_client = AsyncIOMotorClient(know_uri) if know_uri else None
    gw_client = AsyncIOMotorClient(gw_uri) if gw_uri else None

    try:
        auth_db = auth_client[auth_db_name]
        mapping = await build_mapping(auth_db)
        if not mapping:
            print("  No slug-shaped account IDs found — already migrated.\n")
            return 0

        print("  Mapping:")
        for slug, new_id in sorted(mapping.items()):
            print(f"    {slug:<24} -> {new_id}")
        print()

        plan = Plan()
        await migrate_app_accounts(auth_db, mapping, plan, args.apply)
        await migrate_users(auth_db, mapping, plan, args.apply)
        if know_client is not None:
            await migrate_metadata(
                know_client[know_db_name], DOWNSTREAM["knowledge"],
                mapping, plan, args.apply, "knowledge",
            )
        if gw_client is not None:
            await migrate_metadata(
                gw_client[gw_db_name], DOWNSTREAM["gateway"],
                mapping, plan, args.apply, "gateway",
            )

        print("  Changes:")
        print(plan.render())
        print(f"\n  {plan.writes:,} document(s) {'updated' if args.apply else 'would change'}.")
        if not args.apply:
            print("  Re-run with --apply to commit.\n")
        else:
            print("\n  Done. Update AUTH_ADMIN_ACCOUNT_ID and each application's")
            print("  configured account_id to the UUIDs above, then redeploy.\n")
        return 0
    finally:
        auth_client.close()
        if know_client is not None:
            know_client.close()
        if gw_client is not None:
            gw_client.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
