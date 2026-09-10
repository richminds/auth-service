"""Split per-EMAIL user records into per-(email, account) records.

WHY

``users`` used to hold one document per email, with an ``account_ids`` array
naming every application that person could sign in to. It now holds one
document per email AND account: the same email in two applications is two
records, each with its own ``user_id`` and its own password hash, and the
collection enforces the pair with a unique index (features/repository.py).

Nothing reads ``account_ids`` any more. A record left in the old shape parses
— pydantic ignores unknown keys — but its ``account_id`` is absent, so it
reads as belonging to NO application: the person can still sign in, and then
finds an empty account picker and no admin rights. That silence is the reason
to run this.

WHAT IT DOES

For every user document holding an ``account_ids`` array:

  * the FIRST entry stays on the existing document, written to ``account_id``.
    Keeping the original document for the first account preserves that
    ``user_id``, which is what the person's existing tokens and any downstream
    data are keyed on — the default account survives the migration untouched.
  * every FURTHER entry becomes a NEW document: same email, same name, same
    password hash, a fresh ``user_id``, and that account. Cloning the hash is
    what keeps the person able to sign in to those applications; the hashes
    are independent from here on.
  * ``account_ids`` is then removed from the original document.

A document with an EMPTY array (or none) gets ``account_id: null`` and stays a
single record — it belongs to no application, which is a real state, not an
error.

INDEXES

The old email-only unique index makes this migration impossible: it rejects
the second document for an email. The service drops it at startup, and so does
this script before it writes anything, replacing it with the compound
``(email, account_id)`` unique index. Running the script against a database
whose service has not been redeployed is therefore safe and order-independent.

DUPLICATE EMAILS ALREADY PRESENT

If two pre-split documents share an email (possible only if the unique index
was ever missing), their arrays are merged by email and the OLDEST document
wins the first account; the others are treated as extra records. Any account
that would produce a duplicate pair is reported and skipped rather than
written, so the unique index can be created afterwards without failing.

SAFETY

Dry-run by default: it prints every document it would create and change and
writes nothing. ``--apply`` commits. It prints the resolved cluster host and
database name first — in this workspace a local ``.env`` points at the
deployed Atlas cluster, so read that line before committing.

Idempotent: a second run finds no ``account_ids`` arrays and does nothing.

USAGE

    python scripts/migrate_user_account_split.py            # dry run
    python scripts/migrate_user_account_split.py --apply
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(_ROOT / ".env", override=False)
except ImportError:  # pragma: no cover — ships with pydantic-settings
    pass

from features.config import auth_settings  # noqa: E402


def _new_user_id() -> str:
    """Same shape as features/service.py mints, so migrated records are
    indistinguishable from ones the running service creates."""
    return f"USR-{uuid4().hex[:12].upper()}"


def _safe_host(uri: str) -> str:
    """Host of a Mongo URI with credentials stripped — safe to print."""
    if not uri:
        return "(unset)"
    try:
        return urlsplit(uri).netloc.rsplit("@", 1)[-1] or "(unparseable)"
    except Exception:  # noqa: BLE001
        return "(unparseable)"


async def _fix_indexes(col, apply: bool) -> list[str]:
    """Drop the email-only unique index, add the compound one.

    Done BEFORE any write: while ``email_unique`` exists the server rejects the
    second document for an email, which is exactly what this script creates. A
    dry run reports the index work without performing it, so the plan a dry run
    prints is the plan an apply carries out.
    """
    from pymongo import ASCENDING
    from pymongo.errors import OperationFailure

    notes: list[str] = []
    names = set()
    async for index in col.list_indexes():
        names.add(index.get("name"))

    if "email_unique" in names:
        notes.append("DROP   index email_unique (email-only, blocks the split)")
        if apply:
            try:
                await col.drop_index("email_unique")
            except OperationFailure as exc:
                if exc.code not in (26, 27):
                    raise
    else:
        notes.append("index email_unique already absent")

    if "email_account_unique" in names:
        notes.append("index email_account_unique already present")
    else:
        notes.append("CREATE index email_account_unique (email, account_id)")
        if apply:
            await col.create_index(
                [("email", ASCENDING), ("account_id", ASCENDING)],
                unique=True,
                name="email_account_unique",
            )
    return notes


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apply", action="store_true", help="commit (default: dry run)")
    args = ap.parse_args()

    if not auth_settings.mongo_uri:
        print("AUTH_MONGO_URI (or MONGO_URI) is not set — nothing to migrate.", file=sys.stderr)
        return 2

    from motor.motor_asyncio import AsyncIOMotorClient

    mode = "APPLY (writes)" if args.apply else "DRY RUN (no writes)"
    print(f"\n  Mode:     {mode}")
    print(f"  Target:   {_safe_host(auth_settings.mongo_uri)} / {auth_settings.mongo_db_name}\n")

    client = AsyncIOMotorClient(auth_settings.mongo_uri)
    try:
        col = client[auth_settings.mongo_db_name][auth_settings.users_collection]

        for note in await _fix_indexes(col, args.apply):
            print(f"  {note}")
        print()

        # Group by email so a person's records are decided together — which
        # matters when the pre-split data already has more than one document
        # for an email.
        by_email: dict[str, list[dict]] = defaultdict(list)
        async for doc in col.find({}):
            by_email[str(doc.get("email", "")).strip().lower()].append(doc)

        creates = 0
        updates = 0
        skipped: list[str] = []

        for email, docs in sorted(by_email.items()):
            docs.sort(key=lambda d: str(d.get("created_at") or ""))
            primary = docs[0]

            # Accounts this person holds, in order, across every document that
            # shares the email. Both shapes are read: the array (pre-split) and
            # the flat field (already split, or partially migrated).
            wanted: list[str] = []
            for doc in docs:
                for account_id in list(doc.get("account_ids") or []):
                    if account_id and account_id not in wanted:
                        wanted.append(str(account_id))
                flat = doc.get("account_id")
                if flat and str(flat) not in wanted:
                    wanted.append(str(flat))

            # Accounts already covered by a document that names them flatly —
            # those need no new record.
            covered = {
                str(d.get("account_id")): d for d in docs if d.get("account_id")
            }

            if not wanted:
                if "account_ids" in primary or primary.get("account_id", "missing") == "missing":
                    print(f"  UPDATE  {email:<38} -> account_id: null (no application)")
                    updates += 1
                    if args.apply:
                        await col.update_one(
                            {"_id": primary["_id"]},
                            {"$set": {"account_id": None}, "$unset": {"account_ids": ""}},
                        )
                continue

            first = wanted[0]
            # The first account stays on the ORIGINAL document so its user_id —
            # what existing tokens and downstream rows are keyed on — survives.
            if str(primary.get("account_id") or "") != first:
                if first in covered and covered[first]["_id"] != primary["_id"]:
                    skipped.append(f"{email} / {first} (already on another document)")
                else:
                    print(f"  UPDATE  {email:<38} -> account_id: {first}")
                    updates += 1
                    if args.apply:
                        await col.update_one(
                            {"_id": primary["_id"]},
                            {"$set": {"account_id": first}, "$unset": {"account_ids": ""}},
                        )
                    covered[first] = primary
            elif "account_ids" in primary:
                print(f"  UPDATE  {email:<38} -> drop account_ids (keeps {first})")
                updates += 1
                if args.apply:
                    await col.update_one(
                        {"_id": primary["_id"]}, {"$unset": {"account_ids": ""}}
                    )

            for account_id in wanted[1:]:
                if account_id in covered:
                    continue
                user_id = _new_user_id()
                print(f"  CREATE  {email:<38} -> account_id: {account_id}  ({user_id})")
                creates += 1
                if args.apply:
                    await col.insert_one(
                        {
                            "user_id": user_id,
                            "email": email,
                            "name": primary.get("name", ""),
                            # Cloned so the person can still sign in to this
                            # application. Independent from now on.
                            "password_hash": primary.get("password_hash", ""),
                            "account_id": account_id,
                            "created_at": (
                                primary.get("created_at") or datetime.now(UTC).isoformat()
                            ),
                        }
                    )
                covered[account_id] = {"_id": None}

            # Any further pre-split document for this email that still carries
            # an array has now been represented by the records above.
            for doc in docs[1:]:
                if "account_ids" in doc:
                    print(f"  UPDATE  {email:<38} -> drop account_ids (extra document)")
                    updates += 1
                    if args.apply:
                        await col.update_one({"_id": doc["_id"]}, {"$unset": {"account_ids": ""}})

        print()
        for note in skipped:
            print(f"  SKIP    {note}")
        if skipped:
            print()
        print(f"  {creates} record(s) to create, {updates} to update.")
        if not args.apply:
            print("  Nothing written. Re-run with --apply to commit.\n")
        else:
            print("  Done.\n")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
