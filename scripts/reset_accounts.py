"""DESTRUCTIVE: wipe the user and app-account collections and re-seed them.

This exists because the live data predates account IDs becoming UUIDs and
ended up in a state not worth repairing record-by-record: app accounts keyed
by slug ("richminds", "Guest") sitting alongside a bootstrapped UUID record,
one user pointing at a slug, and eight users belonging to no account at all.
``migrate_account_uuid.py`` rewrites IDs in place and is the right tool when
the data is otherwise sound; this one starts over.

WHAT IT DOES

  1. DELETES every document in ``app_accounts`` and ``users``.
  2. Creates the two well-known accounts, with IDs DERIVED from their slugs
     (features/account_ids.py) rather than minted, so they match
     ``AUTH_ADMIN_ACCOUNT_ID``, the admin console's hardcoded constant, and the
     knowledge console's sign-up target:

       RichMinds  328dc8a2-c30c-5715-920f-21b963b5ce39  (admin)
       Guest      1990b268-3b12-50ab-9be3-09970c1bcfc8  (guest sign-ups)

  3. Creates the seed administrator as a member of RichMinds.

WHAT IT DESTROYS

Every existing user — their credentials and their account membership. Anyone
not re-created by this script has to register again. Revoked-token records are
left alone; outstanding tokens for deleted users stop working once the user
lookup fails, which is immediate.

SAFETY

Dry-run by default: it lists exactly what it would delete and create, and
writes nothing. ``--apply`` commits, and prompts for confirmation unless
``--yes`` is passed. It prints the resolved cluster host and database name
first — in this workspace a local ``.env`` points at the deployed Atlas
cluster, so read that line before committing.

USAGE

    python scripts/reset_accounts.py                      # dry run
    python scripts/reset_accounts.py --apply
    python scripts/reset_accounts.py --apply --password 'other-pass'
"""
from __future__ import annotations

import argparse
import asyncio
import sys
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

from features.account_ids import (  # noqa: E402
    ADMIN_ACCOUNT_SLUG,
    ADMIN_ACCOUNT_UUID,
    GUEST_ACCOUNT_SLUG,
    GUEST_ACCOUNT_UUID,
)
from features.config import auth_settings  # noqa: E402
from features.security import hash_password  # noqa: E402

DEFAULT_ADMIN_EMAIL = "richminds84@gmail.com"
DEFAULT_ADMIN_NAME = "Rich Minds"
DEFAULT_ADMIN_PASSWORD = "kkkkkkkk"

ACCOUNTS = [
    {
        "account_id": ADMIN_ACCOUNT_UUID,
        "legacy_account_id": ADMIN_ACCOUNT_SLUG,
        "name": "RichMinds",
        "description": "Maintains all the app accounts.",
        "app_type": "admin",
    },
    {
        "account_id": GUEST_ACCOUNT_UUID,
        "legacy_account_id": GUEST_ACCOUNT_SLUG,
        "name": "Guest",
        "description": "Maintains all the Guest user for knowledge service.",
        "app_type": "service",
    },
]


def _safe_host(uri: str) -> str:
    """Host of a Mongo URI with credentials stripped — safe to print."""
    if not uri:
        return "(unset)"
    try:
        return urlsplit(uri).netloc.rsplit("@", 1)[-1] or "(unparseable)"
    except Exception:  # noqa: BLE001
        return "(unparseable)"


def _new_user_id() -> str:
    """Same shape service._new_user_id produces, so seeded users are
    indistinguishable from registered ones."""
    return f"USR-{uuid4().hex[:12].upper()}"


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apply", action="store_true", help="commit (default: dry run)")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    ap.add_argument("--email", default=DEFAULT_ADMIN_EMAIL, help="seed administrator's email")
    ap.add_argument("--name", default=DEFAULT_ADMIN_NAME, help="seed administrator's display name")
    ap.add_argument(
        "--password", default=DEFAULT_ADMIN_PASSWORD, help="seed administrator's password"
    )
    args = ap.parse_args()

    if not auth_settings.mongo_uri:
        print("AUTH_MONGO_URI (or MONGO_URI) is not set — nothing to reset.", file=sys.stderr)
        return 2

    # Guard against the admin account being unreachable after the reset: the
    # seed user is made a member of ADMIN_ACCOUNT_UUID, so an overridden env
    # var pointing somewhere else would leave nobody able to administer.
    if auth_settings.admin_account_id != ADMIN_ACCOUNT_UUID:
        print(
            f"AUTH_ADMIN_ACCOUNT_ID is {auth_settings.admin_account_id!r} but this script seeds "
            f"the admin into {ADMIN_ACCOUNT_UUID!r}. Unset the override or the seeded user "
            "will not be an administrator.",
            file=sys.stderr,
        )
        return 2

    from motor.motor_asyncio import AsyncIOMotorClient

    email = args.email.strip().lower()
    mode = "APPLY (destructive)" if args.apply else "DRY RUN (no writes)"
    print(f"\n  Mode:     {mode}")
    print(f"  Target:   {_safe_host(auth_settings.mongo_uri)} / {auth_settings.mongo_db_name}\n")

    client = AsyncIOMotorClient(auth_settings.mongo_uri)
    try:
        db = client[auth_settings.mongo_db_name]
        accounts_col = db[auth_settings.app_accounts_collection]
        users_col = db[auth_settings.users_collection]

        existing_accounts = await accounts_col.count_documents({})
        existing_users = [
            u async for u in users_col.find({}, {"_id": 0, "email": 1, "account_id": 1})
        ]

        print(f"  DELETE  {existing_accounts} app account(s)")
        print(f"  DELETE  {len(existing_users)} user(s):")
        for u in existing_users:
            print(f"            {u.get('email', '(no email)')}")
        print()
        print("  CREATE  accounts:")
        for a in ACCOUNTS:
            print(f"            {a['name']:<10} {a['account_id']}  — {a['description']}")
        print("  CREATE  user:")
        print(f"            {email} ({args.name}) in RichMinds, is_admin=True")
        print()

        if not args.apply:
            print("  Nothing written. Re-run with --apply to commit.\n")
            return 0

        if not args.yes:
            print("  This DELETES every user above. They will have to register again.")
            if input("  Type 'reset' to proceed: ").strip() != "reset":
                print("  Aborted.\n")
                return 1
            print()

        await accounts_col.delete_many({})
        await users_col.delete_many({})

        now = datetime.now(UTC)
        await accounts_col.insert_many(
            [
                {
                    **a,
                    "app_url": "",
                    "enabled": True,
                    "created_by": "system:reset",
                    "created_at": now,
                    "updated_at": None,
                }
                for a in ACCOUNTS
            ]
        )
        user_id = _new_user_id()
        await users_col.insert_one(
            {
                "user_id": user_id,
                "email": email,
                "name": args.name.strip(),
                "password_hash": hash_password(args.password),
                "account_id": ADMIN_ACCOUNT_UUID,
                "account_ids": [],
                "created_at": now,
            }
        )

        print(f"  Done. Seeded {user_id} ({email}) as an administrator.")
        print("  Sign in to the admin console with the password you passed.\n")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
