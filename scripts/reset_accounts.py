"""DESTRUCTIVE: wipe the user and app-account collections and re-seed them.

This exists because the live data predates account IDs becoming UUIDs and
ended up in a state not worth repairing record-by-record: app accounts keyed
by slug ("richminds", "Guest") sitting alongside a bootstrapped UUID record,
one user pointing at a slug, and eight users belonging to no account at all.
``migrate_account_uuid.py`` rewrites IDs in place and is the right tool when
the data is otherwise sound; this one starts over.

WHAT IT DOES

  1. DELETES every document in ``app_accounts`` and ``users``.
  2. Creates the RichMinds admin account, with an ID DERIVED from its slug
     (features/account_ids.py) rather than minted, so it matches
     ``AUTH_ADMIN_ACCOUNT_ID`` and the admin console's hardcoded constant:

       RichMinds  328dc8a2-c30c-5715-920f-21b963b5ce39  (admin)

     The Guest account is deliberately NOT seeded here — the service creates it
     at startup (``ensure_guest_account``), which is what keeps the knowledge
     console's public sign-up working on a deployment nobody has seeded.

  3. Creates the seed administrator as ONE user record in RichMinds.

     A user record is one person in one application (features/schemas.py), so
     this seeds exactly one document. Giving that email a second application
     later adds a second record rather than editing this one.

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
from pathlib import Path
from urllib.parse import urlsplit

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(_ROOT / ".env", override=False)
except ImportError:  # pragma: no cover — ships with pydantic-settings
    pass

from features import service  # noqa: E402
from features.account_ids import ADMIN_ACCOUNT_UUID  # noqa: E402
from features.app_accounts import ensure_admin_account  # noqa: E402
from features.config import auth_settings  # noqa: E402
from features.repository import (  # noqa: E402
    close_repository,
    get_app_account_repository,
    get_repository,
    init_repository,
)
from features.schemas import RegisterRequest  # noqa: E402

DEFAULT_ADMIN_EMAIL = "richminds84@gmail.com"
DEFAULT_ADMIN_NAME = "Rich Minds"
DEFAULT_ADMIN_PASSWORD = "kkkkkkkk"


def _safe_host(uri: str) -> str:
    """Host of a Mongo URI with credentials stripped — safe to print."""
    if not uri:
        return "(unset)"
    try:
        return urlsplit(uri).netloc.rsplit("@", 1)[-1] or "(unparseable)"
    except Exception:  # noqa: BLE001
        return "(unparseable)"


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

    # The repositories the service itself uses, pointed at the same database.
    await init_repository()

    # init_repository() falls back to in-memory storage on ANY Mongo failure,
    # and says so only in a log line. For the service that is a reasonable
    # degradation; for this script it would be silent data loss — it would
    # report nothing to delete, seed into a dict, print "Done", and exit 0
    # having written nothing at all. Fail instead.
    from features.repository import InMemoryUserRepository

    if isinstance(get_repository(), InMemoryUserRepository):
        print(
            "Repository fell back to IN-MEMORY storage — Mongo is unreachable or "
            "misconfigured. Nothing was written. Check AUTH_MONGO_URI.",
            file=sys.stderr,
        )
        await close_repository()
        return 2

    client = AsyncIOMotorClient(auth_settings.mongo_uri)
    try:
        existing_users = await get_repository().list_all()
        existing_accounts = await get_app_account_repository().list_all()

        print(f"  DELETE  {len(existing_accounts)} app account(s)")
        print(f"  DELETE  {len(existing_users)} user(s):")
        for u in existing_users:
            print(f"            {u.email}")
        print()
        print(f"  CREATE  account: RichMinds  {ADMIN_ACCOUNT_UUID}")
        print(f"  CREATE  user:    {email} ({args.name}) in RichMinds, is_admin=True")
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

        # Wipe. This is the one thing with no service-level equivalent — the
        # service has no "delete everything" operation, and should not.
        db = client[auth_settings.mongo_db_name]
        await db[auth_settings.app_accounts_collection].delete_many({})
        await db[auth_settings.users_collection].delete_many({})

        # ── Create through the service's OWN code paths ───────────────────
        # Not hand-written documents. This script used to insert_many() its own
        # dicts, which meant the seeded records could drift from what the
        # running service produces — and did, twice: they carried a
        # legacy_account_id the service no longer writes, and they wrote
        # membership in whichever shape was current when the script was last
        # touched. Going through ensure_admin_account() and service.register()
        # makes that class of bug impossible: whatever the service creates at
        # runtime is exactly what this script creates, including the
        # one-record-per-account shape.
        account = await ensure_admin_account()

        # register() is the real registration path — same validation, same
        # password hashing, same UserRecord shape. Self-registration into the
        # admin account is allowed exactly once per store (service.register),
        # and the wipe above just made this that once.
        token = await service.register(
            RegisterRequest(
                email=email,
                name=args.name.strip(),
                password=args.password,
                account_id=account.account_id,
            )
        )

        user = token.user
        print(f"  Done. Seeded {user.user_id} ({user.email}) as an administrator.")
        print(f"        account:  {account.name} ({account.account_id})")
        print(f"        is_admin: {user.is_admin}")
        print("  Sign in to the admin console with the password you passed.\n")
        return 0
    finally:
        client.close()
        await close_repository()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
