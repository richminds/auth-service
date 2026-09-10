"""Seed the first administrator of this auth service.

Administration is gated on holding a user record in ONE app account — the
RichMinds admin application (``AUTH_ADMIN_ACCOUNT_ID``). A record whose
``account_id`` equals it is an admin; nobody else is. See
features/dependencies.py::require_admin.

**This creates a record, it does not move one.** A user document is one person
in one application (features/schemas.py::UserRecord), so granting admin means
adding a record in the admin account, cloning the person's name and password
hash from a record they already have. Their existing records are left exactly
as they are — moving one would silently remove them from the application it
belonged to, and that application's data is scoped on the account they would
have just left.

The service bootstraps the *account* itself at startup
(features/app_accounts.py::ensure_admin_account), and a brand-new deployment
can then create its first admin through the public register endpoint exactly
once (service.register closes it afterwards). This script covers the cases
that can't: an email that already has a record in the admin account and needs
a password reset, and an email whose records are all in other applications.

Usage::

    python scripts/seed_admin.py --email you@example.com
    python scripts/seed_admin.py --email you@example.com --password 'new-pass'
    python scripts/seed_admin.py --email you@example.com --dry-run

Idempotent: re-running only writes what is missing. Reads AUTH_MONGO_URI /
AUTH_MONGO_DB_NAME / AUTH_ADMIN_ACCOUNT_ID exactly the way the service does, so
it always targets the same database the service is talking to.

Setting --password writes that password on the ADMIN record only. Because
records hold independent hashes, this does not change the person's password in
any other application — which is the point: an admin credential should not be
the same secret as the one a guest-facing application holds.
"""
from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from features.config import auth_settings  # noqa: E402
from features.security import hash_password  # noqa: E402


def _new_user_id() -> str:
    """Same shape features/service.py mints, so a seeded record is
    indistinguishable from one the running service created."""
    return f"USR-{uuid4().hex[:12].upper()}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True, help="The user to make an administrator.")
    parser.add_argument(
        "--password",
        default=None,
        help=(
            "Optional. Sets the password on the ADMIN record only — other "
            "applications keep their own, which are stored separately."
        ),
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Report what would change, write nothing."
    )
    args = parser.parse_args()

    if not auth_settings.mongo_uri:
        print("AUTH_MONGO_URI is not set — nothing to seed against.", file=sys.stderr)
        return 1

    from pymongo import MongoClient

    email = args.email.strip().lower()
    admin_account_id = auth_settings.admin_account_id

    db = MongoClient(auth_settings.mongo_uri, serverSelectionTimeoutMS=8000)[
        auth_settings.mongo_db_name
    ]
    print(f"database        : {auth_settings.mongo_db_name}")
    print(f"admin account   : {admin_account_id}")
    print(f"target user     : {email}")

    # 1. The admin app account must exist for anyone to be a member of it.
    accounts = db[auth_settings.app_accounts_collection]
    if accounts.find_one({"account_id": admin_account_id}) is None:
        doc = {
            "account_id": admin_account_id,
            "name": "RichMinds",
            "description": "Administrators of this auth service.",
            "enabled": True,
            "created_by": "system:seed-admin",
            "created_at": datetime.now(UTC).isoformat(),
            "updated_at": None,
        }
        if args.dry_run:
            print(f"WOULD create app account {admin_account_id!r}")
        else:
            accounts.insert_one(doc)
            print(f"created app account {admin_account_id!r}")
    else:
        print(f"app account {admin_account_id!r} already exists")

    # 2. Ensure a record for this email IN the admin account.
    #
    # Not an update of whatever record the email already has: that record
    # belongs to another application, and rewriting its account_id would move
    # the person out of it. Records are per-account now, so admin is an
    # ADDITIONAL record.
    users = db[auth_settings.users_collection]
    existing = list(users.find({"email": email}))
    if not existing:
        print(
            f"No user {email!r} in this database. Register them first "
            "(POST /auth/register), then re-run.",
            file=sys.stderr,
        )
        return 1

    admin_record = next(
        (u for u in existing if u.get("account_id") == admin_account_id), None
    )
    other = [u for u in existing if u.get("account_id") != admin_account_id]
    print(f"existing records : {len(existing)} "
          f"({'admin present' if admin_record else 'none in the admin account'})")

    if admin_record is None:
        # Clone from any record they hold, so they can sign in immediately with
        # the password they already use — unless --password overrides it.
        source = other[0]
        doc = {
            "user_id": _new_user_id(),
            "email": email,
            "name": source.get("name", ""),
            "password_hash": (
                hash_password(args.password) if args.password else source.get("password_hash", "")
            ),
            "account_id": admin_account_id,
            "created_at": datetime.now(UTC).isoformat(),
        }
        if args.dry_run:
            print(f"WOULD create admin record {doc['user_id']} for {email!r}")
            print(
                "       password: "
                + ("as supplied" if args.password else f"cloned from {source.get('user_id')}")
            )
            return 0
        users.insert_one(doc)
        print(f"created admin record {doc['user_id']}")
        print(f"\n{email} is now an administrator of {admin_account_id!r}.")
        return 0

    # They already have one. The only thing left to do is an optional reset.
    if not args.password:
        print("nothing to change — already an administrator")
        return 0

    if args.dry_run:
        print(f"WOULD reset the password on admin record {admin_record.get('user_id')}")
        return 0

    users.update_one(
        {"user_id": admin_record["user_id"]},
        {"$set": {"password_hash": hash_password(args.password)}},
    )
    print(f"reset the password on admin record {admin_record.get('user_id')}")
    print("NOTE: this affects the admin record only — their other applications keep")
    print("      their own passwords, which are stored separately.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
