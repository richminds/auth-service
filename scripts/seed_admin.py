"""Seed the first administrator of this auth service.

Administration is gated on membership of one app account — the RichMinds admin
application (``AUTH_ADMIN_ACCOUNT_ID``, default "richminds"). A user whose
``account_id`` equals it is an admin; nobody else is. See
features/dependencies.py::require_admin.

The service bootstraps the *account* itself at startup
(features/app_accounts.py::ensure_admin_account), and a brand-new deployment
can then create its first admin through the public register endpoint exactly
once (service.register closes it afterwards). This script covers the case that
can't: an email that **already has a user record** and so can't self-register.

Usage::

    python scripts/seed_admin.py --email you@example.com
    python scripts/seed_admin.py --email you@example.com --password 'new-pass'
    python scripts/seed_admin.py --email you@example.com --dry-run

Idempotent: re-running only rewrites what has drifted. Reads AUTH_MONGO_URI /
AUTH_MONGO_DB_NAME / AUTH_ADMIN_ACCOUNT_ID exactly the way the service does, so
it always targets the same database the service is talking to.

Setting --password overwrites the account's existing password hash, which
signs that user out of every application authenticating against this service.
Omit it to leave the existing password alone and only grant admin.
"""
from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from features.config import auth_settings  # noqa: E402
from features.security import hash_password  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True, help="The user to make an administrator.")
    parser.add_argument(
        "--password",
        default=None,
        help="Optional. Resets the user's password — this signs them out everywhere.",
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

    # 2. Tie the user to it (and optionally reset the password).
    users = db[auth_settings.users_collection]
    user = users.find_one({"email": email})
    if user is None:
        print(
            f"No user {email!r} in this database. Register them first "
            "(POST /auth/register), then re-run.",
            file=sys.stderr,
        )
        return 1

    changes: dict = {}
    if user.get("account_id") != admin_account_id:
        changes["account_id"] = admin_account_id
    if args.password:
        changes["password_hash"] = hash_password(args.password)

    if not changes:
        print("nothing to change — already an administrator")
        return 0

    if args.dry_run:
        print("WOULD set:", ", ".join(sorted(changes)))
        return 0

    users.update_one({"email": email}, {"$set": changes})
    print("updated user:", ", ".join(sorted(changes)))
    if "password_hash" in changes:
        print("NOTE: the password was reset — this signs the user out everywhere.")
    print(f"\n{email} is now an administrator of {admin_account_id!r}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
