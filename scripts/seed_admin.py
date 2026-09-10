"""Seed the RichMinds admin account and its administrator — and nothing else.

Administration is gated on holding a user record in ONE app account — the
RichMinds admin application (``AUTH_ADMIN_ACCOUNT_ID``). A record whose
``account_id`` equals it is an admin; nobody else is. See
features/dependencies.py::require_admin.

**Scope: exactly one account and one user.** This script creates the RichMinds
app account and the administrator record inside it. It deliberately does NOT
create the Guest account or any other well-known account — seeding here means
the administrator, and an application that wants an account registers one
through the API (POST /auth/accounts) where the record's ``created_by`` says
who asked for it.

**It creates the user rather than only promoting one.** A user document is one
person in one application (features/schemas.py::UserRecord), so granting admin
is adding a record in the admin account, never moving an existing record into
it — moving one would silently remove that person from the application it
belonged to, whose data is scoped on the account they just left. The record is
built three ways, in this order:

  * a record already in the admin account  -> left alone, or its password reset
    when --password is given;
  * no admin record but the email has one elsewhere -> a new record CLONED from
    it (same name, same password hash), so the person signs in with the
    password they already use;
  * no record at all -> a new record from the supplied name and password.

Records are written through the service's own repository layer rather than as
hand-written dicts, so a seeded record is exactly what the running service
produces. It does not go through service.register, because that closes the
admin account to self-registration after the first administrator and would
therefore refuse to seed a second one.

Usage::

    python scripts/seed_admin.py                        # defaults below
    python scripts/seed_admin.py --dry-run
    python scripts/seed_admin.py --email you@example.com --password 'new-pass'

Idempotent: re-running only writes what is missing. Reads AUTH_MONGO_URI /
AUTH_MONGO_DB_NAME / AUTH_ADMIN_ACCOUNT_ID exactly the way the service does, so
it always targets the same database the service is talking to — and prints the
resolved host and database first, because in this workspace a local ``.env``
points at the deployed Atlas cluster.

Setting --password writes that password on the ADMIN record only. Because
records hold independent hashes, it does not change the person's password in
any other application — which is the point: an admin credential should not be
the same secret as the one a guest-facing application holds.
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

from features.account_ids import ADMIN_ACCOUNT_UUID  # noqa: E402
from features.app_accounts import ensure_admin_account  # noqa: E402
from features.config import auth_settings  # noqa: E402
from features.repository import (  # noqa: E402
    InMemoryUserRepository,
    close_repository,
    get_repository,
    init_repository,
)
from features.schemas import UserRecord  # noqa: E402
from features.security import hash_password  # noqa: E402

DEFAULT_ADMIN_EMAIL = "richminds84@gmail.com"
DEFAULT_ADMIN_NAME = "Rich Minds"
DEFAULT_ADMIN_PASSWORD = "kkkkkkkk"


def _new_user_id() -> str:
    """Same shape features/service.py mints, so a seeded record is
    indistinguishable from one the running service created."""
    return f"USR-{uuid4().hex[:12].upper()}"


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
    ap.add_argument("--email", default=DEFAULT_ADMIN_EMAIL, help="the administrator's email")
    ap.add_argument("--name", default=DEFAULT_ADMIN_NAME, help="display name for a new record")
    ap.add_argument(
        "--password",
        default=None,
        help=(
            "Password for the ADMIN record only — other applications keep their "
            f"own, which are stored separately. Defaults to the built-in seed "
            f"password when the record has to be created from scratch."
        ),
    )
    ap.add_argument(
        "--dry-run", action="store_true", help="report what would change, write nothing"
    )
    args = ap.parse_args()

    if not auth_settings.mongo_uri:
        print("AUTH_MONGO_URI (or MONGO_URI) is not set — nothing to seed against.", file=sys.stderr)
        return 2

    # The seeded user is made an administrator by being placed in
    # ADMIN_ACCOUNT_UUID, so an env var pointing somewhere else would leave
    # nobody able to administer. Same guard reset_accounts.py uses.
    if auth_settings.admin_account_id != ADMIN_ACCOUNT_UUID:
        print(
            f"AUTH_ADMIN_ACCOUNT_ID is {auth_settings.admin_account_id!r} but this script "
            f"seeds into {ADMIN_ACCOUNT_UUID!r}. Unset the override or the seeded user "
            "will not be an administrator.",
            file=sys.stderr,
        )
        return 2

    email = args.email.strip().lower()
    mode = "DRY RUN (no writes)" if args.dry_run else "APPLY (writes)"
    print(f"\n  Mode:     {mode}")
    print(f"  Target:   {_safe_host(auth_settings.mongo_uri)} / {auth_settings.mongo_db_name}")
    print(f"  Account:  RichMinds  {auth_settings.admin_account_id}")
    print(f"  User:     {email}\n")

    await init_repository()

    # init_repository() falls back to in-memory storage on ANY Mongo failure and
    # says so only in a log line. For the service that is a reasonable
    # degradation; for this script it would be silent success against a dict —
    # it would report a seeded admin and exit 0 having written nothing.
    if isinstance(get_repository(), InMemoryUserRepository):
        print(
            "Repository fell back to IN-MEMORY storage — Mongo is unreachable or "
            "misconfigured. Nothing was written. Check AUTH_MONGO_URI.",
            file=sys.stderr,
        )
        await close_repository()
        return 2

    try:
        repo = get_repository()
        admin_account_id = auth_settings.admin_account_id

        # ── 1. The RichMinds account, and ONLY it ────────────────────────────
        # It has to exist before anyone can hold a record in it. The Guest
        # account is deliberately not created here: this script seeds the
        # administrator, and every other application registers itself through
        # POST /auth/accounts.
        from features.repository import get_app_account_repository

        if await get_app_account_repository().get(admin_account_id) is None:
            if args.dry_run:
                print(f"  WOULD create app account RichMinds ({admin_account_id})")
            else:
                account = await ensure_admin_account()
                print(f"  created app account {account.name} ({account.account_id})")
        else:
            print("  app account RichMinds already exists")

        # ── 2. The administrator's record IN that account ────────────────────
        existing = await repo.list_by_email(email)
        admin_record = next(
            (u for u in existing if u.account_id == admin_account_id), None
        )
        other = [u for u in existing if u.account_id != admin_account_id]

        if admin_record is not None:
            if not args.password:
                print(f"  user {email} is already an administrator "
                      f"({admin_record.user_id}) — nothing to change\n")
                return 0
            if args.dry_run:
                print(f"  WOULD reset the password on {admin_record.user_id}")
                return 0
            await repo.update_password_hash(admin_record.user_id, hash_password(args.password))
            print(f"  reset the password on admin record {admin_record.user_id}")
            print("  NOTE: this affects the admin record only — their other applications")
            print("        keep their own passwords, which are stored separately.\n")
            return 0

        # Cloning from a record they already hold lets them sign in with the
        # password they already use; --password overrides it either way.
        source = other[0] if other else None
        if args.password:
            password_hash = hash_password(args.password)
            origin = "as supplied"
        elif source is not None:
            password_hash = source.password_hash
            origin = f"cloned from {source.user_id}"
        else:
            password_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
            origin = "built-in seed password — CHANGE IT"

        user = UserRecord(
            user_id=_new_user_id(),
            email=email,
            name=(source.name if source is not None else args.name.strip()),
            password_hash=password_hash,
            account_id=admin_account_id,
            created_at=datetime.now(UTC),
        )

        if args.dry_run:
            print(f"  WOULD create admin record {user.user_id} for {email}")
            print(f"         name:     {user.name}")
            print(f"         password: {origin}")
            print("\n  Nothing written. Re-run without --dry-run to commit.\n")
            return 0

        await repo.create(user)
        print(f"  created admin record {user.user_id} ({user.name})")
        print(f"         password: {origin}")
        print(f"\n  {email} is now an administrator of RichMinds ({admin_account_id}).\n")
        if origin.endswith("CHANGE IT"):
            print("  The built-in seed password is in source control. Rotate it with")
            print(f"  --password before this deployment is reachable.\n")
        return 0
    finally:
        await close_repository()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
