"""Account identifier generation.

An app account's ``account_id`` is a UUID, not a readable slug. Applications
send it as ``LoginRequest.account_id``, downstream services scope their data
on it, and it is what travels in the token.

**Why UUIDs are derived, not random, for known slugs.** The admin app account
has a chicken-and-egg problem: ``AUTH_ADMIN_ACCOUNT_ID`` is the only gate on
administrative access (features/dependencies.py::require_admin), and the
account it names is created at startup by app_accounts.ensure_admin_account.
If that ID were minted randomly, a fresh deployment would generate an ID that
nothing else knows — no default could be correct, the admin console could not
name the account at login, and nobody could be an administrator until an
operator read the value out of Mongo by hand.

Deriving it as a UUIDv5 of a fixed namespace and the account's old slug fixes
that: the value is stable, identical in every environment, knowable before the
account exists, and reproducible by the backfill script
(scripts/migrate_account_uuid.py), so a migrated database and a freshly
bootstrapped one agree on what "richminds" is.

Accounts created through the API afterwards have no such constraint — nothing
needs to predict their ID — so they get a random UUIDv4.
"""
from __future__ import annotations

import uuid

# Fixed namespace for derived account IDs. Changing this value re-derives every
# ID that was generated from a slug, which would orphan already-scoped data —
# treat it as permanent.
ACCOUNT_NAMESPACE = uuid.UUID("a3f5c1d2-8b64-4e7a-9c10-2f8e6d4b7a91")


def account_uuid_for(slug: str) -> str:
    """The stable UUID for a legacy slug (e.g. "richminds").

    Used by the admin bootstrap and by the backfill script, which must agree
    on the value for a migrated database and a fresh one to be equivalent.
    """
    return str(uuid.uuid5(ACCOUNT_NAMESPACE, slug.strip().lower()))


def new_account_uuid() -> str:
    """A fresh ID for an account registered through the API."""
    return str(uuid.uuid4())


# The admin app account's ID, derived from its original slug so it is the same
# in every environment and can serve as the default for AUTH_ADMIN_ACCOUNT_ID.
ADMIN_ACCOUNT_SLUG = "richminds"
ADMIN_ACCOUNT_UUID = account_uuid_for(ADMIN_ACCOUNT_SLUG)

# The guest app account. Derived for the same reason the admin one is: the
# knowledge-ingest console signs new people up into it straight from its own
# sign-in screen, so it needs an ID it can name before the account exists —
# there is no admin session in that flow to look one up with.
GUEST_ACCOUNT_SLUG = "guest"
GUEST_ACCOUNT_UUID = account_uuid_for(GUEST_ACCOUNT_SLUG)
