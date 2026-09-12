"""Account identifier generation.

An app account's ``account_id`` is a UUID, not a readable slug. Applications
send it as ``LoginRequest.account_id``, downstream services scope their data
on it, and it is what travels in the token.

Every account's ID is MINTED here — the admin account's included. Nothing in
this service needs to know an account's ID before the account exists: what
makes a user an administrator is the TYPE of the account their record belongs
to (``AppAccountRecord.app_type == AppType.ADMIN``, see
features/app_accounts.py::is_admin_account), not a match against a configured
value. So there is no ID to predict, no reason to derive one from a slug, and
no setting to keep in step between environments. An application's ID is read
off its record after it is created — the admin console shows it, and
app_accounts.ensure_admin_account returns it — and put in that application's
own configuration, which is the only place it lives.
"""
from __future__ import annotations

import uuid


def new_account_uuid() -> str:
    """A fresh ID for an account — registered through the API or bootstrapped."""
    return str(uuid.uuid4())
