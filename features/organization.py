"""Platform-staff identification — explicit email allowlist.

There is no domain matching or other auto-derived organization logic: which
emails count as platform staff (can create organizations, assign users to
them) is entirely controlled by the AUTH_PORTLESS_EMAILS config value (see
config.py). Everyone else lands in the shared Guest organization at signup
(UserRecord.org_id = GUEST_ORG_ID, see service.py::register and
::ensure_guest_organization) unless they pass a real org_id — a staff admin
can move them to a different one later via POST /auth/organizations +
PATCH /auth/users/{id}/organization, or they can self-service it via
POST /auth/me/organization while still on Guest (see
service.py::join_organization).
"""
from __future__ import annotations

from .config import auth_settings

PORTLESS_ORG_ID = "portless"
"""Reserved org_id auto-assigned to platform staff at signup — a fixed label,
never derived from their email. It exists only so records they personally
create have a valid org_id; it plays no role in the allowlist check itself."""

GUEST_ORG_ID = "Guest"
"""Reserved org_id (and name) of the shared organization every non-staff
signup lands in unless it passes a real org_id (see service.py::register).
Bootstrapped idempotently by ensure_guest_organization() — first call ever
made (typically the very first signup, also attempted at startup) creates
the record; every call after that is a single lookup."""


def is_portless_user(email: str) -> bool:
    """True when email is on the AUTH_PORTLESS_EMAILS allowlist."""
    return email.strip().lower() in auth_settings.portless_emails
