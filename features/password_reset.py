"""Password reset — request a link, then redeem it.

The usual email-a-token flow, with two things a single-application service
gets to skip and this one cannot, because it backs several applications.

**1. A reset is scoped to ONE app account.** A single-application service has
one user per email, so it can resolve a reset from the address alone. Here
users are keyed on (email, account_id) with independent password hashes per
record (features/schemas.py), so an email does not identify a record. The
request therefore carries ``account_id``, the token binds to the resolved
``user_id``, and redeeming it rewrites exactly that one record's hash. A reset
started from one application's frontend cannot change someone's password in
an unrelated application.

**2. The link is built from the app account's own ``app_url``.** A single
configured frontend URL — the single-application norm — would send every
application's users to whichever frontend it named. ``app_url`` is already
registered per application and validated to http(s)
(features/schemas.py::_validate_app_url), so it is both the correct value and
one an operator can set from the account console without a redeploy.
``AUTH_PASSWORD_RESET_URL`` remains as a fallback for accounts that have none.

The flow:

1. ``request_password_reset`` — resolve the record; invalidate that user's
   prior unused tokens; mint a random token; store only its SHA-256 hash with
   an expiry; email the raw token inside a link.
2. ``reset_password`` — look the hash up, reject used/expired/unknown, rewrite
   the password hash, mark the token used.

Every failure in step 1 is silent. The caller always answers with the same
generic message, so this endpoint cannot be used to discover which addresses
are registered or which applications they belong to.

KNOWN GAP: redeeming a token does not revoke that user's existing sessions.
Revocation here is per-token-jti (features/blacklist.py) and we do not hold
the set of a user's outstanding jtis, so an attacker who already has a valid
access token keeps it until it expires (AUTH_ACCESS_TTL_MINUTES, 60 by
default). Closing that needs a per-user "tokens issued before T are invalid"
marker checked during introspection.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .config import auth_settings
from .email import send_password_reset_email, smtp_configured
from .repository import (
    get_app_account_repository,
    get_password_reset_repository,
    get_repository,
)
from .schemas import PasswordResetTokenRecord
from .security import hash_password

logger = logging.getLogger(__name__)

#: Path appended to an application's base URL. Both consoles render their
#: reset screen when this path carries a ``token`` query parameter.
RESET_PATH = "/reset-password"


class InvalidResetTokenError(Exception):
    """The presented token is unknown, already used, or expired (400).

    One exception type for all three because the CLIENT distinction is only a
    better message — none of them grants anything. The message says which.
    """


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _as_utc(value: datetime) -> datetime:
    """Documents written before tz-aware timestamps read back naive; treat
    those as UTC rather than letting the comparison raise."""
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _reset_link(app_url: str, raw_token: str) -> str:
    """Build the link mailed to the user, or "" if we have no base to use.

    ``app_url`` is an application's home, so the reset path is appended —
    unless the value already points at the reset screen, the second of the
    two shapes .env.example documents for ``AUTH_PASSWORD_RESET_URL``.

    Split into components rather than concatenated. Treating the URL as a
    string got this wrong for a base carrying a query
    (``https://app/reset-password?src=email``): the "does it already end in the
    reset path" test looked at the query instead of the path, so the path was
    appended AFTER it — ``?src=email/reset-password&token=…``.
    """
    base = (app_url or auth_settings.password_reset_url or "").strip()
    if not base:
        return ""

    parts = urlsplit(base)
    path = parts.path.rstrip("/")
    if not path.endswith(RESET_PATH):
        path = f"{path}{RESET_PATH}"

    # Drop any token already present so a re-used base can't carry a stale one.
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != "token"]
    query.append(("token", raw_token))

    return urlunsplit((parts.scheme, parts.netloc, path, urlencode(query), parts.fragment))


async def request_password_reset(email: str, account_id: str) -> tuple[bool, str | None]:
    """Mint and dispatch a reset link for one (email, account_id) record.

    Returns ``(dispatched, debug_token)``. ``debug_token`` is the raw token,
    populated only when the message could NOT be sent — it is what makes the
    flow exercisable without a mail server. The controller decides whether to
    surface it (AUTH_EXPOSE_RESET_TOKEN); this layer just reports the fact.

    Returns ``(False, None)`` for every "no" case — unknown email, no record in
    that application, disabled application — because distinguishing them to the
    caller is exactly the enumeration this endpoint must not permit.
    """
    email = email.strip().lower()
    user = await get_repository().get_by_email_account(email, account_id)
    if user is None:
        logger.info("Auth: reset requested for unknown record (account=%s)", account_id)
        return False, None

    account = await get_app_account_repository().get(account_id)
    if account is not None and not account.enabled:
        # Same rule login applies (features/app_accounts.py::assert_login_allowed):
        # a disabled application is out of service. Silent here rather than a
        # 403, so the refusal doesn't confirm the address exists.
        logger.warning("Auth: reset requested for disabled application %s", account_id)
        return False, None

    now = datetime.now(timezone.utc)
    repo = get_password_reset_repository()

    # Supersede this user's outstanding links, so requesting a second one
    # invalidates the first. Without it every link ever mailed stays live until
    # its own expiry, and each is a standing takeover of the account.
    superseded = await repo.invalidate_for_user(user.user_id, now)
    if superseded:
        logger.info("Auth: superseded %d earlier reset token(s) for %s", superseded, user.user_id)

    raw_token = secrets.token_urlsafe(48)
    await repo.create(
        PasswordResetTokenRecord(
            token_hash=_hash_token(raw_token),
            user_id=user.user_id,
            email=user.email,
            account_id=user.account_id,
            expires_at=now + timedelta(minutes=auth_settings.password_reset_ttl_minutes),
            created_at=now,
        )
    )

    app_name = account.name if account is not None else "RichMinds"
    link = _reset_link(account.app_url if account is not None else "", raw_token)
    if not link:
        # The token is already stored, so the dev escape hatch below still
        # works; this is loud because in production it means the user was
        # promised an email that can never arrive.
        logger.error(
            "Auth: no reset link base for account %s — set its app_url in the account "
            "console, or set AUTH_PASSWORD_RESET_URL. No email sent.",
            account_id,
        )
        return False, raw_token

    dispatched = send_password_reset_email(
        to_email=user.email,
        name=user.name,
        app_name=app_name,
        reset_link=link,
        expires_minutes=auth_settings.password_reset_ttl_minutes,
    )
    if not dispatched and not smtp_configured():
        logger.warning(
            "Auth: SMTP unconfigured — reset link for %s was logged, not emailed.", user.email
        )
    return dispatched, (None if dispatched else raw_token)


async def reset_password(raw_token: str, new_password: str) -> None:
    """Redeem a token and rewrite that ONE record's password hash."""
    repo = get_password_reset_repository()
    record = await repo.get_by_hash(_hash_token(raw_token))

    if record is None:
        raise InvalidResetTokenError("This reset link is invalid. Please request a new one.")
    if record.used_at is not None:
        raise InvalidResetTokenError("This reset link has already been used.")
    if _as_utc(record.expires_at) <= datetime.now(timezone.utc):
        # Mongo's TTL monitor only sweeps about once a minute, so an expired
        # document can still be here. The stored timestamp is the authority.
        raise InvalidResetTokenError("This reset link has expired. Please request a new one.")

    user = await get_repository().get_by_id(record.user_id)
    if user is None:
        # The record was deleted after the link was mailed. Same message as an
        # unknown token: there is nothing to reset either way.
        raise InvalidResetTokenError("This reset link is invalid. Please request a new one.")

    await get_repository().update_password_hash(user.user_id, hash_password(new_password))
    await repo.mark_used(record.token_hash, datetime.now(timezone.utc))
    logger.info(
        "Auth: password reset completed for %s (account=%s)", user.user_id, user.account_id
    )
