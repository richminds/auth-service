"""Request/response models for the Auth service.

One scope, not two. A user belongs to APP ACCOUNTS (``account_id`` plus
``account_ids``) and nothing else — there is no separate organization or
tenant field, and downstream services scope their data on the account.

**In responses, ``accounts`` carries all of it.** ``UserPublic`` deliberately
does NOT repeat ``account_id``/``account_ids`` alongside it: those were three
views of the same membership that could disagree, and a client had no way to
tell which was authoritative. The one thing the flat fields said that the list
did not — WHICH account this session is scoped to — is now ``selected`` on the
list entry itself, so the list really is the whole story.

An ``account_id`` is a UUID (see features/account_ids.py), never a readable
slug.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator


class UserRecord(BaseModel):
    """Stored user document (password is hashed, never returned).

    ``account_id`` ties the user to the APPLICATION they belong to — an app
    account (see app_accounts.py). It is the only scope: membership of the
    configured admin app account (``AUTH_ADMIN_ACCOUNT_ID``) is what
    ``require_admin`` checks, and downstream services filter their data on the
    same value.

    Documents written before the organization concept was removed may still
    carry an ``org_id`` field; pydantic ignores unknown keys, so they load
    unchanged and the value is simply no longer read.
    """

    user_id: str
    email: str
    name: str
    password_hash: str
    account_id: str | None = None
    account_ids: list[str] = Field(default_factory=list)
    """Additional app accounts this user may sign in through, beyond
    ``account_id`` (their primary/default one). A user who works across two
    applications picks one at login — see service.effective_account_ids, which
    is the single place the two fields are combined."""
    created_at: datetime


class UserPublic(BaseModel):
    """The user, as returned to clients and embedded in tokens.

    Account membership appears exactly once, as ``accounts``. The flat
    ``account_id``/``account_ids`` fields that used to sit beside it are gone:
    they were the same membership expressed three ways, and nothing said which
    copy won if they disagreed. The scoped account is now the entry with
    ``selected`` set — see LoginAccount.
    """

    user_id: str
    email: str
    name: str
    accounts: list["LoginAccount"] = Field(default_factory=list)
    """Every account this user may sign in through, primary one first, each
    with its display name and whether this session is scoped to it.

    Populated wherever a client needs it — login, registration, account
    switch, and GET /auth/me — because with the flat fields removed this is
    the only account information in the response."""
    is_admin: bool = False
    """True when this session is scoped to the configured admin app account —
    the only gate on the account-administration endpoints."""
    created_at: datetime | None = None

    @classmethod
    def from_record(
        cls, r: UserRecord, accounts: list["LoginAccount"] | None = None
    ) -> "UserPublic":
        """Build the response for ``r``.

        ``r.account_id`` is the SCOPED account (service._token_for copies the
        record with the session's account before calling this), so it decides
        both ``is_admin`` and which entry is marked ``selected``. Marking
        happens here rather than in the caller so every path that returns a
        user — login, register, switch, /auth/me — agrees on it.
        """
        from .config import auth_settings

        scoped = r.account_id
        marked = [
            a.model_copy(update={"selected": bool(scoped) and a.account_id == scoped})
            for a in (accounts or [])
        ]
        return cls(
            user_id=r.user_id,
            email=r.email,
            name=r.name,
            accounts=marked,
            is_admin=bool(scoped) and scoped == auth_settings.admin_account_id,
            created_at=r.created_at,
        )


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=200)
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=6, max_length=200)
    account_id: str | None = Field(default=None, max_length=64)
    """The application this user belongs to (an app account's account_id).
    Must reference a registered app account when given — see
    service.register. Omit for a user who isn't tied to one."""


class LoginRequest(BaseModel):
    email: str
    password: str
    account_id: str | None = Field(default=None, max_length=200)
    """Which application this login is for (an app account's account_id).
    The account must be enabled and the user must belong to it — see
    app/controllers/auth_controller.py::login and features/service.py::login.
    Still optional so applications that predate app accounts keep working;
    omitting it skips the membership check."""


class LoginAccount(BaseModel):
    """One app account a user may sign in through, as offered at login.

    Only the fields a sign-in picker needs — the full AppAccountRecord is
    staff-only administration data.
    """

    account_id: str
    name: str
    selected: bool = False
    """True on the account THIS session is scoped to — the one whose ID is in
    the token and which downstream services filter their data on.

    This is what replaced ``UserPublic.account_id``. Without it the response
    would say which accounts a user may use but not which one they are
    currently using, and a client could not render the active account, default
    an account picker, or tell that POST /auth/me/account had taken effect.

    Exactly one entry is marked when the session is scoped to an account the
    user still belongs to; none are marked for a user who belongs to no
    account yet (the client should then prompt for one)."""


class SelectAccountRequest(BaseModel):
    account_id: str = Field(min_length=1, max_length=64)


class AssignUserAccountsRequest(BaseModel):
    account_id: str | None = Field(default=None, max_length=64)
    """The user's primary/default app account."""
    account_ids: list[str] = Field(default_factory=list)
    """Every additional app account the user may sign in through."""


class TokenResponse(BaseModel):
    """What a successful sign-in, sign-up or token re-issue returns.

    Deliberately flat: the token, its type, and the user. Everything about
    account membership lives on ``user`` — repeating ``account_id`` and
    ``accounts`` at this level meant two copies that could disagree, and
    clients had no way to know which one was authoritative.

    ``user.accounts`` is populated only after the password has been verified:
    which accounts an email belongs to is not something an unauthenticated
    caller should be able to probe. More than one entry means the client
    should let the user pick, then call POST /auth/me/account.
    """

    access_token: str
    token_type: str = "bearer"
    user: UserPublic


# ---------------------------------------------------------------------------
# App accounts — the applications registered against this service.
#
# An AppAccountRecord is an *application* that authenticates against this
# service — the value it sends as LoginRequest.account_id when its users sign
# in. It is also the only scope a user has: there is no separate organization
# or tenant field (see UserRecord).
# ---------------------------------------------------------------------------

class AppType(StrEnum):
    """What kind of application an app account is.

    A closed set so the value is validated server-side, not just constrained by
    whatever the UI's dropdown happens to offer. Adding a member here is all
    that's needed to offer a new choice — the console reads these from the API
    schema rather than keeping its own copy.
    """

    WEB = "web"
    MOBILE = "mobile"
    SERVICE = "service"
    ADMIN = "admin"
    OTHER = "other"


class AppAccountRecord(BaseModel):
    account_id: str
    """The account's UUID — generated here, never supplied by the caller, and
    immutable. It is the value the application sends as
    LoginRequest.account_id and the value downstream services scope their data
    on.

    This replaced a caller-chosen slug ("richminds"). The slug was readable but
    it was also guessable, and it conflated a display label with an
    authorization key: knowing it was most of what you needed to name an
    account at login. Operators now read the UUID off this record (the admin
    console shows it) and put it in the application's config.

    See features/account_ids.py for how the value is produced — derived for
    accounts that predate this change so every environment agrees, random for
    ones registered afterwards."""
    legacy_account_id: str = ""
    """The slug this account used before IDs became UUIDs, kept for tracing a
    migrated record back to its old identity and to make the backfill
    (scripts/migrate_account_uuid.py) re-runnable. Never used to authenticate
    or to scope data — it is not an alias for account_id."""
    name: str
    description: str = ""
    app_type: AppType = AppType.OTHER
    """Defaulted rather than required so records written before this field
    existed still load."""
    app_url: str = ""
    """Where the application lives. Free text, but constrained to http(s) when
    given so it's safe to render as a link."""
    enabled: bool = True
    """False takes the account out of service without deleting its record (and
    without losing the ID, which an application may still be sending)."""
    created_by: str
    created_at: datetime
    updated_at: datetime | None = None


def _validate_app_url(value: str) -> str:
    """Empty, or an http(s) URL. Rejecting other schemes keeps the console
    safe to render this as a clickable link (javascript: would not be)."""
    url = value.strip()
    if url and not url.startswith(("http://", "https://")):
        raise ValueError("app_url must start with http:// or https://")
    return url


class CreateAppAccountRequest(BaseModel):
    """Register an application. The ID is generated, so it isn't an input —
    the response carries the UUID to put in that application's config."""

    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=1000)
    app_type: AppType = AppType.OTHER
    app_url: str = Field(default="", max_length=500)

    _check_url = field_validator("app_url")(_validate_app_url)


class UpdateAppAccountRequest(BaseModel):
    """Every field optional — only what's supplied is changed. account_id
    itself is immutable (applications send it; changing it would break their
    logins), so it isn't here."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=1000)
    app_type: AppType | None = None
    app_url: str | None = Field(default=None, max_length=500)
    enabled: bool | None = None

    @field_validator("app_url")
    @classmethod
    def _check_url(cls, v: str | None) -> str | None:
        return None if v is None else _validate_app_url(v)

