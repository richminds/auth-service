"""Request/response models for the Auth service.

One scope, not two. A user belongs to APP ACCOUNTS (``account_id`` plus
``account_ids``) and nothing else — there is no separate organization or
tenant field, and downstream services scope their data on the account.

The login/registration response carries the user ONCE: ``account_id``,
``account_ids`` and ``accounts`` all live inside ``user`` rather than being
repeated at the top level.
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

    This is the ONLY place account membership appears in a response — the
    login/registration envelope does not repeat it. ``account_id`` is the
    account this session is scoped to, ``account_ids`` every account the user
    may use, and ``accounts`` the same set with display names for a picker.
    """

    user_id: str
    email: str
    name: str
    account_id: str | None = None
    """The account this session is scoped to. Downstream services filter their
    data on it, so it travels in the token."""
    account_ids: list[str] = Field(default_factory=list)
    """Every account this user may sign in through, primary one first."""
    accounts: list["LoginAccount"] = Field(default_factory=list)
    """The same accounts with display names. Populated only where a client
    needs to choose between them (login, register, account switch); an
    id-and-name pair rather than two positional lists, so a name that happens
    to be duplicated can still be resolved back to its account."""
    is_admin: bool = False
    """True when the user belongs to the configured admin app account — the
    only gate on the account-administration endpoints."""
    created_at: datetime | None = None

    @classmethod
    def from_record(
        cls, r: UserRecord, accounts: list["LoginAccount"] | None = None
    ) -> "UserPublic":
        from .config import auth_settings

        return cls(
            user_id=r.user_id,
            email=r.email,
            name=r.name,
            account_id=r.account_id,
            account_ids=list(r.account_ids),
            accounts=accounts or [],
            is_admin=bool(r.account_id) and r.account_id == auth_settings.admin_account_id,
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

_ACCOUNT_ID_PATTERN = r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$"


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
    """Caller-chosen, stable identifier an application sends as
    LoginRequest.account_id (e.g. "richminds"). Never generated — the
    application already knows the value it will send, so letting the service
    mint one would guarantee a mismatch."""
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
    account_id: str = Field(pattern=_ACCOUNT_ID_PATTERN, max_length=64)
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

