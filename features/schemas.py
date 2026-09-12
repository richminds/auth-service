"""Request/response models for the Auth service.

**One document per (email, account_id).** A stored user record belongs to
exactly ONE app account — ``UserRecord.account_id``, a plain string. A person
who works in two applications has TWO user records, one per account, each with
its own ``user_id``, its own password hash, and its own display name. The
uniqueness rule the ``users`` collection enforces is the PAIR: the same email
may appear once per account and no more (see features/repository.py).

Membership is therefore not stored as a list anywhere — it is DERIVED at
request time by looking up every record sharing an email
(features/service.py::accounts_for_email). That is what keeps the two facts
from drifting: there is no array to fall out of step with the documents it
claims to summarise, because the documents are the only copy.

**In responses, ``accounts`` still carries all of it.** ``UserPublic`` is
unchanged by the split on purpose — clients see the same ``accounts`` list
with the same ``selected`` marker they saw when membership was an array, so
nothing downstream has to know how it is stored.

An ``account_id`` is a UUID (see features/account_ids.py), never a readable
slug.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator


class UserRecord(BaseModel):
    """One stored user document — ONE person in ONE app account.

    ``account_id`` is the application this record belongs to, and it is
    singular because the document is. A person in two applications has two of
    these records: same email, different ``account_id``, different
    ``user_id``, independent password hashes. The ``users`` collection
    enforces that pair as unique, so an email can appear once per account and
    never twice in the same one.

    **This replaced an ``account_ids`` array on a single per-email document.**
    The array made one record answer for several applications, which meant
    every membership change was a read-modify-write of a list, an account
    could be present in the array while nothing in the account collection
    matched it, and there was no way to give a person different credentials or
    a different display name in two applications that do not otherwise trust
    each other. Splitting the document makes membership a fact about which
    documents exist, and Mongo enforces it with a unique index instead of
    application code being careful.

    Membership across accounts is not stored — it is derived per request by
    querying the email (features/service.py::accounts_for_email), so there is
    no second copy to keep in step.

    Documents written before the split may still carry an ``account_ids``
    array (and, older still, a flat ``org_id``); pydantic ignores unknown
    keys, so they load, but their ``account_id`` is absent and they read as
    belonging to no application. Split them with
    scripts/migrate_user_account_split.py.
    """

    user_id: str
    """Unique per DOCUMENT, not per person. The same human in two accounts has
    two user_ids, and the token's ``sub`` is whichever one this session signed
    in as — switching accounts issues a token for the other record."""
    email: str
    """Lowercased on write. Shared across this person's records; it is the key
    that ties them together, and the only one."""
    name: str
    password_hash: str
    """Independent per record. Two accounts' credentials for one email may
    diverge, and nothing here tries to keep them in step — see
    features/service.py::login for how a login with no named account resolves
    which record it is for."""
    account_id: str | None = None
    """The ONE application this record belongs to. ``None`` means the record
    belongs to no application yet; such a user can still sign in, they just
    cannot claim an account. Optional rather than required so a record can be
    created before an administrator assigns it."""
    created_at: datetime


class UserPublic(BaseModel):
    """The user, as returned to clients and embedded in tokens.

    Deliberately UNCHANGED by the one-document-per-account split. Account
    membership still appears exactly once, as ``accounts``, and the account
    this session is scoped to is still the entry with ``selected`` set. The
    list is now assembled from the caller's sibling records rather than read
    off one record's array, but that is a storage detail and no client should
    have to know it.
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
    """True when this session is scoped to an admin-type app account
    (features/app_accounts.py::is_admin_account) — the only gate on the
    account-administration endpoints."""
    created_at: datetime | None = None

    @classmethod
    def from_record(
        cls,
        r: UserRecord,
        accounts: list["LoginAccount"] | None = None,
        scoped_account_id: str | None = None,
        is_admin: bool = False,
    ) -> "UserPublic":
        """Build the response for ``r``.

        ``is_admin`` is supplied by the caller rather than derived here:
        whether the scoped account is admin-type is a fact about that
        account's record (features/app_accounts.py::is_admin_account), and
        this model deliberately does not reach for a repository — the same
        reason ``accounts`` is passed in.

        ``scoped_account_id`` is the account THIS session is scoped to; it
        decides which entry is marked ``selected``. It
        defaults to the record's own ``account_id``, which is now the natural
        answer: a record belongs to exactly one account, so the document the
        caller authenticated as IS the scope. It stays a parameter because
        callers that resolve a sibling record (account switching) already know
        the answer and should not depend on which record they happened to
        load.

        ``accounts`` is passed in rather than queried here because building it
        needs the repository, and this model deliberately does not reach for
        one — see features/service.py::accounts_for_email.

        Marking happens here rather than in each caller so every path that
        returns a user — login, register, switch, /auth/me — agrees on it.
        """
        scoped = scoped_account_id or r.account_id
        marked = [
            a.model_copy(update={"selected": bool(scoped) and a.account_id == scoped})
            for a in (accounts or [])
        ]
        return cls(
            user_id=r.user_id,
            email=r.email,
            name=r.name,
            accounts=marked,
            is_admin=is_admin,
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
    account_ids: list[str] = Field(default_factory=list)
    """Every app account this user should be able to sign in through.

    Still a list on the WIRE even though membership is no longer a list in
    storage: this is a desired end state, and the service reconciles the
    user's documents to match it — creating a record for an account they lack,
    deleting the record for one that has been dropped (see
    features/service.py::assign_user_accounts). Keeping the request shape
    means the admin console's list editor round-trips unchanged.

    Order sets the default: the FIRST entry is what a login naming no account
    resolves to when several match. An empty list removes the user from every
    application, which DELETES all of their records."""


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

    ``ADMIN`` is special: it is what makes an account's members administrators
    (features/app_accounts.py::is_admin_account). Records carry it, but the
    request schemas below refuse it — the one admin account is created by the
    operator bootstrap, never through the API.
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

    Minted (features/account_ids.py) — for every account, the admin one
    included. Nothing needs to predict an ID: what makes an account the admin
    one is its ``app_type``, so even that is read off the record after the
    fact."""
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


def _reject_admin_type(value: AppType | None) -> AppType | None:
    """``admin`` is not assignable through the API.

    An admin-type account is what makes its members administrators
    (features/app_accounts.py::is_admin_account), so accepting it here would
    let any administrator — or a slip in the console's dropdown — mint another
    admin account, or promote an existing application's entire user base by
    flipping its type. The one admin account is created by the operator
    bootstrap (app_accounts.ensure_admin_account) and only there.
    """
    if value == AppType.ADMIN:
        raise ValueError(
            "app_type 'admin' is reserved: the administrator account is created by the "
            "operator bootstrap, not through this API"
        )
    return value


class CreateAppAccountRequest(BaseModel):
    """Register an application. The ID is generated, so it isn't an input —
    the response carries the UUID to put in that application's config."""

    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=1000)
    app_type: AppType = AppType.OTHER
    app_url: str = Field(default="", max_length=500)

    _check_url = field_validator("app_url")(_validate_app_url)
    _check_type = field_validator("app_type")(_reject_admin_type)


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

    _check_type = field_validator("app_type")(_reject_admin_type)



# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------

class PasswordResetTokenRecord(BaseModel):
    """One issued reset token.

    The raw token is NEVER stored — only its SHA-256 hash, so a dump of this
    collection cannot be replayed to take over accounts. The raw value exists
    exactly twice: in the email, and in the request that redeems it.

    ``user_id`` is what the token actually binds to, not the email. Users here
    are keyed on (email, account_id), so an email alone does not identify a
    record; binding to the resolved user_id is what keeps a reset started from
    one application from touching that person's records in another. ``email``
    and ``account_id`` are carried alongside for logging and so a revoked
    account can be spotted without a second lookup.
    """

    token_hash: str
    user_id: str
    email: str
    account_id: str | None = None
    expires_at: datetime
    created_at: datetime
    used_at: datetime | None = None
    """Set when redeemed. A used token is kept rather than deleted so a second
    attempt can be told apart from an expired or forged one — the distinction
    is a better error message, not a security boundary."""


class ForgotPasswordRequest(BaseModel):
    """Start a reset.

    ``account_id`` is required, unlike a single-application reset flow, because
    one email may back several records with independent passwords. Without it
    the service would have to guess which application's password the caller
    means, and guessing wrong silently changes the password for an unrelated
    product.
    """

    email: str = Field(min_length=3, max_length=200)
    account_id: str = Field(min_length=1, max_length=200)


class ForgotPasswordResponse(BaseModel):
    """Always the same generic message, whether or not the email is known.

    This is the whole anti-enumeration property of the endpoint: an
    unauthenticated caller must not be able to use it to discover which
    addresses are registered, or which applications an address belongs to.
    """

    message: str
    debug_token: str | None = None
    """The raw token, returned ONLY when SMTP is unconfigured AND
    AUTH_EXPOSE_RESET_TOKEN is on — a development affordance so the flow can
    be exercised without a mail server. Never populated in production."""


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=8, max_length=512)
    new_password: str = Field(min_length=6, max_length=200)
    """Minimum matches RegisterRequest.password, so a reset cannot be used to
    set a password that registration would have rejected."""


class ResetPasswordResponse(BaseModel):
    message: str
