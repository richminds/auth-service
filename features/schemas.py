"""Request/response models for the Auth service."""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

from .organization import is_portless_user


class UserRecord(BaseModel):
    """Stored user document (password is hashed, never returned).

    Two independent groupings, deliberately not the same field:

    ``account_id`` ties the user to the APPLICATION they belong to — an
    app account (see app_accounts.py). This is what makes someone an admin of
    this service: membership of the configured admin app account
    (``AUTH_ADMIN_ACCOUNT_ID``) is the only thing ``require_admin`` checks.

    ``org_id`` ties the user to their ORGANIZATION (tenant) within whichever
    application they use. Every org-scoped data query filters on this value.
    """

    user_id: str
    email: str
    name: str
    password_hash: str
    account_id: str | None = None
    org_id: str | None = None
    created_at: datetime


class UserPublic(BaseModel):
    """User info safe to return to clients / embed in tokens."""

    user_id: str
    email: str
    name: str
    account_id: str | None = None
    org_id: str | None = None
    is_admin: bool = False
    """True when the user belongs to the configured admin app account — the
    only gate on the account-administration endpoints. Independent of
    is_portless below."""
    is_portless: bool = False
    """Legacy platform-staff flag from the AUTH_PORTLESS_EMAILS allowlist.
    Still emitted because knowledge-service reads this claim to bypass
    per-org filtering; it plays no part in account administration."""
    created_at: datetime | None = None

    @classmethod
    def from_record(cls, r: UserRecord) -> "UserPublic":
        from .config import auth_settings

        return cls(
            user_id=r.user_id,
            email=r.email,
            name=r.name,
            account_id=r.account_id,
            org_id=r.org_id,
            is_admin=bool(r.account_id) and r.account_id == auth_settings.admin_account_id,
            is_portless=is_portless_user(r.email),
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
    org_id: str | None = Field(default=None, max_length=200)
    """Optional at signup. If given, must reference an existing organization
    (see service.register) and the account is created as a member of it.
    If omitted, the account is created as a guest (org_id stays None) —
    it can join one later via POST /auth/me/organization."""


class LoginRequest(BaseModel):
    email: str
    password: str
    account_id: str | None = Field(default=None, max_length=200)
    """Which application this login is for (an app account's account_id).
    The account must be enabled and the user must belong to it — see
    app/controllers/auth_controller.py::login and features/service.py::login.
    Still optional so applications that predate app accounts keep working;
    omitting it skips the membership check."""


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic
    account_id: str | None = None
    """The application the user belongs to. Callers that go on to call
    llm-gateway/knowledge-service on this user's behalf can forward it as
    their X-Account-ID header."""


# ---------------------------------------------------------------------------
# Organizations (platform-staff admin only — see require_portless)
# ---------------------------------------------------------------------------

class OrganizationRecord(BaseModel):
    org_id: str
    name: str
    created_by: str
    """user_id of the staff member who created this organization, or a
    "system:*" marker when created automatically (see service.py::
    find_or_create_organization_for_deal)."""
    known_emails: list[str] = Field(default_factory=list)
    """Communication emails associated with this organization (lowercased,
    deduplicated). Lets a staff admin match a new signup's email to the right
    organization in the assign-user flow."""
    created_at: datetime


class CreateOrganizationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class RenameOrganizationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)


# ---------------------------------------------------------------------------
# App accounts — the applications registered against this service.
#
# NOT organizations. An OrganizationRecord is a tenant that *users* belong to
# (org_id on UserRecord, used for per-tenant data scoping). An AppAccountRecord
# is an *application* that authenticates against this service — the value it
# sends as LoginRequest.account_id when its users sign in. They live in
# separate collections and neither one implies the other.
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
    LoginRequest.account_id (e.g. "richminds"). Unlike org_id this is never
    generated — the application already knows the value it will send, so
    letting the service mint one would guarantee a mismatch."""
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


class AssignUserOrgRequest(BaseModel):
    org_id: str
