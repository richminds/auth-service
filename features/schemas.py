"""Request/response models for the Auth service."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from .organization import is_portless_user


class UserRecord(BaseModel):
    """Stored user document (password is hashed, never returned).

    org_id ties the user to their organization. It starts unset (None) at
    signup — a platform-staff admin assigns it via the Organizations admin
    endpoints (see organization.py, service.py::assign_user_organization).
    Every org-scoped data query filters on this value, except for platform
    staff (see is_portless_user), who see data across every organization
    regardless of their own org_id.
    """

    user_id: str
    email: str
    name: str
    password_hash: str
    org_id: str | None = None
    created_at: datetime


class UserPublic(BaseModel):
    """User info safe to return to clients / embed in tokens."""

    user_id: str
    email: str
    name: str
    org_id: str | None = None
    is_portless: bool = False
    created_at: datetime | None = None

    @classmethod
    def from_record(cls, r: UserRecord) -> "UserPublic":
        return cls(
            user_id=r.user_id,
            email=r.email,
            name=r.name,
            org_id=r.org_id,
            is_portless=is_portless_user(r.email),
            created_at=r.created_at,
        )


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=200)
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=6, max_length=200)


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic


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


class AssignUserOrgRequest(BaseModel):
    org_id: str
