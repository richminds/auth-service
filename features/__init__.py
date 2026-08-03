"""Auth Service core — registration, login, JWT issuance/validation, organizations.

Portable core, importable in-process or served over HTTP (see ``app/``).
Extracted from the calling application's ``backend/services/auth`` +
``backend/shared/auth`` — a 1:1 feature port; that codebase's own copy is
untouched.

Quick start::

    from features import register, login, get_current_user

Model names, secrets and storage are declared in exactly one place
(``config.py``).
"""
from .blacklist import is_token_revoked, revoke_token
from .config import AuthSettings, auth_settings
from .dependencies import AuthUser, get_current_user, require_org_scope, require_portless
from .organization import PORTLESS_ORG_ID, is_portless_user
from .repository import (
    InMemoryOrganizationRepository,
    InMemoryRevocationRepository,
    InMemoryUserRepository,
    OrganizationRepository,
    RevocationRepository,
    UserRepository,
    close_repository,
    get_org_repository,
    get_repository,
    get_revocation_repository,
    init_repository,
)
from .schemas import (
    AssignUserOrgRequest,
    CreateOrganizationRequest,
    LoginRequest,
    OrganizationRecord,
    RegisterRequest,
    TokenResponse,
    UserPublic,
    UserRecord,
)
from .security import create_access_token, decode_token, hash_password, verify_password
from .service import (
    EmailTakenError,
    InvalidCredentialsError,
    InvalidEmailError,
    OrganizationNotFoundError,
    UserNotFoundError,
    assign_user_organization,
    create_organization,
    find_or_create_organization_for_deal,
    get_user,
    list_organizations,
    list_users,
    login,
    logout,
    register,
)

__version__ = "1.0.0"

__all__ = [
    "__version__",
    # config
    "AuthSettings",
    "auth_settings",
    # security
    "create_access_token",
    "decode_token",
    "hash_password",
    "verify_password",
    # blacklist
    "revoke_token",
    "is_token_revoked",
    # dependencies
    "AuthUser",
    "get_current_user",
    "require_org_scope",
    "require_portless",
    # organization
    "PORTLESS_ORG_ID",
    "is_portless_user",
    # schemas
    "UserRecord",
    "UserPublic",
    "RegisterRequest",
    "LoginRequest",
    "TokenResponse",
    "OrganizationRecord",
    "CreateOrganizationRequest",
    "AssignUserOrgRequest",
    # repository
    "UserRepository",
    "OrganizationRepository",
    "RevocationRepository",
    "InMemoryUserRepository",
    "InMemoryOrganizationRepository",
    "InMemoryRevocationRepository",
    "get_repository",
    "get_org_repository",
    "get_revocation_repository",
    "init_repository",
    "close_repository",
    # service
    "register",
    "login",
    "logout",
    "get_user",
    "create_organization",
    "list_organizations",
    "list_users",
    "assign_user_organization",
    "find_or_create_organization_for_deal",
    "EmailTakenError",
    "InvalidEmailError",
    "InvalidCredentialsError",
    "OrganizationNotFoundError",
    "UserNotFoundError",
]
