"""Auth Service core — registration, login, JWT issuance/validation, app accounts.

Portable core, importable in-process or served over HTTP (see ``app/``).

A user's only scope is the APP ACCOUNT they belong to (``account_id``, plus
``account_ids`` for anyone who works across several). There is no organization
or tenant concept: downstream services filter their data on the account, and
administration is gated on membership of the configured admin app account.

Quick start::

    from features import register, login, get_current_user

Model names, secrets and storage are declared in exactly one place
(``config.py``).
"""
from .app_accounts import (
    AppAccountExistsError,
    AppAccountNotFoundError,
    create_app_account,
    delete_app_account,
    get_app_account,
    list_app_accounts,
    update_app_account,
)
from .blacklist import is_token_revoked, revoke_token
from .config import AuthSettings, auth_settings
from .dependencies import AuthUser, get_current_user, require_admin
from .repository import (
    InMemoryRevocationRepository,
    InMemoryUserRepository,
    RevocationRepository,
    UserRepository,
    close_repository,
    get_repository,
    get_revocation_repository,
    init_repository,
)
from .schemas import (
    AppAccountRecord,
    AssignUserAccountsRequest,
    CreateAppAccountRequest,
    LoginAccount,
    LoginRequest,
    RegisterRequest,
    SelectAccountRequest,
    TokenResponse,
    UpdateAppAccountRequest,
    UserPublic,
    UserRecord,
)
from .security import create_access_token, decode_token, hash_password, verify_password
from .service import (
    AccountNotAllowedError,
    EmailTakenError,
    InvalidCredentialsError,
    InvalidEmailError,
    UserNotFoundError,
    assign_user_accounts,
    effective_account_ids,
    get_user,
    list_users,
    login,
    logout,
    register,
    select_account,
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
    "require_admin",
    # schemas
    "UserRecord",
    "UserPublic",
    "RegisterRequest",
    "LoginRequest",
    "LoginAccount",
    "SelectAccountRequest",
    "AssignUserAccountsRequest",
    "TokenResponse",
    # app accounts (registered applications — a user's only scope)
    "AppAccountRecord",
    "CreateAppAccountRequest",
    "UpdateAppAccountRequest",
    "create_app_account",
    "list_app_accounts",
    "get_app_account",
    "update_app_account",
    "delete_app_account",
    "AppAccountExistsError",
    "AppAccountNotFoundError",
    # repository
    "UserRepository",
    "RevocationRepository",
    "InMemoryUserRepository",
    "InMemoryRevocationRepository",
    "get_repository",
    "get_revocation_repository",
    "init_repository",
    "close_repository",
    # service
    "register",
    "login",
    "logout",
    "select_account",
    "get_user",
    "list_users",
    "assign_user_accounts",
    "effective_account_ids",
    "EmailTakenError",
    "InvalidEmailError",
    "InvalidCredentialsError",
    "AccountNotAllowedError",
    "UserNotFoundError",
]
