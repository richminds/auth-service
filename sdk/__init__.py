"""Client SDK for the Auth Service HTTP API.

Copy this package (or pip-install this repo) into any application that
should authenticate users through this service instead of embedding auth
logic directly.
"""
from .client import (
    AppAccountRecord,
    AuthServiceClient,
    AuthServiceError,
    LoginAccount,
    TokenResponse,
    UserPublic,
)

__all__ = [
    "AuthServiceClient",
    "AuthServiceError",
    "TokenResponse",
    "UserPublic",
    "LoginAccount",
    "AppAccountRecord",
]
