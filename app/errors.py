"""Domain exception → HTTP status mapping.

The core raises domain exceptions; this is the only place that decides what
each one means over HTTP. Keeping the mapping here lets ``features/`` stay
framework-free and importable in-process.

    InvalidEmailError         → 422  malformed email at registration
    EmailTakenError           → 409  email already registered
    InvalidCredentialsError   → 401  bad email/password at login
    UserNotFoundError         → 404  assigning an org to a nonexistent user
    AccountNotAllowedError    → 403  switching to an app account the user doesn't belong to
    AppAccountExistsError       → 409  registering an account_id that is taken
    AppAccountNotFoundError     → 404  reading/updating/deleting an unknown account_id
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from features.app_accounts import (
    AdminAccountClosedError,
    AppAccountDisabledError,
    AppAccountExistsError,
    AppAccountNotFoundError,
)
from features.service import (
    AccountNotAllowedError,
    EmailTakenError,
    InvalidCredentialsError,
    InvalidEmailError,
    UserNotFoundError,
)

logger = logging.getLogger(__name__)


def _problem(request: Request, status: int, code: str, message: str, **extra: Any) -> JSONResponse:
    body = {
        "error": {
            "code": code,
            "message": message,
            "request_id": getattr(request.state, "request_id", ""),
            **extra,
        }
    }
    return JSONResponse(status_code=status, content=body)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(InvalidEmailError)
    async def _invalid_email(request: Request, exc: InvalidEmailError) -> JSONResponse:
        return _problem(request, 422, "invalid_email", str(exc))

    @app.exception_handler(EmailTakenError)
    async def _email_taken(request: Request, exc: EmailTakenError) -> JSONResponse:
        return _problem(request, 409, "email_taken", str(exc))

    @app.exception_handler(InvalidCredentialsError)
    async def _invalid_credentials(request: Request, exc: InvalidCredentialsError) -> JSONResponse:
        return _problem(request, 401, "invalid_credentials", str(exc))

    @app.exception_handler(UserNotFoundError)
    async def _user_not_found(request: Request, exc: UserNotFoundError) -> JSONResponse:
        return _problem(request, 404, "user_not_found", str(exc))

    @app.exception_handler(AccountNotAllowedError)
    async def _account_not_allowed(request: Request, exc: AccountNotAllowedError) -> JSONResponse:
        return _problem(request, 403, "account_not_allowed", str(exc))

    @app.exception_handler(AppAccountDisabledError)
    async def _app_account_disabled(
        request: Request, exc: AppAccountDisabledError
    ) -> JSONResponse:
        return _problem(request, 403, "app_account_disabled", str(exc))

    @app.exception_handler(AdminAccountClosedError)
    async def _admin_account_closed(
        request: Request, exc: AdminAccountClosedError
    ) -> JSONResponse:
        return _problem(request, 403, "admin_account_closed", str(exc))

    @app.exception_handler(AppAccountExistsError)
    async def _app_account_exists(request: Request, exc: AppAccountExistsError) -> JSONResponse:
        return _problem(request, 409, "app_account_exists", str(exc))

    @app.exception_handler(AppAccountNotFoundError)
    async def _app_account_not_found(
        request: Request, exc: AppAccountNotFoundError
    ) -> JSONResponse:
        return _problem(request, 404, "app_account_not_found", str(exc))
