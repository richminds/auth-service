"""Domain exception → HTTP status mapping.

The core raises domain exceptions; this is the only place that decides what
each one means over HTTP. Keeping the mapping here lets ``features/`` stay
framework-free and importable in-process.

    InvalidEmailError         → 422  malformed email at registration
    EmailTakenError           → 409  email already registered
    InvalidCredentialsError   → 401  bad email/password at login
    OrganizationNotFoundError → 404  assigning a user to a nonexistent org
    UserNotFoundError         → 404  assigning an org to a nonexistent user
    AlreadyAssignedError      → 409  self-service join by an already-assigned user
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from features.service import (
    AlreadyAssignedError,
    EmailTakenError,
    InvalidCredentialsError,
    InvalidEmailError,
    OrganizationNotFoundError,
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

    @app.exception_handler(OrganizationNotFoundError)
    async def _org_not_found(request: Request, exc: OrganizationNotFoundError) -> JSONResponse:
        return _problem(request, 404, "organization_not_found", str(exc))

    @app.exception_handler(UserNotFoundError)
    async def _user_not_found(request: Request, exc: UserNotFoundError) -> JSONResponse:
        return _problem(request, 404, "user_not_found", str(exc))

    @app.exception_handler(AlreadyAssignedError)
    async def _already_assigned(request: Request, exc: AlreadyAssignedError) -> JSONResponse:
        return _problem(request, 409, "already_assigned", str(exc))
