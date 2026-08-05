"""Auth Service — FastAPI application.

A standalone HTTP front end for the auth core in ``features/``. The calling
application currently implements this in-process as
``backend/services/auth`` + ``backend/shared/auth``; this service exposes
the identical behaviour over HTTP so callers can migrate one at a time.
That codebase's own copy is untouched — this service is additive.

Run it::

    uvicorn app.main:app --reload --port 8100
    # or: python run.py
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from features import __version__
from features.config import auth_settings
from features.repository import close_repository, init_repository
from features.service import ensure_guest_organization

from .config import service_settings
from .controllers import auth_controller, health_controller
from .errors import register_exception_handlers
from .logging_config import configure_logging
from .middleware.request_context import RequestContextMiddleware

logger = logging.getLogger(__name__)


def _warn_on_insecure_secret() -> None:
    """Refuse to let a default JWT secret go unnoticed on a real deployment.

    The default is fine for localhost and CI; on a deployed instance it means
    anyone who reads this source can forge a valid token for any user.
    """
    if not auth_settings.jwt_secret_is_default:
        return
    message = (
        "AUTH_JWT_SECRET is unset — using the built-in development default. "
        "Anyone who has read this source can forge a valid token. Set "
        "AUTH_JWT_SECRET before exposing this service."
    )
    if service_settings.is_production:
        logger.error("!!! %s", message)
    else:
        logger.warning(message)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging(service_settings.log_level, service_settings.log_format)
    _warn_on_insecure_secret()

    await init_repository()

    try:
        await ensure_guest_organization()
    except Exception as exc:  # noqa: BLE001 — best-effort; register() retries this per guest signup
        logger.warning("Auth Service: could not bootstrap the Guest organization at startup: %s", exc)

    logger.info(
        "Auth Service ready — mongo=%s db=%s",
        "configured" if auth_settings.mongo_uri else "in-memory (no AUTH_MONGO_URI)",
        auth_settings.mongo_db_name,
    )

    yield

    await close_repository()
    logger.info("Auth Service shut down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Auth Service",
        version=__version__,
        description=(
            "Registration, login, JWT issuance/validation, logout (token "
            "revocation), and organization admin (platform-staff only). "
            "Extracted from the calling application's backend/services/auth "
            "+ backend/shared/auth as a standalone, network-callable service."
        ),
        lifespan=lifespan,
        root_path=service_settings.root_path,
        docs_url="/docs" if service_settings.docs_enabled else None,
        redoc_url="/redoc" if service_settings.docs_enabled else None,
        openapi_url="/openapi.json" if service_settings.docs_enabled else None,
    )

    app.add_middleware(RequestContextMiddleware)

    origins = service_settings.parsed_cors_origins()
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    register_exception_handlers(app)

    app.include_router(health_controller.router)
    app.include_router(auth_controller.router)

    @app.get("/", tags=["health"], summary="Service banner")
    async def root() -> dict:
        return {
            "service": "auth-service",
            "version": __version__,
            "docs": "/docs" if service_settings.docs_enabled else None,
            "health": "/health",
        }

    return app


app = create_app()
