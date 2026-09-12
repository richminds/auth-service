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

from .config import service_settings
from .controllers import auth_controller, health_controller
from .errors import register_exception_handlers
from features.email import smtp_configured

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


def _warn_on_unconfigured_smtp() -> None:
    """Password reset silently does nothing without SMTP.

    POST /auth/forgot-password always answers 200 with the same message so it
    can't be used to enumerate addresses — which means an unconfigured mailer
    is indistinguishable, to the user, from a working one. The only place that
    difference can surface is here.
    """
    if smtp_configured():
        return
    message = (
        "AUTH_SMTP_HOST/AUTH_SMTP_FROM_EMAIL are unset — password-reset emails "
        "will be logged instead of sent, and POST /auth/forgot-password will "
        "still answer 200. Nobody can complete a reset."
    )
    if service_settings.is_production:
        logger.error("!!! %s", message)
    else:
        logger.warning(message)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging(service_settings.log_level, service_settings.log_format)
    _warn_on_insecure_secret()
    _warn_on_unconfigured_smtp()

    await init_repository()

    # NOTHING is created here. Starting this service does not bring any app
    # account into existence — not the admin one, not a guest one. An account
    # is a deliberate act by an operator or an administrator, never a side
    # effect of a process starting.
    #
    # Why that is worth the inconvenience: a bootstrap runs on EVERY cold start,
    # so it silently recreates whatever an operator deleted, and it did — a
    # guest account removed on purpose came back the moment the database became
    # reachable again. It also writes records nobody asked for, attributed to
    # "system:bootstrap", into a database it has only just connected to.
    #
    # The consequence is a real chicken-and-egg, stated plainly rather than
    # worked around: registering the first administrator needs the admin
    # account to exist, and creating an account through POST /auth/accounts
    # needs an administrator. A fresh deployment therefore CANNOT bootstrap
    # itself through the API, by design. Break the cycle out of band, once:
    # an operator calls features.app_accounts.ensure_admin_account() against
    # the deployment's database (the README shows the snippet). It mints the
    # admin account and returns its ID, which goes into the admin console's
    # VITE_ADMIN_ACCOUNT_ID; the first administrator then self-registers into
    # it. Everything after that is ordinary API work.

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
            "revocation), and app-account administration (administrators only). "
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
    origin_regex = service_settings.cors_origin_regex.strip()
    if origins or origin_regex:
        if "*" in origins:
            # Browsers reject a wildcard origin on a credentialed request, and
            # every call here carries an Authorization header — so "*" doesn't
            # loosen anything, it just silently blocks everything.
            logger.warning(
                "AUTHSVC_CORS_ORIGINS contains '*', which browsers refuse on "
                "credentialed requests — list real origins, or use "
                "AUTHSVC_CORS_ORIGIN_REGEX."
            )
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_origin_regex=origin_regex or None,
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
