"""Auth domain configuration — JWT, password hashing, storage.

Env vars (no blanket prefix — names match the source implementation in the
calling application's ``backend/shared/auth`` + ``backend/services/auth``
verbatim, so an existing ``.env`` value copies straight across):

    AUTH_JWT_SECRET           — HMAC signing key (CHANGE in production)
    AUTH_JWT_ALGORITHM        — default HS256
    AUTH_ACCESS_TTL_MINUTES   — access-token lifetime in minutes, default 60
    AUTH_MONGO_URI            — falls back to bare MONGO_URI when unset
    AUTH_MONGO_DB_NAME        — falls back to bare MONGO_DB_NAME, default "app"

There is deliberately no admin-account setting. Administrator-ness is a
property of the app account a user's record belongs to
(``AppAccountRecord.app_type == AppType.ADMIN``, features/app_accounts.py),
so the service never has to be told which account that is — the admin console
is the only thing that names it, in its own configuration.

This module — and only this module — owns *what* the service authenticates
against (secret, token lifetime, storage). ``app/config.py``
owns *how the service is exposed* (host/port/CORS/docs), matching the split
already used by the sibling llm-gateway (``features/config.py`` vs
``app/config.py``) and knowledge-service (``rag/config.py`` vs ``app/config.py``).
"""
from __future__ import annotations

from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_ROOT = Path(__file__).parent.parent


class AuthSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ------------------------------------------------------------------- JWT
    jwt_secret: str = Field(default="dev-secret-change-me", validation_alias="AUTH_JWT_SECRET")
    jwt_algorithm: str = Field(default="HS256", validation_alias="AUTH_JWT_ALGORITHM")
    # The api-gateway caches introspection answers, so this value bounds how
    # long a logged-out or deleted user can still work downstream (that cache
    # TTL bounds it further). Kept short for that reason; there is no refresh
    # token, so raising it trades revocation latency for fewer re-logins.
    access_ttl_minutes: int = Field(default=60, validation_alias="AUTH_ACCESS_TTL_MINUTES")

    refresh_ttl_minutes: int = Field(
        default=10080, validation_alias="AUTH_REFRESH_TTL_MINUTES"
    )
    """How long after it was ISSUED a token may still be exchanged at
    ``POST /auth/refresh-token``. Seven days by default.

    This is the idle timeout, not the session length: each refresh mints a token
    with a fresh ``iat``, so an active user's window keeps sliding and only an
    absence longer than this forces a new sign-in. That is what lets
    ``access_ttl_minutes`` stay short — an hour of revocation latency — without
    signing people out every hour.

    It is also the bound on the one property refresh gives up. The endpoint
    accepts an expired token, so without this a token found in a log a year
    later would still be exchangeable. 0 disables refresh entirely: every
    exchange is refused and clients fall back to signing in again."""
    # This service is the trust root for end-user identity (sub, account_id),
    # and now the ONLY holder of the signing key: llm-gateway and
    # knowledge-service no longer validate tokens themselves — the api-gateway
    # asks this service (GET /auth/me) and injects verified identity headers.
    # iss/aud are still stamped for any future verifier.
    jwt_issuer: str = Field(default="auth-service", validation_alias="AUTH_JWT_ISSUER")
    jwt_audience_raw: str = Field(
        default="llm-gateway,knowledge-service", validation_alias="AUTH_JWT_AUDIENCE"
    )

    @property
    def jwt_audience(self) -> list[str]:
        return [a.strip() for a in self.jwt_audience_raw.split(",") if a.strip()]

    # ---------------------------------------------------------------- storage
    # Same shared cluster/db the calling application's monolith writes to by
    # default (during the transition period both can point at the same data);
    # override AUTH_MONGO_URI to point this service at its own cluster later.
    mongo_uri: str = Field(
        default="", validation_alias=AliasChoices("AUTH_MONGO_URI", "MONGO_URI")
    )
    mongo_db_name: str = Field(
        default="app", validation_alias=AliasChoices("AUTH_MONGO_DB_NAME", "MONGO_DB_NAME")
    )
    users_collection: str = "users"
    revoked_tokens_collection: str = "revoked_tokens"
    # Registered applications (see features/app_accounts.py) — the value an
    # application sends as LoginRequest.account_id, and the only scope a user
    # has.
    app_accounts_collection: str = "app_accounts"

    # ------------------------------------------------------------ password hash
    # bcrypt cost factor for new passwords. 12 is the bcrypt library's own
    # default (gensalt), so it is what an application storing bcrypt most
    # likely writes and imported hashes don't all look stale. Raising it
    # re-hashes each user on their next successful login
    # (features/security.py::needs_rehash) rather than at once.
    bcrypt_rounds: int = Field(default=12, validation_alias="AUTH_BCRYPT_ROUNDS")

    # ---------------------------------------------------------- password reset
    # Names are prefixed AUTH_ to match the rest of this file rather than the
    # conventional bare SMTP_* / PASSWORD_RESET_*, because those would collide
    # with any other service sharing an environment.
    password_reset_tokens_collection: str = "password_reset_tokens"
    password_reset_ttl_minutes: int = Field(
        default=30, validation_alias="AUTH_PASSWORD_RESET_TTL_MINUTES"
    )
    # Fallback link base, used ONLY when the app account being reset has no
    # app_url of its own. The per-account URL is the primary source (see
    # features/password_reset.py::_reset_link) — one auth-service serves
    # several frontends, so a single global URL cannot be right for all of
    # them. Leave empty and the flow refuses to send rather than mailing a
    # broken link.
    password_reset_url: str = Field(default="", validation_alias="AUTH_PASSWORD_RESET_URL")
    # Returns the raw token in the HTTP response when SMTP is unconfigured, so
    # the flow is testable without a mail server. NEVER enable in production:
    # it hands anyone who can guess an email a working reset link.
    expose_reset_token: bool = Field(
        default=False, validation_alias="AUTH_EXPOSE_RESET_TOKEN"
    )

    # --------------------------------------------------------------------- SMTP
    # Unset host or from-address means "not configured": messages are logged
    # instead of sent (features/email.py). That is a legitimate dev mode and a
    # silent production outage, so app/main.py warns about it at startup.
    smtp_host: str = Field(default="", validation_alias="AUTH_SMTP_HOST")
    smtp_port: int = Field(default=587, validation_alias="AUTH_SMTP_PORT")
    smtp_username: str = Field(default="", validation_alias="AUTH_SMTP_USERNAME")
    smtp_password: str = Field(default="", validation_alias="AUTH_SMTP_PASSWORD")
    smtp_from_email: str = Field(default="", validation_alias="AUTH_SMTP_FROM_EMAIL")
    smtp_from_name: str = Field(default="RichMinds", validation_alias="AUTH_SMTP_FROM_NAME")
    smtp_use_tls: bool = Field(default=True, validation_alias="AUTH_SMTP_USE_TLS")

    @property
    def jwt_secret_is_default(self) -> bool:
        return self.jwt_secret == "dev-secret-change-me"


auth_settings = AuthSettings()
