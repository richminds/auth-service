"""Auth domain configuration — JWT, password hashing, storage, admin account.

Env vars (no blanket prefix — names match the source implementation in the
calling application's ``backend/shared/auth`` + ``backend/services/auth``
verbatim, so an existing ``.env`` value copies straight across):

    AUTH_JWT_SECRET           — HMAC signing key (CHANGE in production)
    AUTH_JWT_ALGORITHM        — default HS256
    AUTH_ACCESS_TTL_MINUTES   — access-token lifetime in minutes, default 60
    AUTH_MONGO_URI            — falls back to bare MONGO_URI when unset
    AUTH_MONGO_DB_NAME        — falls back to bare MONGO_DB_NAME, default "app"

This module — and only this module — owns *what* the service authenticates
against (secret, token lifetime, storage, admin account). ``app/config.py``
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
    # Downstream services verify tokens locally and never see this service's
    # revocation list, so this value IS the window in which a logged-out or
    # deleted user still works against them (see the README's token lifecycle
    # section). Kept short for that reason; there is no refresh token, so
    # raising it trades revocation latency for fewer re-logins.
    access_ttl_minutes: int = Field(default=60, validation_alias="AUTH_ACCESS_TTL_MINUTES")
    # This service is the trust root for end-user identity (sub, account_id) —
    # llm-gateway and knowledge-service each validate tokens minted here rather
    # than issuing their own, so `iss` must equal their configured
    # LLM_JWT_ISSUER/RAG_JWT_ISSUER and `aud` must include their configured
    # LLM_JWT_AUDIENCE/RAG_JWT_AUDIENCE. That only works if AUTH_JWT_SECRET
    # equals LLM_JWT_SECRET and RAG_JWT_SECRET (HS256 is symmetric) — see each
    # service's .env.example.
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
    # bcrypt cost factor for new passwords. 12 is the current default and
    # matches what makemerich-backend writes, so imported hashes don't all
    # look stale. Raising it re-hashes each user on their next successful
    # login (features/security.py::needs_rehash) rather than at once.
    bcrypt_rounds: int = Field(default=12, validation_alias="AUTH_BCRYPT_ROUNDS")

    # ------------------------------------------------------------------- admin
    # Administering this service (app accounts) is gated on membership of ONE
    # app account — the RichMinds admin application. A user whose
    # UserRecord.account_id equals this value is an admin; nobody else is.
    admin_account_id: str = Field(default="richminds", validation_alias="AUTH_ADMIN_ACCOUNT_ID")

    @property
    def jwt_secret_is_default(self) -> bool:
        return self.jwt_secret == "dev-secret-change-me"


auth_settings = AuthSettings()
