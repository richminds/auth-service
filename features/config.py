"""Auth domain configuration — JWT, password hashing, storage, Portless allowlist.

Env vars (no blanket prefix — names match the source implementation in the
calling application's ``backend/shared/auth`` + ``backend/services/auth``
verbatim, so an existing ``.env`` value copies straight across):

    AUTH_JWT_SECRET           — HMAC signing key (CHANGE in production)
    AUTH_JWT_ALGORITHM        — default HS256
    AUTH_ACCESS_TTL_MINUTES   — access-token lifetime in minutes, default 720 (12h)
    AUTH_MONGO_URI            — falls back to bare MONGO_URI when unset
    AUTH_MONGO_DB_NAME        — falls back to bare MONGO_DB_NAME, default "portless"
    AUTH_PORTLESS_EMAILS      — comma-separated allowlist of platform-staff emails

This module — and only this module — owns *what* the service authenticates
against (secret, token lifetime, storage, staff allowlist). ``app/config.py``
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
    access_ttl_minutes: int = Field(default=720, validation_alias="AUTH_ACCESS_TTL_MINUTES")
    # This service is the trust root for end-user identity (sub, org_id, ...) —
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
        default="portless", validation_alias=AliasChoices("AUTH_MONGO_DB_NAME", "MONGO_DB_NAME")
    )
    users_collection: str = "users"
    organizations_collection: str = "organizations"
    revoked_tokens_collection: str = "revoked_tokens"

    # --------------------------------------------------------------- allowlist
    # Explicit allowlist of platform-staff emails (comma-separated). There is
    # no domain matching or other derivation — an email either is or isn't on
    # this list. See features/organization.py::is_portless_user.
    portless_emails_raw: str = Field(
        default="", validation_alias=AliasChoices("AUTH_PORTLESS_EMAILS", "PORTLESS_EMAILS")
    )

    @property
    def portless_emails(self) -> set[str]:
        return {e.strip().lower() for e in self.portless_emails_raw.split(",") if e.strip()}

    @property
    def jwt_secret_is_default(self) -> bool:
        return self.jwt_secret == "dev-secret-change-me"


auth_settings = AuthSettings()
