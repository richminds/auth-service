"""Service-level configuration for the Auth Service HTTP API.

Env-var prefix: ``AUTHSVC_``.

This is deliberately separate from ``features/config.py`` (no blanket
prefix — its var names match the source implementation's ``AUTH_*`` names
verbatim): that file owns *what the service authenticates against* (JWT
secret, storage, staff allowlist), this one owns *how the service is
exposed* (host/port/CORS/docs) — the same split used by the sibling
llm-gateway (``features/config.py`` vs ``app/config.py``) and
knowledge-service (``rag/config.py`` vs ``app/config.py``).
"""
from __future__ import annotations

import logging
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

_ROOT = Path(__file__).parent.parent


class ServiceSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AUTHSVC_",
        env_file=str(_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ------------------------------------------------------------- server
    host: str = "0.0.0.0"
    port: int = 8100
    root_path: str = ""          # set when behind a path-prefixing proxy
    log_level: str = "INFO"
    log_format: str = "json"     # "json" (default, log-aggregator friendly) | "text"
    environment: str = "development"  # development | staging | production

    # ------------------------------------------------------------- docs
    docs_enabled: bool = True    # set false in production if the API is public

    # ------------------------------------------------------------- CORS
    # Comma-separated origins, or "*" for any. Browsers only — service-to-service
    # callers are unaffected. Needed so a web UI can call /auth/login directly.
    cors_origins: str = ""

    # Vercel gives every deployment and every preview its own hostname
    # (account-management-<hash>-<scope>.vercel.app), so an exact allowlist
    # goes stale on each deploy and previews are broken by default. A regex
    # covers the whole family in one rule — anchor it to the projects you
    # actually own, never leave it open.
    cors_origin_regex: str = ""

    # ------------------------------------------------------------- misc
    request_id_header: str = "X-Request-ID"
    # Expose resolved (non-secret) configuration on GET /v1/config.
    expose_config_endpoint: bool = True

    # ---------------------------------------------------------- derived

    def parsed_cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in ("production", "prod")


service_settings = ServiceSettings()
