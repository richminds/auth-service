"""HTTP client for the Auth Service.

Drop this into any application that should authenticate users through this
service rather than embedding the auth logic directly.

Usage::

    from sdk import AuthServiceClient

    client = AuthServiceClient(base_url="https://auth-service.internal")
    token = await client.register(email="a@b.com", name="A B", password="hunter22")
    token = await client.login(email="a@b.com", password="hunter22")
    profile = await client.me(token.access_token)
    await client.logout(token.access_token)
    await client.aclose()

Every non-2xx response raises ``AuthServiceError`` carrying the HTTP status
code, so a caller can distinguish 401 (bad credentials / invalid token), 403
(not platform staff), 409 (email taken), 422 (malformed email/password), and
404 (organization/user not found).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15.0


@dataclass
class UserPublic:
    """Mirror of ``features.schemas.UserPublic``."""

    user_id: str
    email: str
    name: str
    org_id: str | None = None
    is_portless: bool = False
    created_at: str | None = None


@dataclass
class TokenResponse:
    access_token: str
    user: UserPublic
    token_type: str = "bearer"
    account_id: str | None = None
    """The application the user belongs to. Forward it as X-Account-ID on
    later llm-gateway/knowledge-service calls made on this user's behalf."""


@dataclass
class OrganizationRecord:
    org_id: str
    name: str
    created_by: str
    created_at: str
    known_emails: list[str] = field(default_factory=list)


class AuthServiceError(Exception):
    """Raised when the auth service returns a non-2xx response.

    ``status_code``: 401 bad credentials/invalid or revoked token, 403 not
    platform staff, 409 email already registered or self-join by an
    already-assigned user, 422 malformed input, 404 organization/user not
    found.
    """

    def __init__(self, status_code: int, message: str, code: str = "") -> None:
        self.status_code = status_code
        self.code = code
        super().__init__(f"[{status_code}] {code or 'error'}: {message}")


def _user_from_dict(d: dict[str, Any]) -> UserPublic:
    return UserPublic(
        user_id=d["user_id"],
        email=d["email"],
        name=d["name"],
        org_id=d.get("org_id"),
        is_portless=d.get("is_portless", False),
        created_at=d.get("created_at"),
    )


def _raise_for_error(response: httpx.Response) -> None:
    if response.is_success:
        return
    try:
        body = response.json()
        detail = body.get("error", {})
        message = detail.get("message") or body.get("detail") or response.text
        code = detail.get("code", "")
    except Exception:  # noqa: BLE001
        message, code = response.text, ""
    raise AuthServiceError(response.status_code, message, code)


class AuthServiceClient:
    """Async HTTP client for the Auth Service. Build once per process — it
    owns a connection pool."""

    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    # ------------------------------------------------------------- identity

    async def register(
        self, email: str, name: str, password: str, org_id: str | None = None
    ) -> TokenResponse:
        """Register a new user. Pass ``org_id`` (from ``register_organization``)
        to join that organization immediately; omit it to sign up as a guest
        and join one later via ``join_organization``."""
        payload: dict[str, Any] = {"email": email, "name": name, "password": password}
        if org_id is not None:
            payload["org_id"] = org_id
        r = await self._client.post("/auth/register", json=payload)
        _raise_for_error(r)
        d = r.json()
        return TokenResponse(access_token=d["access_token"], user=_user_from_dict(d["user"]))

    async def login(
        self, email: str, password: str, account_id: str | None = None
    ) -> TokenResponse:
        """Log in. Pass ``account_id`` to name the application this login is
        for — it must be enabled and the user must belong to it (see
        features/app_accounts.py in this service)."""
        payload: dict[str, Any] = {"email": email, "password": password}
        if account_id is not None:
            payload["account_id"] = account_id
        r = await self._client.post("/auth/login", json=payload)
        _raise_for_error(r)
        d = r.json()
        return TokenResponse(
            access_token=d["access_token"],
            user=_user_from_dict(d["user"]),
            account_id=d.get("account_id"),
        )

    async def me(self, token: str) -> UserPublic:
        r = await self._client.get("/auth/me", headers=self._auth_headers(token))
        _raise_for_error(r)
        return _user_from_dict(r.json())

    async def logout(self, token: str) -> None:
        r = await self._client.post("/auth/logout", headers=self._auth_headers(token))
        _raise_for_error(r)

    # ------------------------------------------------ organization self-service

    async def register_organization(self, name: str) -> OrganizationRecord:
        """Self-serve organization creation — no token required. Returns the
        new org_id to hand out at signup or pass to ``join_organization``."""
        r = await self._client.post("/auth/organizations/register", json={"name": name})
        _raise_for_error(r)
        return OrganizationRecord(**r.json())

    async def join_organization(self, token: str, org_id: str) -> TokenResponse:
        """Attach the caller's own (still-guest) account to an organization.

        Only succeeds while the account is unassigned — raises
        ``AuthServiceError(409)`` once it already belongs to one. Returns a
        fresh token carrying the new org_id claim.
        """
        r = await self._client.post(
            "/auth/me/organization", json={"org_id": org_id}, headers=self._auth_headers(token)
        )
        _raise_for_error(r)
        d = r.json()
        return TokenResponse(access_token=d["access_token"], user=_user_from_dict(d["user"]))

    # -------------------------------------------------- organization admin
    # Platform-staff only (403 otherwise) — see features/organization.py.

    async def create_organization(self, token: str, name: str) -> OrganizationRecord:
        r = await self._client.post(
            "/auth/organizations", json={"name": name}, headers=self._auth_headers(token)
        )
        _raise_for_error(r)
        return OrganizationRecord(**r.json())

    async def rename_organization(self, token: str, org_id: str, name: str) -> OrganizationRecord:
        r = await self._client.patch(
            f"/auth/organizations/{org_id}", json={"name": name}, headers=self._auth_headers(token)
        )
        _raise_for_error(r)
        return OrganizationRecord(**r.json())

    async def delete_organization(self, token: str, org_id: str) -> None:
        """Raises AuthServiceError(409) if the organization still has member
        users, or (403) for the reserved Guest/Portless organizations."""
        r = await self._client.delete(
            f"/auth/organizations/{org_id}", headers=self._auth_headers(token)
        )
        _raise_for_error(r)

    async def list_organizations(self, token: str) -> list[OrganizationRecord]:
        r = await self._client.get("/auth/organizations", headers=self._auth_headers(token))
        _raise_for_error(r)
        return [OrganizationRecord(**o) for o in r.json()]

    async def list_users(self, token: str) -> list[UserPublic]:
        r = await self._client.get("/auth/users", headers=self._auth_headers(token))
        _raise_for_error(r)
        return [_user_from_dict(u) for u in r.json()]

    async def assign_user_organization(self, token: str, user_id: str, org_id: str) -> UserPublic:
        r = await self._client.patch(
            f"/auth/users/{user_id}/organization",
            json={"org_id": org_id},
            headers=self._auth_headers(token),
        )
        _raise_for_error(r)
        return _user_from_dict(r.json())
