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
(not an administrator, or a disabled application), 409 (email taken), 422
(malformed email/password), and 404 (app account / user not found).

A user's only scope is the APP ACCOUNT — the application they signed in
through, identified by a UUID. Organizations no longer exist; the methods that
managed them are gone along with the routes they called.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15.0


@dataclass
class LoginAccount:
    """One app account the user may sign in through."""

    account_id: str
    name: str
    selected: bool = False
    """True on the account this session's token is scoped to."""


@dataclass
class UserPublic:
    """Mirror of ``features.schemas.UserPublic``.

    Account membership is carried ONLY by ``accounts``; there are no flat
    ``account_id``/``account_ids`` fields to disagree with it. Use
    ``account_id`` below to read the scoped account.
    """

    user_id: str
    email: str
    name: str
    accounts: list[LoginAccount] = field(default_factory=list)
    is_admin: bool = False
    created_at: str | None = None

    @property
    def account_id(self) -> str | None:
        """The account this session is scoped to — the selected entry.

        Downstream services (llm-gateway, knowledge-service) filter their data
        on this value; forward it as ``X-Account-ID`` on calls made on this
        user's behalf.
        """
        return next((a.account_id for a in self.accounts if a.selected), None)


@dataclass
class TokenResponse:
    access_token: str
    user: UserPublic
    token_type: str = "bearer"

    @property
    def account_id(self) -> str | None:
        """The scoped account, read off the user rather than repeated here —
        the envelope used to carry its own copy that could disagree."""
        return self.user.account_id


@dataclass
class AppAccountRecord:
    """A registered application. ``account_id`` is a UUID minted by the
    service, not a name the caller chooses."""

    account_id: str
    name: str
    description: str = ""
    app_type: str = "other"
    app_url: str = ""
    enabled: bool = True
    legacy_account_id: str = ""
    created_by: str = ""
    created_at: str = ""
    updated_at: str | None = None


class AuthServiceError(Exception):
    """Raised when the auth service returns a non-2xx response.

    ``status_code``: 401 bad credentials/invalid or revoked token, 403 not an
    administrator or a disabled application, 409 email already registered, 422
    malformed input, 404 app account/user not found.
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
        accounts=[LoginAccount(**a) for a in d.get("accounts", [])],
        is_admin=bool(d.get("is_admin", False)),
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
        self, email: str, name: str, password: str, account_id: str | None = None
    ) -> TokenResponse:
        """Register a new user. Pass ``account_id`` (an app account's UUID)
        to join that organization immediately; omit it to sign up as a guest
        and join one later via ``join_organization``."""
        payload: dict[str, Any] = {"email": email, "name": name, "password": password}
        if account_id is not None:
            payload["account_id"] = account_id
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
        )

    async def me(self, token: str) -> UserPublic:
        r = await self._client.get("/auth/me", headers=self._auth_headers(token))
        _raise_for_error(r)
        return _user_from_dict(r.json())

    async def logout(self, token: str) -> None:
        r = await self._client.post("/auth/logout", headers=self._auth_headers(token))
        _raise_for_error(r)

    # ------------------------------------------------ organization self-service

    async def select_account(self, token: str, account_id: str) -> TokenResponse:
        """Re-scope the caller's token to another of their own app accounts.

        The second half of a multi-account sign-in: the account is a token
        claim (downstream services scope data on it), so switching means a new
        token rather than a client-side flag. 403 if the user doesn't belong to
        that account or it is disabled.
        """
        r = await self._client.post(
            "/auth/me/account",
            json={"account_id": account_id},
            headers=self._auth_headers(token),
        )
        _raise_for_error(r)
        d = r.json()
        return TokenResponse(
            access_token=d["access_token"],
            token_type=d.get("token_type", "bearer"),
            user=_user_from_dict(d["user"]),
        )

    # ---------------------------------------------------------------- accounts
    # Registered applications. Administrators only.

    async def create_account(
        self,
        token: str,
        name: str,
        description: str = "",
        app_type: str = "other",
        app_url: str = "",
    ) -> AppAccountRecord:
        """Register an application; the service mints its ``account_id``.

        The returned UUID is the value that application must send as
        ``account_id`` at login — put it in that application's configuration.
        """
        r = await self._client.post(
            "/auth/accounts",
            json={
                "name": name,
                "description": description,
                "app_type": app_type,
                "app_url": app_url,
            },
            headers=self._auth_headers(token),
        )
        _raise_for_error(r)
        return AppAccountRecord(**r.json())

    async def list_accounts(self, token: str) -> list[AppAccountRecord]:
        r = await self._client.get("/auth/accounts", headers=self._auth_headers(token))
        _raise_for_error(r)
        return [AppAccountRecord(**a) for a in r.json()]

    async def get_account(self, token: str, account_id: str) -> AppAccountRecord:
        r = await self._client.get(
            f"/auth/accounts/{account_id}", headers=self._auth_headers(token)
        )
        _raise_for_error(r)
        return AppAccountRecord(**r.json())

    async def delete_account(self, token: str, account_id: str) -> None:
        r = await self._client.delete(
            f"/auth/accounts/{account_id}", headers=self._auth_headers(token)
        )
        _raise_for_error(r)

    async def list_users(self, token: str) -> list[UserPublic]:
        r = await self._client.get("/auth/users", headers=self._auth_headers(token))
        _raise_for_error(r)
        return [_user_from_dict(u) for u in r.json()]

    async def assign_user_accounts(
        self, token: str, user_id: str, account_id: str | None, account_ids: list[str] | None = None
    ) -> UserPublic:
        """Set which applications a user may sign in through (admin only).

        ``account_id`` is their default — what a login naming no account gets;
        ``account_ids`` are the extras that make an account picker appear.
        """
        r = await self._client.patch(
            f"/auth/users/{user_id}/accounts",
            json={"account_id": account_id, "account_ids": account_ids or []},
            headers=self._auth_headers(token),
        )
        _raise_for_error(r)
        return _user_from_dict(r.json())
