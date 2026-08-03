# Auth Service

A standalone authentication/authorization service: registration, login, JWT
issuance/validation, logout (token revocation), and organization admin
(platform-staff only) — over MongoDB, with an in-memory fallback.

Extracted from the calling application's `backend/services/auth` +
`backend/shared/auth` so any application — the monolith or otherwise — can
use it over HTTP instead of embedding the logic in its own codebase. It is a
1:1 feature port: every endpoint, every access rule, every status code the
source implementation had, this service has too. The calling application's
own copy of the code is **untouched**; this service is additive until a
follow-up migrates it to call this service instead (see
[Migrating the calling application](#migrating-the-calling-application) below).

## Quick start

```bash
cp .env.example .env
# Fill in AUTH_JWT_SECRET (required) and AUTH_MONGO_URI (recommended) at minimum.

pip install -r requirements-dev.txt
make dev          # http://localhost:8100/docs
```

Register, then use the token:

```bash
curl -X POST localhost:8100/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"a@b.com","name":"A B","password":"hunter22"}'
# -> {"access_token": "...", "user": {...}}

curl localhost:8100/auth/me -H "Authorization: Bearer <access_token>"
```

Or call it from Python with the bundled SDK:

```python
from sdk import AuthServiceClient

client = AuthServiceClient(base_url="http://localhost:8100")
token = await client.register(email="a@b.com", name="A B", password="hunter22")
profile = await client.me(token.access_token)
await client.logout(token.access_token)
await client.aclose()
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/auth/register` | none | Create a user, return a token |
| `POST` | `/auth/login` | none | Authenticate, return a token |
| `GET` | `/auth/me` | bearer token | Current user's profile |
| `POST` | `/auth/logout` | bearer token | Revoke the token used for this request |
| `POST` | `/auth/organizations` | platform staff | Create an organization |
| `GET` | `/auth/organizations` | platform staff | List every organization |
| `GET` | `/auth/users` | platform staff | List every user + their org assignment |
| `PATCH` | `/auth/users/{id}/organization` | platform staff | Assign a user to an organization |
| `GET` | `/health`, `/health/live`, `/health/ready` | none | Liveness/readiness (MongoDB reachability) |

"platform staff" means the caller's email is on the `AUTH_PORTLESS_EMAILS`
allowlist (see [Access model](#access-model)) — there are no other roles or
permissions in this system today.

## Access model

There is exactly one privilege bit: `is_portless` — is the caller's email on
the `AUTH_PORTLESS_EMAILS` allowlist? Platform staff get it automatically at
registration and can create organizations, assign users to them, and list
every user. Everyone else registers with **no organization** (`org_id` is
`None`) until a staff admin assigns one via `PATCH /auth/users/{id}/organization`
— an org-scoped caller with no `org_id` should be treated by *your*
service as "not yet provisioned," not "sees everything" (see
`features.dependencies.require_org_scope`).

This is intentionally minimal — no roles/permissions table, no refresh
tokens, no password reset or email verification, no rate-limiting on login,
no OAuth/social login. None of that exists in the source implementation
either; see `features/service.py`'s docstrings for what's deliberately out
of scope.

## Why a separate `features/` and `app/`

`features/` is the portable core — framework-light (FastAPI only for
`Depends()`/`HTTPException`, matching the source), no HTTP server concerns.
`app/` is the HTTP translation layer: routing, request-ID propagation,
structured logging, CORS. This mirrors the split already used by the sibling
[`llm-gateway`](../llm-gateway) (`features/` vs `app/`) and
[`knowledge-service`](../knowledge-service) (`rag/` vs `app/`) — an
application that "genuinely cannot take a network hop" can still import
`features/` directly:

```python
from features import register, login, init_repository

await init_repository()
token = await register(RegisterRequest(email=..., name=..., password=...))
```

## Storage

MongoDB, three collections: `users`, `organizations`, `revoked_tokens` (TTL-
indexed — a revoked token's entry expires at the same moment the token
itself would have anyway, so the blacklist never grows unbounded). All three
share one Motor connection (`features/mongo_connection.py`) — the source
implementation instead reused a separate, generic app-wide TTL cache just
for the revocation blacklist; this service folds that into the same
connection since it has nothing else to share a pool with.

`AUTH_MONGO_DB_NAME` defaults to `portless` — the same database the calling
application's monolith already writes `users`/`organizations` into — so this
service can read/write the *same* data during a transition period. Point
`AUTH_MONGO_URI` at a dedicated cluster once this service is the sole source
of truth. Leaving `AUTH_MONGO_URI` empty falls back to process-local
in-memory storage (fine for a quick local run; no persistence, no cross-
replica sharing).

## Configuring it

Two settings objects, same split as the sibling services:

- `features/config.py` (`AuthSettings`) — **what** the service authenticates
  against: `AUTH_JWT_SECRET`, `AUTH_JWT_ALGORITHM`, `AUTH_ACCESS_TTL_MINUTES`,
  `AUTH_MONGO_URI`, `AUTH_MONGO_DB_NAME`, `AUTH_PORTLESS_EMAILS`. These names
  match the source implementation verbatim, so an existing value copies
  straight across.
- `app/config.py` (`ServiceSettings`, prefix `AUTHSVC_`) — **how** the
  service is exposed: host/port, CORS, docs, log format.

**Set `AUTH_JWT_SECRET` before exposing this anywhere but localhost.** With
the built-in development default, anyone who has read this source can forge
a valid token for any user — `app/main.py` logs a loud warning (error, in
`AUTHSVC_ENVIRONMENT=production`) at startup if it's still the default.

## Migrating the calling application

Not done as part of this extraction — this service is additive. When ready:

1. Point the calling application's UI/backend at this service's `/auth/*`
   endpoints (or vendor `sdk/client.py`'s `AuthServiceClient`) instead of its
   own `services/auth`/`shared/auth`.
2. `agents/negotiation_agent/service.py` and
   `services/dealmaker/service.py::accept_pi` currently call
   `find_or_create_organization_for_deal` as a direct in-process import —
   ported here as `features.service.find_or_create_organization_for_deal`,
   but not yet exposed over HTTP (no route calls it). Add one if/when a
   remote caller needs it.
3. `shared/auth/middleware.py`'s per-path allowlist (e.g. "non-Portless users
   may reach `GET /deals`") is specific to the monolith's route layout, not
   ported here — that access rule belongs in whichever service owns
   `/deals`, checked against a token this service issued.
4. Once the calling application no longer imports `services/auth` or
   `shared/auth` directly, that code can be removed there — this service is
   the 1:1 replacement.

## Running the core in-process instead

If an application genuinely cannot take a network hop, `features/` is
importable directly — see [Why a separate `features/` and `app/`](#why-a-separate-features-and-app)
above. It still needs its own `AUTH_MONGO_URI` (or accepts the in-memory
fallback) and `AUTH_JWT_SECRET`.
