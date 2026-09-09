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
| `POST` | `/auth/login` | none | Authenticate, return a token + the `accounts` the user may work under (see [One login for every application](#one-login-for-every-application)) |
| `POST` | `/auth/me/account` | bearer token | Re-issue the token scoped to another [app account](#app-accounts-vs-organizations) the caller belongs to |
| `GET` | `/auth/me` | bearer token | Current user's profile |
| `POST` | `/auth/logout` | bearer token | Revoke the token used for this request |
| `POST` | `/auth/organizations` | platform staff | Create an organization |
| `GET` | `/auth/organizations` | platform staff | List every organization |
| `GET` | `/auth/users` | platform staff | List every user + their org assignment |
| `PATCH` | `/auth/users/{id}/organization` | platform staff | Assign a user to an organization |
| `PATCH` | `/auth/users/{id}/accounts` | platform staff | Set which applications a user may sign in through ([app accounts](#app-accounts-vs-organizations)) |
| `POST` | `/auth/accounts` | **admin** | Register an application ([app account](#app-accounts-vs-organizations)) |
| `GET` | `/auth/accounts` | **admin** | List registered applications |
| `GET` | `/auth/accounts/{id}` | **admin** | One registered application |
| `PATCH` | `/auth/accounts/{id}` | **admin** | Update name/description/type/url/enabled |
| `DELETE` | `/auth/accounts/{id}` | **admin** | Deregister an application |
| `GET` | `/health`, `/health/live`, `/health/ready` | none | Liveness/readiness (MongoDB reachability) |

Two independent gates: **"admin"** means the caller belongs to the admin app
account (see [Administration](#administration)); **"platform staff"** means
their email is on the legacy `AUTH_PORTLESS_EMAILS` allowlist (see
[Access model](#access-model)). Neither implies the other.

## App accounts vs organizations

Two different things, two different collections. Conflating them is the easiest
mistake to make here, so:

| | **App account** (`app_accounts`) | **Organization** (`organizations`) |
|---|---|---|
| What it is | An **application** registered against this service | A **tenant** that users belong to |
| Identified by | `account_id`, chosen by the caller (e.g. `richminds`) | `org_id`, generated (`ORG-…`) |
| Where it shows up | `LoginRequest.account_id` — picks which user store a login checks | `org_id` on `UserRecord` and in token claims — what per-tenant data scoping filters on |
| Managed by | `/auth/accounts` + [account-management-ui](../account-management-ui) | `/auth/organizations` |

Neither implies the other: one application can serve many organizations, and an
organization means nothing to an application that has no tenants.

Registering an app account is what lets its users name it at login (see
below). `PATCH … {"enabled": false}` takes an application out of service
without deleting its record, which is preferable to `DELETE` when the
application may still be sending that `account_id`.

## One login for every application

`POST /auth/login` is one endpoint shared by every onboarded application, not
per-app forks. Credentials are **always** checked against this service's own
`users` collection: this service is the source of truth for identity and never
reaches into an application's private database.

`LoginRequest.account_id` names the application the login is for, and is
enforced rather than decorative:

- the app account must not be **disabled** (`assert_login_allowed`), and
- the user must **belong to** it — a user of application A is refused through
  application B's login form, with the same 401 as a bad password so
  membership can't be probed.

Two deliberate looseness's remain, both so nothing breaks mid-migration:
`account_id` is **optional** (omitting it skips the membership check), and an
`account_id` with no `app_accounts` record is allowed through with a warning.
Once every application is registered and every user has an `account_id`, both
can be tightened — see [Making `account_id` mandatory](#making-account_id-mandatory).

The response's top-level `account_id` is the application this token is scoped
to — downstream services (knowledge-service) read it from the verified token
and scope their data on it, so it's baked into the JWT claims rather than a
header the caller can spoof.

### Users who belong to more than one application

A user can work across several applications. Staff set this with
`PATCH /auth/users/{id}/accounts` — `account_id` is their **default** (what a
login that names no account gets) and `account_ids` lists the **extras**; the
two are combined by `features/service.py::effective_account_ids`, the single
place membership is decided.

`POST /auth/login` therefore returns an `accounts` array — every application
the verified user may sign in through, each `{account_id, name}` — **only after
the password checks out**, since which applications an email belongs to isn't
something an unauthenticated caller should be able to enumerate. The token it
issues is scoped to the account named at login, or the user's default when
none was named, so a single-account client that never shows a picker still
gets a usable token.

When there is more than one, the client offers a choice and exchanges it via
`POST /auth/me/account`, which re-issues the token scoped to the chosen
application (403 if the user doesn't belong to it, or it's disabled). It has
to be a token exchange rather than a client-side flag precisely because the
account is a signed claim the downstream services filter on — see
[knowledge-service](../knowledge-service/README.md#account-and-tenant-isolation).

A disabled application is dropped from the `accounts` list, so a user is never
offered one they can't actually use.

### Making `account_id` mandatory

Not done yet, and the order matters:

1. Register every application in [account-management-ui](../account-management-ui).
2. Backfill each user's applications with `PATCH /auth/users/{id}/accounts`
   (`account_id` for the default, `account_ids` for anyone who works across
   several).
3. Update each app to send its `account_id` at login.
4. Only then make the field required and drop the two allowances above.

Steps 1–3 are safe individually; step 4 is the breaking one.

## Password hashing

New passwords are hashed with **bcrypt** (`AUTH_BCRYPT_ROUNDS`, default 12).
Verification accepts two formats, chosen by the stored hash's own prefix:

| Stored as | Read | Written |
|---|---|---|
| `$2a$` / `$2b$` / `$2y$` | ✅ | ✅ |
| `pbkdf2_sha256$…` (this service's original scheme) | ✅ | ❌ |

bcrypt over pbkdf2 because pbkdf2 uses almost no memory and so parallelises
cheaply on GPUs; bcrypt's ~4 KB working set blunts that. (Argon2id is stronger
still, but needs a compiled dependency and wouldn't give the import
compatibility below.)

**Hashes upgrade themselves on login.** After a successful sign-in, a stored
hash that isn't current — a legacy pbkdf2 record, or bcrypt at a lower cost
than `AUTH_BCRYPT_ROUNDS` — is re-hashed in place (`features/security.py::needs_rehash`,
applied in `features/service.py::login`). Nobody resets a password; records
migrate as people sign in. Failure to rewrite is logged and never fails the
login.

That is also what makes **importing another application's users cheap**: copy
their existing bcrypt hash into this service's `users` collection and they
sign in with the password they already have. Long passwords are trimmed to
bcrypt's 72-byte limit on a UTF-8 boundary, matching how makemerich-backend
trims before hashing, so even >72-byte passwords verify against imported
hashes.

## Token lifecycle and revocation

**Read this before shortening or lengthening `AUTH_ACCESS_TTL_MINUTES`, and
before relying on logout.**

Login returns a self-describing HS256 JWT — `sub` (user_id), `email`, `name`,
`account_id`, `org_id`, `is_portless`, plus `iss` / `aud` / `jti` / `iat` /
`exp`. Callers send it as `Authorization: Bearer …` on every request.

Each service then verifies it **locally**, with no call back here:

| Service | Verifies with | Checks revocation? |
|---|---|---|
| auth-service | `AUTH_JWT_SECRET` | **Yes** — `revoked_tokens`, in `features/dependencies.py` |
| knowledge-service | `RAG_JWT_SECRET` (must equal the above) | No |
| llm-gateway | `LLM_JWT_SECRET` (must equal the above) | No |

That is deliberate: HS256 is symmetric, so all three share one secret and each
derives `user_id`/`org_id` from a *verified* token instead of trusting a
request body. No per-request network hop, and an auth-service outage doesn't
take the other services down with it.

### The consequence: logout is not instant everywhere

`POST /auth/logout` records the token's `jti` in `revoked_tokens`, and that
list is consulted in exactly one place — this service. knowledge-service and
llm-gateway only check signature, issuer, audience and expiry.

**So a logged-out (or deleted, or disabled) user keeps working against those
services until their token expires.** The exposure window is exactly
`AUTH_ACCESS_TTL_MINUTES` — which is why it defaults to **60 minutes** rather
than something more convenient. There is no refresh token, so lengthening it
buys fewer re-logins at the cost of slower revocation; shortening it does the
reverse.

If instant revocation is ever required downstream, the options are the usual
ones, and both give up the "no hop" property: have those services call
`GET /auth/me` (or a dedicated introspection endpoint) per request, or share
the revocation list through a cache both sides read.

## Administration

There is one privilege: **membership of the admin app account**
(`AUTH_ADMIN_ACCOUNT_ID`, default `richminds`). A user whose `account_id`
equals it is an admin — that is the whole rule, and it gates every
`/auth/accounts` endpoint via `require_admin`.

The account is bootstrapped at startup. The first administrator self-registers
into it once (`POST /auth/register` with that `account_id`); after that it is
**closed** to self-registration — otherwise anyone knowing the ID could sign
up as an admin. Further admins are made with
[`scripts/seed_admin.py`](scripts/seed_admin.py), which also covers an email
that already has a user record and so can't self-register.

The legacy `is_portless` allowlist is unrelated and confers nothing here; it
still gates the organization endpoints and is still read by knowledge-service.

## Access model

This section covers the legacy `is_portless` bit, which now gates only the
organization/user endpoints — app-account administration uses the separate
rule in [Administration](#administration). `is_portless` asks: is the
caller's email on the `AUTH_PORTLESS_EMAILS` allowlist? Platform staff get it automatically at
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
