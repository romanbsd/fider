# Mobile API

## Status

**Implemented (backend).** The mobile sign-in channel is live in this
repository. Clients authenticate via `/widget/signin` with an OIDC
**id_token** (Google, Apple, etc.) and then use the returned JWT against the
existing `/api/v1/*` API (posts, comments, votes) as an ordinary authenticated
user, with their real role.

## 1. Overview

The mobile channel lets a native app (or Flutter Web client) authenticate
against a Fider tenant **without a browser, cookies or a password**:

1. **id_token sign-in** — the client presents an OIDC **id_token** (Google,
   Apple, etc.) issued to the operator-configured client; Fider verifies it
   against the configured JWKS/issuer and signs the matching user in.
2. **Signed-in JWT** — after sign-in the client holds a Fider JWT
   (`Authorization: Bearer <jwt>`): valid **24 hours**, issued with
   `Origin=api` so it can never be replayed as a browser session cookie.

There is no dedicated widget/device identity path anymore: the widget token,
device hash and device-secret machinery have been removed from the backend.
The `/widget/*` routes exist only to hand a client an API-origin JWT in
exchange for an id_token.

## 2. Backend implementation

### 2.1 Configuration (env vars)

| Variable | Default | Purpose |
| --- | --- | --- |
| `WIDGET_ENABLED` | `true` | Mounts the `/widget/*` route group and the mobile API CORS layers |
| `WIDGET_RATE_LIMIT` | `120` | Max requests per tenant per minute |
| `WIDGET_IDTOKEN_JWKS_URL` | — | JWKS endpoint for id_token verification |
| `WIDGET_IDTOKEN_ISSUER` | — | Expected `iss` claim |
| `WIDGET_IDTOKEN_CLIENT_ID` | — | Expected `aud` claim |

Setting the three `WIDGET_IDTOKEN_*` variables enables mobile sign-in for every
tenant of the instance; they are the single global switch (per-tenant OIDC
configuration is intentionally out of scope).

### 2.2 Middleware chain (route group)

```go
widget := r.Group()
widget.Use(middlewares.WidgetCORS())     // CORS for cross-origin clients
widget.Use(middlewares.WidgetRateLimit()) // per-tenant sliding-window limiter
widget.Use(middlewares.WidgetAuth())      // mobile JWT resolution
```

**`WidgetAuth`** (see `app/middlewares/widget.go`):

| Method | Credentials |
| --- | --- |
| Bearer JWT | `Authorization: Bearer <fider-jwt>` → signs in the token's user |

- The `/widget/signin` path is exempt from authentication (it *is* the login).
- The JWT must carry `Origin=api` — a UI-session (`Origin=ui`) JWT is rejected.
- Invalid/expired JWT → `401`.

**`WidgetRateLimit`** (see `app/middlewares/widget.go`) applies a sliding window
of 1 minute per tenant; exceeding `WIDGET_RATE_LIMIT` → `429`. The
unauthenticated `/widget/signin` endpoint is additionally limited per client IP
(at `WIDGET_RATE_LIMIT/4`) so one client cannot starve the whole tenant.

**`WidgetCORS`** (see `app/middlewares/cors.go`):
`Access-Control-Allow-Origin: *`, `GET, POST, PUT, DELETE, OPTIONS`, headers
`Content-Type, Authorization`, `Max-Age: 86400`. Preflight `OPTIONS` returns
`200` immediately. On the authenticated `/api/v1/*` member API, the wildcard
origin is scoped to mobile-API sessions only (`MobileApiCORS`): a request
authenticated through an API-origin JWT gets the wildcard headers, a same-origin
UI-cookie session stays same-origin-only, so a leaked higher-privilege UI
session can't be abused from an arbitrary origin.

## 3. API surface

All endpoints are public/unauthenticated except where noted.

| Method | Path | Middlewares | Description |
| --- | --- | --- | --- |
| `POST` | `/widget/signin` | CORS, RateLimit | Exchange an id_token for a Fider JWT |
| `GET` | `/widget/signout` | CORS, RateLimit, Auth | Acknowledge sign-out (client discards token) |

### 3.1 `POST /widget/signin`

Request body:

```json
{
  "id_token": "<oidc-id-token>"
}
```

- `id_token` must verify against the configured JWKS/issuer/aud (provider name
  `idtoken`) and its `email_verified` claim must be `true`. The user is matched
  by provider UID, then by email, otherwise a new Visitor user is registered.

Success `200`:

```json
{
  "token": "<fider-jwt>",
  "user": {
    "id": 42,
    "name": "Jon Snow",
    "email": "jon@example.com",
    "role": 1,
    "tenant": 1
  }
}
```

`token` lifetime: **24 hours**. It is issued with `Origin=api`; it grants
access to `/api/v1/*` with the user's real role (including admin routes when
the account is an administrator) but is never accepted as a session cookie.

Errors:

| Status | Body | Cause |
| --- | --- | --- |
| `400` | `{"errors":{"id_token":"id_token is required"}}` | Missing `id_token` |
| `422` | `{"error":"..."}` | Invalid/expired id_token, identity-provider sign-in not configured, unverified email, or private-tenant admission rejected |
| `429` | `{"error":"Too Many Requests"}` | Tenant or per-client rate limit exceeded |

### 3.2 `GET /widget/signout`

Requires valid credentials. Returns `200 {}`. The server keeps nothing
per-session; the client is expected to discard its stored JWT.

## 4. Client specification

### 4.1 Native mobile app / Flutter Web (id_token)

1. Configure `WIDGET_IDTOKEN_JWKS_URL`, `WIDGET_IDTOKEN_ISSUER`,
   `WIDGET_IDTOKEN_CLIENT_ID` on the server and add the app as an OIDC client.
   The OIDC client used to obtain the id_token must resolve to the configured
   `WIDGET_IDTOKEN_CLIENT_ID` (the `aud` claim).
2. On launch (or when the stored JWT is expired/invalid), obtain an id_token
   from the OS/browser sign-in flow (Google/Apple Sign-In).
3. Sign in:

   ```
   POST /widget/signin
   Content-Type: application/json
   { "id_token": "<oidc-id-token>" }
   ```

   Store the returned Fider JWT (valid **24 hours**) and reuse it until it
   fails. The user is matched to an existing tenant account by provider ID,
   then by email, or provisioned as a new Visitor when unknown. From here on the
   client calls the existing `/api/v1/*` API with
   `Authorization: Bearer <jwt>` exactly like any other authenticated user —
   including admin routes when the account is an administrator.
4. **Authenticated requests** send `Authorization: Bearer <jwt>`. The JWT's
   `Origin=api` claim keeps it a bearer-only credential: if it leaks, it cannot
   be replayed as a full browser UI session.
5. **Sign out** — `GET /widget/signout` with credentials, then delete the JWT.

### 4.2 Retry & error handling

| Status | Action |
| --- | --- |
| `200` | Store JWT |
| `400` | Bug in client request; log |
| `401` | Bearer JWT: session expired or user changed — re-run the sign-in flow |
| `422` | id_token rejected (expired / wrong audience / unverified email / not invited on a private tenant) — re-trigger the native/browser sign-in |
| `429` | **Back off exponentially** (respect `Retry-After` if present); do not retry in a tight loop |

### 4.3 Security notes

- Server only stores user/provider identities; no mobile-specific secrets are
  persisted on the server side.
- JWT expiry is **24 hours**; clients should be prepared for 401 at any time
  and re-sign-in.
- **Origin=api is bearer-only.** The `User()` middleware never turns an
  API-origin JWT into a session cookie: presenting it as a cookie discards the
  cookie and continues only if a valid `Authorization` header is also present
  (see `app/middlewares/user.go`).
- **Sessions are bound to the user's security stamp.** A role change, blocked
  account, or OAuth allowed-roles update rotates the stamp and invalidates
  already-issued mobile JWTs on their next use.
- **Wildcard CORS is scoped.** `MobileApiCORS` on the authenticated
  `/api/v1/*` member API only adds `Access-Control-Allow-Origin: *` for
  mobile-API (JWT) sessions. A leaked higher-privilege UI-cookie session keeps
  same-origin-only behavior, so an arbitrary origin can't read responses acted
  on by the browser UI's session.

## 5. Client implementation checklist

- [ ] OIDC client configured on the server (`WIDGET_IDTOKEN_*`) and in the app.
- [ ] `POST /widget/signin` implemented with `{ "id_token": ... }`.
- [ ] JWT stored; attached as `Authorization: Bearer` on API requests.
- [ ] 401 → re-sign-in; 429 → exponential backoff; 422 → refresh id_token.
- [ ] Sign-out clears the stored JWT.