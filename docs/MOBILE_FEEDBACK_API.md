# Mobile API

## Status

**Implemented (backend).** The mobile sign-in channel is live in this
repository. Clients authenticate via `/widget/signin` with an OIDC
**id_token** (Google, Apple, etc.) and then use the returned JWT against the
existing `/api/v1/*` API (posts, comments, votes) as an ordinary authenticated
user, with their real role.

## 1. Overview

The mobile channel lets a native app (or Flutter Web client) authenticate
against a Fider tenant **without a Fider browser session or Fider cookies** (and
without a password):

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
| `WIDGET_IDTOKEN_GOOGLE_JWKS_URL` | — | Google JWKS endpoint for id_token verification |
| `WIDGET_IDTOKEN_GOOGLE_ISSUER` | — | Expected Google `iss` claim (`https://accounts.google.com`) |
| `WIDGET_IDTOKEN_GOOGLE_CLIENT_ID` | — | Expected Google `aud` claim (OAuth client ID) |
| `WIDGET_IDTOKEN_APPLE_JWKS_URL` | — | Apple JWKS endpoint (`https://appleid.apple.com/auth/keys`) |
| `WIDGET_IDTOKEN_APPLE_ISSUER` | — | Expected Apple `iss` claim (`https://appleid.apple.com`) |
| `WIDGET_IDTOKEN_APPLE_APP_ID` | — | Expected Apple `aud` claim for the native app (App ID) |
| `WIDGET_IDTOKEN_APPLE_SERVICES_ID` | — | Expected Apple `aud` claim for the web client (Services ID) |

Configure at least one provider block (Google and/or Apple) to enable mobile
sign-in; they apply instance-wide for every tenant. On each sign-in the server
tries the configured providers until one verifies the presented id_token (the
token's `iss`/`aud` match at most one) and stores the matched provider's identity
(`google` or `apple`) on the user, so the same Google/Apple subject links to the
same account that uses the regular OAuth flow.

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
(at `max(1, floor(WIDGET_RATE_LIMIT/4))`) so one client cannot starve the whole
tenant.

**`WidgetCORS`** (see `app/middlewares/cors.go`):
`Access-Control-Allow-Origin: *`, `GET, POST, PUT, DELETE, OPTIONS`, headers
`Content-Type, Authorization`, `Max-Age: 86400`. Preflight `OPTIONS` returns
`200` immediately. On the authenticated `/api/v1/*` member API, the wildcard
origin is scoped to mobile-API sessions only (`MobileApiCORS`): only a request
authenticated through an API-origin JWT gets the wildcard headers, while a
same-origin UI-cookie session stays same-origin-only. Note that CORS only
governs whether arbitrary-origin browser JavaScript may **read responses** — it
is neither an authorization nor a CSRF control, and it does not stop a party
that already holds a cookie or token from sending authenticated requests.

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
    "role": 1,
    "status": 1,
    "isTrusted": true
  }
}
```

The `user` object serializes the `entity.User` fields marked public in JSON
(`id`, `name`, `role`, `status`, `isTrusted`, and `avatarURL` when set); email
and tenant are intentionally not exposed.

`token` lifetime: **24 hours**. It is issued with `Origin=api`; it grants
access to `/api/v1/*` with the user's real role (including admin routes when
the account is an administrator) but is never accepted as a session cookie.

Errors:

| Status | Body | Cause |
| --- | --- | --- |
| `400` | `{"errors":[{"message":"..."}]}` | Missing `id_token`, invalid/expired id_token, identity-provider sign-in not configured, unverified email, or private-tenant admission rejected |
| `429` | `{"error":"Too Many Requests"}` | Tenant or per-client rate limit exceeded |

### 3.2 `GET /widget/signout`

Requires valid credentials. Returns `200 {}`. This is an **acknowledgment
only**: the server keeps nothing per-session and does **not** invalidate the
issued JWT (the token stays valid up to its 24h expiry, and the server cannot
revoke it without logging the user out everywhere). Sign-out is client-side
only — the client must discard its stored JWT.

## 4. Client specification

### 4.1 Native mobile app / Flutter Web (id_token)

1. Configure at least one provider block on the server (`WIDGET_IDTOKEN_GOOGLE_*`
   and/or `WIDGET_IDTOKEN_APPLE_*`) and register the app with the matching
   provider: a Google OAuth client ID, or an Apple audience — the native App ID
   (`WIDGET_IDTOKEN_APPLE_APP_ID`) and/or web Services ID
   (`WIDGET_IDTOKEN_APPLE_SERVICES_ID`). The client the app uses to obtain an
   id_token must resolve to one of the configured client IDs of that provider
   (the `aud` claim).
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
| `400` | id_token rejected or sign-in not enabled — **do not retry the same request** until conditions change (see below) |
| `401` | Bearer JWT: session expired or user changed — re-run the sign-in flow |
| `429` | **Back off exponentially** (respect `Retry-After` if present); do not retry in a tight loop |

Treat `400` responses as **mostly non-retryable**: an expired `id_token` *is*
recoverable by reacquiring a fresh one, but a wrong audience, an unverified
email, a private-tenant admission rejection, or an unconfigured identity
provider will not succeed by repeating the identical sign-in and need
configuration or a user-side action instead.

Never log `id_token`, the returned JWT, `Authorization` bearer values, or
request bodies — log only sanitized status/error details.

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
  mobile-API (JWT) sessions — API-key credentials and a same-origin UI-cookie
  session keep same-origin-only behavior. As with all CORS, this limits which
  origins' browser JavaScript may read responses; it is not an authorization
  or CSRF control, and a party that already holds the credentials can always
  send authenticated requests from anywhere.

## 5. Client implementation checklist

- [ ] At least one provider block configured on the server (`WIDGET_IDTOKEN_GOOGLE_*`
      and/or `WIDGET_IDTOKEN_APPLE_*`) and in the app.
- [ ] `POST /widget/signin` implemented with `{ "id_token": ... }`.
- [ ] JWT stored; attached as `Authorization: Bearer` on API requests.
- [ ] 401 → re-sign-in; 429 → exponential backoff; 400 → reacquire `id_token`
      only for the expired case, surface the rest as configuration/account errors.
- [ ] Sign-out clears the stored JWT (client-side only; the server cannot revoke it).