# Mobile API

## Status

**Implemented (backend).** The mobile sign-in channel is live in this
repository. Clients authenticate via `/widget/signin` with either a direct
OIDC **id_token** (Google, Apple, etc.) or, when enabled, a Firebase Auth ID
token plus Firebase App Check. They then use the returned JWT against the
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

The opt-in Firebase flow verifies two independent credentials: App Check
attests the registered app instance and Firebase Auth identifies the user by
UID. A client may automatically create an anonymous Firebase user, then link
that same Firebase account to Google or Apple without changing its UID or its
Fider history.

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
| `FIREBASE_PROJECT_ID` | — | Firebase project ID used to verify Auth tokens |
| `FIREBASE_PROJECT_NUMBER` | — | Numeric Firebase project number used to verify App Check tokens |
| `FIREBASE_APP_IDS` | — | Comma-separated allowlist of Firebase App IDs accepted from App Check tokens |
| `APP_CHECK_MODE` | `off` | `off`, `monitor`, or `enforce`; see rollout behavior below |
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

Firebase mode uses one Firebase project per Fider deployment. Set both its
project ID and numeric project number (Firebase Console → Project Settings →
General); App Check tokens identify the project by number, while Auth tokens use
the project ID. Verification uses Google's public signing keys and does not need
a service account or Application Default Credentials. `FIREBASE_APP_IDS`
contains Firebase App IDs such as `1:1234567890:android:abc123`; package names,
bundle IDs, project IDs, and project numbers are not substitutes.

App Check rollout modes:

| Mode | Existing direct-OIDC/mobile traffic | Firebase provisioning |
| --- | --- | --- |
| `off` | Unchanged; App Check is not evaluated | Disabled because provisioning always fails closed without App Check verification |
| `monitor` | Verification results are recorded, but missing/invalid App Check does not reject legacy traffic | Requires valid App Check and Firebase Auth |
| `enforce` | App Check is required for `/widget/signin` and API-origin mobile-JWT requests | Requires valid App Check and Firebase Auth |

The `fider_app_check_verifications_total{mode,result}` counter exposes only
low-cardinality outcomes (`valid`, `missing`, `invalid`, `disallowed_app`, or
`disabled`). Tokens and app IDs are never metric labels or log fields.

### 2.2 Middleware chain (route group)

```go
widget := r.Group()
widget.Use(middlewares.WidgetCORS())      // CORS for cross-origin clients
widget.Use(middlewares.WidgetAppCheck()) // observe/enforce after CORS
widget.Use(middlewares.WidgetRateLimit()) // per-tenant sliding-window limiter
widget.Use(middlewares.WidgetAuth())      // mobile JWT resolution
```

The root `AppCheck` middleware separately observes/enforces requests that the
`User` middleware has authenticated with an API-origin mobile JWT. Its sign-in
counterpart is mounted after `WidgetCORS`, so even an App Check rejection keeps
the CORS response headers; preflight `OPTIONS` remains credential-free.

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
`Content-Type, Authorization, X-Firebase-AppCheck`, `Max-Age: 86400`. Preflight `OPTIONS` returns
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
| `POST` | `/widget/signin` | CORS, RateLimit, optional App Check enforcement | Exchange one supported identity token for a Fider JWT |
| `GET` | `/widget/signout` | CORS, RateLimit, Auth | Acknowledge sign-out (client discards token) |

### 3.1 `POST /widget/signin`

Request body:

```json
{
  "id_token": "<oidc-id-token>"
}
```

Or, for Firebase mode:

```http
POST /widget/signin
Content-Type: application/json
X-Firebase-AppCheck: <app-check-token>

{"firebase_id_token":"<firebase-auth-id-token>"}
```

Send exactly one of `id_token` and `firebase_id_token`.

When `APP_CHECK_MODE=enforce`, both credential forms must include a valid
`X-Firebase-AppCheck` token, and the client must continue sending a fresh App
Check token with every request authenticated by the returned mobile JWT.
Direct-OIDC clients that cannot supply App Check must remain on `off` or
`monitor`; enforce mode has no App-Check-free compatibility path.

- `id_token` must verify against the configured JWKS/issuer/aud (provider name
  `idtoken`) and its `email_verified` claim must be `true`. The user is matched
  by provider UID, then by email, otherwise a new Visitor user is registered.
- `firebase_id_token` must verify in the configured Firebase project and must
  always be accompanied by a valid App Check token from an allowlisted Firebase
  App ID, regardless of `APP_CHECK_MODE`. The mode controls enforcement for
  legacy/direct-OIDC traffic; Firebase provisioning has no App-Check-free path.
  The Fider provider identity is `firebase` plus the Firebase UID. A new
  public-tenant user is provisioned as a Visitor named `Anonymous`; a private
  tenant rejects a new identity. A verified Firebase email may link an
  existing Fider user, and later verified name/email claims hydrate empty
  anonymous profile fields and replace the `Anonymous` placeholder name when a
  verified name arrives.

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
| `400` | `{"errors":[{"message":"..."}]}` | Missing `id_token`, invalid/expired id_token, identity-provider sign-in not configured, or unverified email |
| `401` | `{"error":"Unauthorized"}` | Firebase Auth/App Check token missing or invalid, Firebase App ID disallowed, private-tenant admission rejected for a new identity, or the matched user is blocked/deleted (OIDC and Firebase) |
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
| `401` | Sign-in: Firebase Auth/App Check rejected, App ID disallowed, private-tenant admission denied, or user blocked/deleted — do not repeat the unchanged request. Bearer JWT: session expired or user changed — re-run the sign-in flow |
| `429` | **Back off exponentially** (respect `Retry-After` if present); do not retry in a tight loop |

Treat `400` responses as **mostly non-retryable**: an expired `id_token` *is*
recoverable by reacquiring a fresh one, but a wrong audience, an unverified
email, or an unconfigured identity provider will not succeed by repeating the
identical sign-in and need configuration or a user-side action instead.

For sign-in, `401` is also non-retryable without a changed condition: obtain
fresh Firebase Auth and App Check tokens, use an allowlisted App ID, or resolve
the tenant/user admission state. A `401` from an authenticated API request means
the stored bearer JWT should be discarded and the sign-in flow restarted.

Never log `id_token`, the returned JWT, `Authorization` bearer values, or
request bodies — log only sanitized status/error details.

### 4.3 Firebase client flow

The host application initializes Firebase and activates a platform App Check
provider before constructing the feedback client. It must also enable
Anonymous Authentication in Firebase Console and register every Android, iOS,
or web app whose Firebase App ID appears in the backend allowlist.

1. Restore the tenant-scoped Fider JWT. If it is absent or rejected, reuse the
   current Firebase user or call Firebase Anonymous Auth.
2. Obtain a fresh Firebase Auth ID token and App Check token, then exchange
   them through the Firebase form of `/widget/signin` above.
3. Send a freshly obtained `X-Firebase-AppCheck` token on every subsequent
   Fider request, alongside the Fider bearer JWT where required. Do not send
   the request if App Check cannot produce a token.
4. On a protected-request `401`, clear the stale Fider JWT and repeat the
   Firebase exchange once using the current Firebase user.
5. To upgrade an anonymous account, link Google or Apple credentials to the
   current Firebase user. Refresh the Firebase ID token and Fider session after
   linking; the unchanged Firebase UID preserves ownership and history. If the
   credential already belongs to another Firebase user, do not silently merge
   or switch identities.

Avoid offering destructive sign-out for an unlinked anonymous account: it can
make that UID and its Fider history unreachable. A linked Firebase user may
sign out through Firebase Auth and later sign back into the same account.

For development, use Firebase's registered App Check debug provider and keep
debug tokens out of source control and production configuration.

### 4.4 Security notes

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
- [ ] Firebase mode only: Firebase initialized by the host, Anonymous Auth
      enabled, App Check activated, Firebase App IDs allowlisted, and every
      request carries `X-Firebase-AppCheck`.
- [ ] Roll out Firebase clients while the backend is in `monitor`; review
      `fider_app_check_verifications_total`, then move to `enforce`.
