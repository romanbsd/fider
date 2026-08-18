# Mobile Feedback & Widget API

## Status

**Implemented (backend).** The feedback widget and mobile client sign-in channel is
live in this repository. Clients authenticate via `/widget/signin` and then use the
returned JWT against the **existing** `/api/v1/*` API (posts, comments, votes) as an
ordinary authenticated user — with a real role for id_token sign-ins, or a
`Visitor` device user for widget-token sign-ins. There is **no widget UI** yet and
no `/widget/*` data routes: the JWT itself unlocks the existing API.

## 1. Overview

The widget/mobile channel lets third-party clients (an embedded feedback widget on a
customer site, or a native mobile app) authenticate against a Fider tenant **without
a browser, cookies or a password**. Three mechanisms:

1. **Widget tokens** — per-tenant secrets created by administrators. A client proves
   possession by sending the raw token together with a stable **device ID**. This
   signs the device in as a scoped **device user** (role Visitor) and the server
   responds with a long-lived Fider JWT.
2. **ID tokens** — for native/mobile apps: the client presents an OIDC **id_token**
   (Google, Apple, etc.) issued to the tenant's client; Fider verifies it against the
   configured JWKS/issuer and signs the matching user in.
3. **Signed-in JWT** — after sign-in the client holds a Fider JWT
   (`Authorization: Bearer <jwt>`): **365 days** for a device sign-in, **24 hours**
   for an id_token sign-in.

## 2. Backend implementation

### 2.1 Database (migration `202608171200_add_widget_tokens`)

```sql
CREATE TABLE widget_tokens (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    INTEGER NOT NULL REFERENCES tenants (id),
    token_hash   TEXT NOT NULL,
    label        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    UNIQUE (tenant_id, token_hash)
);

CREATE INDEX widget_tokens_tenant_id_idx ON widget_tokens (tenant_id);

ALTER TABLE users ADD COLUMN device_hash TEXT;
ALTER TABLE users ADD COLUMN device_secret_hash TEXT;
CREATE UNIQUE INDEX users_tenant_device_hash_idx ON users (tenant_id, device_hash);
```

- **Tokens are stored hashed** (`SHA-256` of the raw value). The raw value is shown
  once at creation time and can never be retrieved afterwards.
- **Device users** are ordinary `users` rows with `device_hash` set and role
  `Visitor`. `(tenant_id, device_hash)` is unique, so a re-sign-in from the same
  device resolves to the same user. A client-supplied `email` is **not** stored
  (it is unverified and would otherwise collide with OAuth/magic-link identity).
- **Device secrets are stored hashed** the same way as widget tokens. The raw
  value is returned once, in the response to a device's first sign-in, and is
  required to re-authenticate that device afterwards — see
  [4.4 Security notes](#44-security-notes).

### 2.2 Configuration (env vars)

| Variable | Default | Purpose |
| --- | --- | --- |
| `WIDGET_ENABLED` | `true` | Mounts the `/widget/*` route group |
| `WIDGET_RATE_LIMIT` | `120` | Max requests per tenant per minute |
| `WIDGET_IDTOKEN_JWKS_URL` | — | JWKS endpoint for id_token verification |
| `WIDGET_IDTOKEN_ISSUER` | — | Expected `iss` claim |
| `WIDGET_IDTOKEN_CLIENT_ID` | — | Expected `aud` claim |

`WIDGET_IDTOKEN_*` are only needed if native id_token sign-in is used.

### 2.3 Middleware chain (route group)

```go
widget := r.Group()
widget.Use(middlewares.WidgetCORS())     // CORS for cross-origin clients
widget.Use(middlewares.WidgetRateLimit()) // per-tenant sliding-window limiter
widget.Use(middlewares.WidgetAuth())      // credential resolution
```

**`WidgetAuth`** (see `app/middlewares/widget_auth.go`) resolves the caller from one
of:

| Method | Credentials |
| --- | --- |
| Bearer JWT | `Authorization: Bearer <fider-jwt>` → signs in the token's user |
| Widget token + device | `X-Widget-Token: <raw>` + `X-Widget-UDID: <device-id>` + `X-Widget-Device-Secret: <raw>` → signs in the device user |

- The `/widget/signin` path is exempt from authentication (it *is* the login).
- Token/device mismatch, unknown device, missing/incorrect device secret, or a
  revoked token → `401`.
- `X-Widget-UDID` must be a well-formed UUID **v4** specifically — a bare
  length check isn't enough, and neither is accepting any UUID version: v1 is
  time/MAC-based and predictable, v3/v5 are deterministic hashes of a
  namespace+name an attacker could precompute. Only v4's ~122 bits of CSPRNG
  entropy make a `udid` infeasible to pre-register ahead of a legitimate
  device — see [4.4 Security notes](#44-security-notes).
- The widget token alone identifies the *tenant*, not the caller — every device
  of a tenant shares it. `X-Widget-Device-Secret` is the caller's actual proof
  of identity for this specific device; see
  [4.4 Security notes](#44-security-notes).

**`WidgetRateLimit`** (see `app/middlewares/widget_rate_limit.go`) applies a sliding
window of 1 minute per tenant; exceeding `WIDGET_RATE_LIMIT` → `429`.

**`WidgetCORS`** (see `app/middlewares/cors.go`):
`Access-Control-Allow-Origin: *`, `GET, POST, PUT, DELETE, OPTIONS`, headers
`Content-Type, Authorization, X-Widget-Token, X-Widget-UDID, X-Widget-Device-Secret`,
`Max-Age: 86400`. Preflight `OPTIONS` returns `200` immediately. On the
authenticated `/api/v1/*` member API, the wildcard origin is scoped to
Visitor-role (device) sessions only (`VisitorWidgetCORS`) — a real
collaborator/admin bearer session hitting the same routes stays
same-origin-only.

## 3. API surface

All endpoints are public/unauthenticated except where noted.

| Method | Path | Middlewares | Description |
| --- | --- | --- | --- |
| `POST` | `/widget/signin` | CORS, RateLimit | Sign in a device user or via id_token → returns JWT |
| `GET` | `/widget/signout` | CORS, RateLimit, Auth | Acknowledge sign-out (client discards token) |
| `GET` | `/api/v1/admin/widgets/tokens` | **admin** | List widget tokens |
| `POST` | `/api/v1/admin/widgets/tokens` | **admin** | Create a widget token |
| `DELETE` | `/api/v1/admin/widgets/tokens/:id` | **admin** | Revoke a widget token |

### 3.1 `POST /widget/signin`

Request body:

```json
{
  "token": "<raw-widget-token>",
  "udid": "<stable-device-id>",
  "name": "My Device",         // optional, default ""
  "email": "",                 // optional, default ""
  "device_secret": "",         // required to re-sign-in an already-registered device; omit/empty on first sign-in
  "id_token": "<oidc-id-token>" // optional; when present, token/udid/device_secret are ignored
}
```

- **Device path:** `token` + `udid` required. `token` is validated (hash lookup,
  not revoked). A device seen for the first time is created and its user
  returned. An already-registered `udid` requires `device_secret` to match the
  value issued at that device's first sign-in — see
  [4.4 Security notes](#44-security-notes).
- **id_token path:** `id_token` must verify against the configured JWKS/issuer/aud
  (provider name `idtoken`). The user is matched by provider UID, then by email,
  otherwise a new Visitor user is registered.

Success `200`:

```json
{
  "token": "<fider-jwt>",
  "device_secret": "<raw-secret>", // only present on a device's first sign-in
  "user": {
    "id": 42,
    "name": "My Device",
    "email": "",
    "role": 3,
    "tenant": 1
  }
}
```

`token` lifetime depends on the path: **365 days** for a device sign-in, **24 hours**
for an id_token sign-in (see [4.4 Security notes](#44-security-notes)).

`device_secret` is never recoverable after this response — the client must store
it (alongside `udid`) and send it as `device_secret` on every later sign-in for
this device.

Errors:

| Status | Body | Cause |
| --- | --- | --- |
| `400` | `{"errors":{"token":"token is required, udid must be a valid UUID"}}` | Missing `token`, or `udid` missing/not a well-formed UUID, on device path |
| `401` | — | Invalid or revoked widget token, or `device_secret` missing/incorrect for an already-registered `udid` |
| `422` | `{"error":"..."}` | Invalid `id_token`, or id_token sign-in not configured |
| `429` | `{"error":"Too Many Requests"}` | Tenant rate limit exceeded |

### 3.2 `GET /widget/signout`

Requires valid credentials. Returns `200 {}`. The server keeps nothing per-session;
the client is expected to discard its stored JWT.

### 3.3 Admin token management

`POST /api/v1/admin/widgets/tokens` — body `{"label": "iOS app"}` → `200`:

```json
{
  "id": 7,
  "label": "iOS app",
  "token": "<raw-token-shown-once>"
}
```

`GET /api/v1/admin/widgets/tokens` → `200`:

```json
{
  "tokens": [
    { "id": 7, "label": "iOS app", "createdAt": "...", "lastUsedAt": null, "revokedAt": null }
  ]
}
```

Raw tokens are never returned by list — only `id`, `label`, `createdAt`,
`lastUsedAt`, `revokedAt`.

`DELETE /api/v1/admin/widgets/tokens/:id` → `200 {}`. Revoked tokens fail all
subsequent sign-in and stateless header auth (`X-Widget-Token`). Revoking a
token immediately invalidates device JWTs issued from it; revoking the tenant's
**last** active token also invalidates id_token JWTs — see
[4.4 Security notes](#44-security-notes). `403` if the id does not belong to
the tenant.

## 4. Client specification

### 4.1 Embedded widget (device user)

1. Obtain a widget token out-of-band (admin API or future admin UI) and bake it into
   the widget build. It is a 32-char base62 secret — treat like a password; it must
   not ship with per-user privilege.
2. Generate a **stable device id** (`udid`) on first launch — a UUID v4 stored
   locally. Do **not** regenerate per request (that would create a new device user
   each time).
3. **Sign in** once per launch:

   ```
   POST /widget/signin
   Content-Type: application/json
   { "token": "<widget-token>", "udid": "<device-id>", "name": "Chrome on macOS" }
   ```

   On the **first** sign-in for this `udid`, the response includes a
   `device_secret` — store it locally alongside `udid` (e.g. `localStorage`).
   From the **second** sign-in onward, send it back:

   ```
   POST /widget/signin
   Content-Type: application/json
   { "token": "<widget-token>", "udid": "<device-id>", "device_secret": "<stored-secret>" }
   ```

   Store the returned `token` (JWT). On a `401` sign-in response (revoked
   widget token, or a missing/incorrect `device_secret`) drop the stored JWT
   and surface "widget not configured" — a wrong `device_secret` for an
   existing `udid` is not recoverable by retrying; it means the locally
   stored secret was lost or the client is misconfigured.
4. **Authenticated requests** send `Authorization: Bearer <jwt>`. The JWT is
   accepted by the **existing `/api/v1/*` member API** (posts, comments, votes,
   subscriptions, settings) with the signed-in user's real role; device users
   (Widget Visitor) can vote and create posts on public communities. The server
   re-checks — on every authenticated request — that the widget token the JWT was
   issued from is still active, so revoking a token immediately invalidates the
   JWTs tied to it (see
   [4.4 Security notes](#44-security-notes)).
5. **Sign out** — `GET /widget/signout` with credentials, then delete the JWT. The
   device user and widget token remain valid; re-sign-in uses the same `udid`.

### 4.2 Native mobile app (id_token)

1. Configure `WIDGET_IDTOKEN_JWKS_URL`, `WIDGET_IDTOKEN_ISSUER`,
   `WIDGET_IDTOKEN_CLIENT_ID` on the server and add the app as an OIDC client.
   The tenant must also have at least one active widget token — that is the
   per-tenant opt-in for mobile sign-in.
2. On launch (or when the stored JWT is expired/invalid), obtain an id_token from the
   OS sign-in flow (Google/Apple Sign-In).
3. Sign in:

   ```
   POST /widget/signin
   Content-Type: application/json
   { "id_token": "<oidc-id-token>" }
   ```

   Store the returned Fider JWT (valid **24 hours**) and reuse it until it fails.
   The user is matched to an existing tenant account by Google/Apple subject,
   then by email, or provisioned as a new Visitor when unknown. From here on the
   app calls the existing `/api/v1/*` API with `Authorization: Bearer <jwt>`
   exactly like any other authenticated user — including admin routes when the
   account is an administrator.
4. Optionally persist the user (name/email) from the `user` field for display.

### 4.3 Retry & error handling

| Status | Action |
| --- | --- |
| `200` | Store JWT |
| `400` | Bug in client request; log |
| `401` | Sign-in: widget token invalid/revoked — show "widget not configured". Bearer JWT: session expired or user changed — re-run the sign-in flow |
| `422` | id_token rejected (expired / wrong audience / unverified email / not invited on a private tenant) — re-trigger native sign-in |
| `429` | **Back off exponentially** (respect `Retry-After` if present); do not retry in a tight loop |

### 4.4 Security notes

- Server only stores `SHA-256` hashes of widget tokens — a DB leak does not leak
  usable tokens.
- Device identifiers (`udid`) are also stored as `SHA-256` digests; the raw value
  is never persisted.
- JWT expiry is **365 days** for device JWTs and **24 hours** for id_token JWTs;
  clients should be prepared for 401 at any time and re-sign-in.
- **Token revocation is retroactive**: each device JWT is bound to its widget
  token, and every authenticated request re-checks that the token is still
  active. Revoking a widget token immediately invalidates the JWTs issued through
  it. id_token JWTs are not bound to a single token; they remain valid only while
  the tenant still has **at least one** active widget token, so revoking all
  tokens (or the last one) ends mobile id_token sessions without blocking the
  user in the browser UI.
- **Re-authenticating an existing device requires its `device_secret`**, not just
  the widget token and `udid`. The widget token is shared by every device of a
  tenant, so it alone doesn't identify the caller; `device_secret` is issued once
  at a device's first sign-in (never recoverable afterwards) and is the actual
  proof of possession for that specific device. Without it, anyone holding the
  tenant's widget token plus a known `udid` could otherwise authenticate as that
  device's user. Treat `device_secret` as a non-shareable credential, the same as
  a password — a client that loses it cannot recover the same device identity and
  must be treated as re-registering.
- **First registration is first-come, first-served on `udid`.** A caller
  holding only the widget token can register a brand-new `udid` before its
  legitimate owner ever does, claiming that device identity and locking the
  real device out with no recovery. The server rejects any `udid` that isn't
  a well-formed UUID **v4** specifically to make this impractical: pre-registering a
  meaningful share of a real UUID v4's ~122-bit space isn't feasible. This
  depends on the *server-side format check*, not client cooperation — but it
  does not, and cannot, prevent a client's own duplicate first-launch request
  from racing itself; a client should sign in exactly once per install and
  treat that as fire-and-forget (no naive retry-on-timeout with a fresh
  request).
- Device users are role `Visitor` — they cannot administer anything. Raise
  privilege via the normal member/admin flow if a device user needs more.
- `Access-Control-Allow-Origin: *` is intentional (arbitrary customer sites embed the
  widget) — credentials are carried in headers, never cookies. On the
  authenticated `/api/v1/*` member API this wildcard is scoped to Visitor-role
  (device) sessions only (`VisitorWidgetCORS`); a real collaborator or admin
  bearer session hitting the same routes stays same-origin-only, so a leaked
  higher-privilege token can't be used from an arbitrary origin.

## 5. Client implementation checklist

- [ ] Admin-created widget token available to the client (env/secret/config).
- [ ] Stable per-install `udid` generated and persisted.
- [ ] `device_secret` from a device's first sign-in persisted alongside `udid`
      and sent as `device_secret` on every later sign-in for that device.
- [ ] `POST /widget/signin` implemented with both token/udid and id_token paths.
- [ ] JWT stored; attached as `Authorization: Bearer` on widget requests.
- [ ] 401 → re-sign-in; 429 → exponential backoff; 422 → refresh id_token.
- [ ] Sign-out clears the stored JWT.
- [ ] Revoked-token UX ("widget not configured") surfaced to the user.

## 6. Not implemented (removed / future work)

Read/write data routes under `/api/v1/widget/*` (posts, comments, votes,
reactions, tags, subscriptions, search) are **not implemented** and are not needed:
the JWT issued by `/widget/signin` is accepted by the existing `/api/v1/*` member
API directly, so clients use the standard endpoints. The widget channel remains a
thin authentication layer (sign-in, sign-out, token lifecycle, rate limiting) on
top of it.
