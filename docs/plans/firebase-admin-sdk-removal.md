# Plan: Replace Firebase Admin SDK with Local Token Verification

## Goal

Remove `firebase.google.com/go/v4`, which is currently used only to verify
Firebase App Check and Auth ID tokens. Keep the existing Fider verifier,
middleware, metrics, and sign-in contracts while validating tokens directly
against Google's public RSA signing keys.

The two Firebase token families deliberately use different project identifiers
and key formats:

| Token | Project claim | Public keys |
| --- | --- | --- |
| App Check | Numeric Firebase project number | JWKS |
| Firebase Auth ID token | Firebase project ID | JSON map of `kid` to PEM X.509 certificate |

No service account or Application Default Credentials are needed for either
verification path.

## Configuration

Add `FIREBASE_PROJECT_NUMBER` alongside `FIREBASE_PROJECT_ID`. When
`APP_CHECK_MODE` is `monitor` or `enforce`, initialization requires:

* a non-empty project ID;
* an ASCII-numeric project number;
* at least one Firebase App ID in `FIREBASE_APP_IDS`.

`off` continues to disable Firebase verification without performing network
requests. Existing deployments must set the project number before enabling
`monitor` or `enforce`; find it in Firebase Console → Project Settings → General.

## Shared public-key cache

Introduce `app/pkg/publickeys` and use it from both Firebase verification and
the existing Google/Apple `idtoken.Validator`:

* decode RSA JWKS and Google's X.509 certificate-map response;
* cache parsed keys by `kid` and replace the active set only after a successful
  complete fetch;
* refresh expired sets and refresh once for an unknown `kid`;
* coalesce concurrent refreshes and rate-limit repeated unknown-key refreshes;
* fail closed when an expired set cannot be refreshed;
* preserve the existing one-hour Google/Apple key TTL;
* honor App Check response `max-age` but never cache longer than six hours;
* honor Firebase Auth's response `max-age`.

App Check keys are fetched during `Initialize` under the existing startup
timeout, preserving fail-fast startup. Auth keys remain lazy and are fetched on
the first Auth token verification.

## Token validation

### App Check

Fetch `https://firebaseappcheck.googleapis.com/v1/jwks` and require:

* a known, non-empty `kid`, `alg=RS256`, and `typ=JWT`;
* `iss == https://firebaseappcheck.googleapis.com/<PROJECT_NUMBER>`;
* an `aud` array containing `projects/<PROJECT_NUMBER>`;
* numeric `exp` strictly in the future;
* non-empty `sub`, treated as the Firebase App ID and checked against
  `FIREBASE_APP_IDS`.

This intentionally follows Firebase's documented manual-verification contract,
which is stricter than the current Go Admin SDK's project-ID audience and
issuer-prefix checks.

### Firebase Auth ID tokens

Fetch
`https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com`
and require:

* a known, non-empty `kid` and `alg=RS256`;
* exact string `aud == <PROJECT_ID>`;
* `iss == https://securetoken.google.com/<PROJECT_ID>`;
* numeric `exp` in the future;
* numeric `iat` and `auth_time` in the past;
* string `sub` between 1 and 128 characters.

Map `sub`, `name`, `email`, boolean `email_verified`, and nested
`firebase.sign_in_provider == "anonymous"` to the existing `AuthClaims` fields.
Do not log raw tokens.

## Compatibility and tests

Keep `Verifier`, `AppCheckClaims`, `AuthClaims`, `Mode`, `Enabled`, `Initialize`,
`SetVerifierForTest`, error categories, and `StubVerifier` unchanged. Middleware
and handlers require no Firebase-specific changes.

Test with generated RSA keys, local JWKS/X.509 endpoints, and locally signed
tokens. Cover key rotation, expiry, malformed responses, refresh concurrency,
unknown-key throttling, every required claim, App ID allowlisting, and claim
mapping. Run an opt-in smoke test with short-lived tokens from a real Firebase
test project before first deployment; never store those tokens as fixtures.

After focused and full tests pass, remove the Admin SDK import, run
`go mod tidy`, and confirm no Firebase Admin module remains in the dependency
graph. Deploy first with `APP_CHECK_MODE=monitor`, inspect verification metrics,
then switch to `enforce`.
