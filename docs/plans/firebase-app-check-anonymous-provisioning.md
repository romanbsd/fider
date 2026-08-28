# Firebase App Check and Anonymous User Provisioning

## Summary

Add an opt-in Firebase authentication mode spanning the Go backend and
`fider_flutter`. The client automatically creates or restores a Firebase
anonymous account, sends both its Firebase Auth ID token and
`X-Firebase-AppCheck`, and receives the existing Fider API JWT. Direct
Google/Apple OIDC remains backward compatible.

Firebase App Check provides app attestation, while Firebase Auth UID supplies
the per-user identity. The design follows Firebase's custom-backend App Check,
anonymous authentication, and ID-token verification guidance.

## Backend changes

- Add an injectable verifier for Firebase App Check and Auth tokens using
  Google's public signing keys, one Firebase project per Fider deployment, and
  an allowlist of accepted Firebase App IDs.
- Add `FIREBASE_PROJECT_ID`, `FIREBASE_PROJECT_NUMBER`, `FIREBASE_APP_IDS`, and
  `APP_CHECK_MODE=off|monitor|enforce` configuration. Public-key verification
  does not require Firebase Admin credentials.
- Extend `POST /widget/signin` with a Firebase request containing
  `firebase_id_token` plus `X-Firebase-AppCheck`, without changing the existing
  `id_token` contract.
- Always require valid Firebase Auth and App Check tokens for Firebase
  provisioning. Return `400` for malformed credential selection, `401` for
  invalid credentials or disallowed app IDs, and preserve existing `429`
  behavior.
- Identify Firebase users by provider `firebase` and Firebase UID. Provision
  public-tenant visitors as `Anonymous` with an empty email, or attach the
  provider to an existing user matched by verified email.
- Preserve private-site admission: reject new anonymous users while permitting
  an already-linked or email-matched existing user.
- Add a partial unique index on `(tenant_id, provider, provider_uid)` for the
  Firebase provider and make concurrent provisioning conflict-safe.
- Hydrate only previously empty profile fields from later verified Firebase
  claims and never silently merge two existing Fider users.
- In `monitor` mode, record App Check outcomes while allowing existing mobile
  traffic. In `enforce` mode, require App Check on `/widget/*` and `/api/v1/*`
  requests authenticated with an API-origin mobile JWT. UI-cookie and API-key
  requests remain unaffected.
- Keep metrics and structured logs low-cardinality and never log Firebase ID
  tokens, App Check tokens, or Fider JWTs.

## Flutter changes and public interfaces

- Add `firebase_auth` and `firebase_app_check`. The embedding application owns
  `Firebase.initializeApp()` and platform-specific App Check activation.
- Add an opt-in Firebase authentication mode to `FiderFeedbackConfig`; existing
  direct Google/Apple authentication remains the default.
- Restore a tenant-scoped Fider session first. If absent or rejected, reuse the
  current Firebase user or call `signInAnonymously()`, obtain Firebase Auth and
  App Check tokens, exchange them at `/widget/signin`, and persist the returned
  Fider session.
- Fetch an App Check token before every Fider request and send it in
  `X-Firebase-AppCheck`. In Firebase mode, fail locally rather than sending an
  unattested request when no token can be obtained.
- Add a Firebase credential-provider abstraction with Google and Apple adapters
  for linking an anonymous account. Refresh the Firebase ID token and Fider
  session after linking so the unchanged Firebase UID preserves history.
- Do not silently switch or merge accounts when a credential already belongs to
  another Firebase user. Surface an actionable error.
- Hide destructive sign-out for an unlinked anonymous account. Linked users may
  sign out and later restore their original Firebase UID by signing in again.
- Document host Firebase initialization, Anonymous Auth, App Check provider and
  debug-provider setup, and Google/Apple linking requirements.

## Tests and rollout

- Backend tests cover App Check presence, verification and allowlisting;
  enforcement modes; Firebase Auth verification; public/private tenant
  provisioning; verified-email linking; concurrency; blocked users; and legacy
  OIDC, UI-cookie, API-key, rate-limit, and mobile-JWT compatibility.
- Flutter tests cover session restoration, automatic anonymous sign-in, token
  refresh, App Check headers on every request, `401` recovery, account linking,
  conflicts, cancellation, direct-OIDC compatibility, and controller
  race/disposal behavior.
- Run focused Go tests through `.test.env`, relevant Flutter and example tests,
  analyzers, formatting checks, and `git diff --check`.
- Validate an Android/iOS debug-provider flow against a real Firebase project.
- Deploy the backend in `monitor`, release the App Check-capable client, observe
  valid-versus-missing metrics, then switch to `enforce`. Firebase provisioning
  remains unavailable while the mode is `off`.
- Preserve unrelated untracked backend files and the pre-existing deleted
  Flutter E2E files.

## References

- [Verify App Check tokens from a custom backend](https://firebase.google.com/docs/app-check/custom-resource-backend#go)
- [Protect custom backend resources from Flutter](https://firebase.google.com/docs/app-check/flutter/custom-resource)
- [Authenticate with Firebase anonymously](https://firebase.google.com/docs/auth/flutter/anonymous-auth)
- [Verify Firebase ID tokens](https://firebase.google.com/docs/auth/admin/verify-id-tokens)
