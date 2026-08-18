
<p align="center">
  <a href="https://fider.io/" target="_blank">
    <img src="etc/fiderlogo.png" width="300" alt="Fider">
  </a>
</p>

<p align="center">
    <a href="https://fider.io/">Fider.io</a> •
    <a href="https://feedback.fider.io">Fider Feedback</a> •
    <a href="https://demo.fider.io">Fider Demo</a> •
    <a href="https://docs.fider.io">Docs</a> •
    <a href="https://github.com/getfider/fider/blob/main/CONTRIBUTING.md">Contributing</a>
</p>

<br/>
<br/>

<img src="etc/fidergithub.png">

<br/>
<br/>

[![build](https://github.com/getfider/fider/actions/workflows/build.yml/badge.svg)](https://github.com/getfider/fider/actions/workflows/build.yml)

# Fider is a feedback portal for feature requests and suggestions.

__Give your customers a voice and let them tell you what they need. Spend less time guessing and more time building the right product.__

# Getting Started

## ☁️ **Fider Cloud**

The easiest and quickest way to get started. A fully managed services by the creators of Fider to help you get started in minutes. Forget about managing software updates and patches, we do it all for you! [Sign up now](https://fider.io/#get-started)

## 🏢 **Self-Hosted**

Install Fider on your own servers, in your own infrastructure. It's totally free, but of course you're responsible for everything. [Learn how](https://docs.fider.io/self-hosted/)

If you do self-host and enjoy Fider, please [let us know where you're using it](https://github.com/getfider/fider/issues/899) - we really appreciate it 🙏

# 📱 Configuration: Mobile App Sign-In

Fider can authenticate native mobile apps (Google or Apple Sign-In) without a
browser session: the app exchanges an OIDC `id_token` for a 24-hour API JWT at
`POST /widget/signin` and then calls the existing `/api/v1/*` API with
`Authorization: Bearer <jwt>`. Full API spec:
[docs/MOBILE_FEEDBACK_API.md](docs/MOBILE_FEEDBACK_API.md).

## Enabling mobile sign-in

Add at least one provider block to your environment (`.env` / `/etc/fider/fider.env`) and restart the service:

```env
# Mobile API
WIDGET_ENABLED=true
WIDGET_RATE_LIMIT=120

# Google Sign-In (optional)
WIDGET_IDTOKEN_GOOGLE_JWKS_URL=https://www.googleapis.com/oauth2/v3/certs
WIDGET_IDTOKEN_GOOGLE_ISSUER=https://accounts.google.com
WIDGET_IDTOKEN_GOOGLE_CLIENT_ID=xxxxxxxx.apps.googleusercontent.com

# Sign in with Apple (optional)
WIDGET_IDTOKEN_APPLE_JWKS_URL=https://appleid.apple.com/auth/keys
WIDGET_IDTOKEN_APPLE_ISSUER=https://appleid.apple.com
# Native app audience (App ID) and web audience (Services ID); set the one(s) you
# use. The client the app uses to obtain an id_token must match one of these.
WIDGET_IDTOKEN_APPLE_APP_ID=com.example.app
WIDGET_IDTOKEN_APPLE_SERVICES_ID=com.example.app.services
```

Google and Apple can be configured at the same time; the server tries each
configured provider until one verifies the presented id_token. A user who signs
in through mobile is linked to the same account as the regular OAuth flow for
that provider.

## Setting up a provider

```md
Google Cloud Console (console.cloud.google.com → Credentials):
1. Create an OAuth 2.0 Client ID (Web application is simplest; native
   platforms can use their own clients).
2. Add your app to the client (package + SHA-1 for Android, bundle ID + reverse
   client ID in Info.plist for iOS).
3. Put the client ID in WIDGET_IDTOKEN_GOOGLE_CLIENT_ID. The clientId passed to
   GoogleSignIn() in the app must match — it becomes the token's aud claim.

Apple Developer (developer.apple.com → Certificates, Identifiers & Profiles):
1. Enable "Sign in with Apple" for your App ID and set it as
   WIDGET_IDTOKEN_APPLE_APP_ID (the native app's aud claim).
2. Create a Services ID and set it as WIDGET_IDTOKEN_APPLE_SERVICES_ID (the
   web client's aud claim). Set only the one(s) your client uses.
3. Create a private Key for Sign in with Apple (record the Key ID and Team ID).
```

## Security notes

- Mobile JWTs are `Origin=api` bearer-only credentials — they are never accepted
  as a browser session cookie and expire after 24 hours.
- `Access-Control-Allow-Origin: *` on the member API is scoped to mobile-JWT
  sessions only; UI-cookie and API-key sessions stay same-origin-only.
- Sign-out is client-side only: the server acknowledges it but cannot revoke the
  issued JWT (it expires within 24h).

# 💰 Donations and Sponsors

Support the development of Fider to help us make it the best feedback tool! You can set up donations as small or large as you want to help us keep Fider going. [Donate](https://opencollective.com/fider)

If your organization uses Fider, consider becoming a sponsor - set up a monthly donation and get your logo and link on the README. [Become a sponsor](https://opencollective.com/fider)

<br/>
<br/>

# Contributors

This project exists thanks to all the amazing people who contribute!

<a href="https://github.com/getfider/fider/graphs/contributors"><img src="https://opencollective.com/fider/contributors.svg?width=890&button=false" /></a>

Read our [CONTRIBUTING](CONTRIBUTING.md) guide to learn how you can contribute to Fider.

<br/>
<br/>
