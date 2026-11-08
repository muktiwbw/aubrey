# Technical Requirements Document (TRD): Centralized Rust Authentication Service

**Status:** Draft / Ready for Implementation

**Language & Runtime:** Rust (Edition 2021 / Tokio Async Runtime)

**Primary Database:** PostgreSQL 16+

**Authentication Protocol:** OAuth 2.0 Authorization Server (Authorization Code + PKCE for public clients) brokering Google OpenID Connect, issuing audience-scoped EdDSA JWT Access Tokens (verified via JWKS) and rotating Refresh Tokens

## 1. Background & Problem Statement

Modern product architectures are split into **browser applications** (single-page apps) and **backend APIs** that hold the actual data. Each API must know _who_ is calling it, and each browser app needs a way to sign the user in, without every team building its own login, session, and password handling.

This document specifies a **centralized Authentication Service** (an OAuth 2.0 Authorization Server acting as an Identity Broker) that:

1. **Delegates identity to Google SSO.** No passwords are stored. Users prove who they are with Google OpenID Connect (OIDC); the Auth Service auto-provisions or matches them in PostgreSQL.
2. **Signs in browser apps as public clients.** A browser app (`app_web`) cannot keep a secret, so it uses the **Authorization Code flow with PKCE**. A stolen authorization code is useless without the PKCE `code_verifier` that only the initiating browser tab holds.
3. **Issues tokens for a specific API (audience).** Access Tokens are minted **for a named Resource Server** (`aud = "app_api"`), not for the browser app. An API only accepts tokens that were explicitly addressed to it.
4. **Enables zero-call verification.** Access Tokens are signed with an **Ed25519 private key**. APIs fetch the matching **public keys from a JWKS endpoint** (`/.well-known/jwks.json`) and verify every token locally, without a per-request call to the Auth Service.
5. **Keeps long-lived sessions out of JavaScript.** Refresh Tokens live only in a hardened `HttpOnly` cookie scoped to the Auth Service host. They rotate on every use, and replaying an old one revokes the whole session family.

The design stays generic: any number of browser apps (`app_web`, `other_web`, ...) and any number of APIs (`app_api`, `other_api`, ...) can be registered as rows in PostgreSQL with no code changes.

## 2. Terminology & Roles

| Term                              | Example                                 | Description                                                                                                                                                                                                    |
| --------------------------------- | --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Auth Service**                  | `https://auth.yourdomain.com`           | This system. OAuth 2.0 Authorization Server + Google OIDC broker. The only holder of the JWT **private** signing key.                                                                                          |
| **Issuer (`iss`)**                | `https://auth.yourdomain.com`           | Identifies the Auth Service inside every token. Resource Servers require an exact match.                                                                                                                       |
| **Public Client**                 | `app_web`                               | A browser SPA that starts login and receives tokens. Registered in `oauth_clients`. Has **no `client_secret`**. Must use PKCE.                                                                                 |
| **Resource Server**               | `app_api`                               | A backend API that serves data and accepts Access Tokens. Registered in `api_resources`. **Not** an OAuth client, so it never starts a login and has no `client_id`.                                           |
| **Audience (`aud`)**              | `app_api`                               | Identifier of the Resource Server a token is meant for. Stamped into the Access Token. Each Resource Server rejects tokens whose `aud` is not its own identifier.                                               |
| **`client_id` claim**             | `app_web`                               | Records _which_ Public Client obtained the token (RFC 9068). Used for auditing and policy. It is not an audience.                                                                                              |
| **PKCE**                          | `code_verifier` / `code_challenge`      | Proof Key for Code Exchange (RFC 7636). The client commits to `code_challenge = BASE64URL(SHA-256(code_verifier))` at login and proves possession of `code_verifier` when it exchanges the code.               |
| **Internal Authorization Code**   | 43-char Base64URL string                | Short-lived (60s), single-use code that the Auth Service returns to the Public Client's `redirect_uri`. It is bound to `client_id`, `redirect_uri`, `audience`, and `code_challenge`.                          |
| **Access Token (AT)**             | EdDSA-signed JWT, 15 min                | Bearer credential sent to the Resource Server in `Authorization: Bearer <AT>`. Held in browser **memory only**.                                                                                                |
| **Refresh Token (RT)**            | Opaque 43-char string, 14 days          | Used only against the Auth Service to obtain new Access Tokens. Delivered in an `HttpOnly` cookie, rotated on every use, stored only as a SHA-256 hash.                                                        |
| **JWKS**                          | `GET /.well-known/jwks.json`            | JSON Web Key Set (RFC 7517). Publishes the Auth Service's **public** verification keys, each identified by a Key ID (`kid`).                                                                                   |
| **Upstream IdP**                  | Google SSO                              | Verifies the human's identity. The Auth Service is a **confidential** client of Google (it has a Google client secret) and also uses PKCE on that leg.                                                         |

## 3. Architecture

### 3.1 System Context

```
                                                        ┌──────────────────────────────┐
                                                        │          Google SSO          │
                                                        │     (Upstream OIDC IdP)      │
                                                        └──────────────▲───────────────┘
                                                                       │ B. OIDC Authorization Code + PKCE
                                                                       │    (Auth Service ⇄ Google, server-side)
┌──────────────────────────────┐                        ┌──────────────┴───────────────┐
│           app_web            │ A. Auth Code + PKCE    │         Auth Service         │
│       (Public Client)        │ ─────────────────────► │    (Authorization Server)    │
│    client_id = "app_web"     │ ◄───────────────────── │   iss: auth.yourdomain.com   │
│       no client_secret       │ C. Access Token (JWT)  │   Signs JWTs (Ed25519 key)   │
└──────────────┬───────────────┘    + refresh cookie    └──────────────▲───────────────┘
               │ D. Authorization: Bearer <access_token>               │
               ▼                                                       │ E. GET /.well-known/jwks.json
┌──────────────────────────────┐                                       │    (cached; refetch on unknown kid)
│           app_api            │                                       │
│      (Resource Server)       ├───────────────────────────────────────┘
│       aud = "app_api"        │
└──────────────────────────────┘
  F. Verifies every JWT locally: EdDSA signature (by kid), iss, aud == "app_api", exp/nbf.
     No per-request call to the Auth Service.
```

| Step  | Interaction                                                                                                                                                                                                       |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A** | `app_web` redirects the browser to the Auth Service with its `client_id`, `redirect_uri`, the target `audience` (`app_api`), and a PKCE `code_challenge`.                                                         |
| **B** | The Auth Service runs its own, separate OIDC flow with Google (with its own state, nonce, and PKCE) to verify the human.                                                                                           |
| **C** | `app_web` exchanges the returned single-use code + `code_verifier` for an **Access Token** (`aud = "app_api"`, held in memory) and an **`HttpOnly` Refresh Token cookie** (scoped to the Auth Service host).      |
| **D** | `app_web` calls `app_api` with `Authorization: Bearer <access_token>`.                                                                                                                                            |
| **E** | `app_api` downloads the Auth Service's public keys from the JWKS endpoint at startup and caches them. It refetches only when keys expire from cache or a token carries an unknown `kid`.                          |
| **F** | `app_api` verifies each token **locally**: signature, issuer, audience, and expiry.                                                                                                                               |

### 3.2 Recommended Deployment Topology

| Component        | Origin                        | Notes                                                                                     |
| ---------------- | ----------------------------- | ----------------------------------------------------------------------------------------- |
| Auth Service     | `https://auth.yourdomain.com` | Dedicated host. All auth cookies are host-only cookies on this host.                      |
| `app_web` (SPA)  | `https://app.yourdomain.com`  | Static assets. Registered redirect URI: `https://app.yourdomain.com/callback`.            |
| `app_api`        | `https://api.yourdomain.com`  | Stateless with respect to auth. Needs only the issuer URL, JWKS URL, and its audience.    |

> [!IMPORTANT]
> All three origins should share one **registrable domain** (`yourdomain.com`) so they are _same-site_. This lets the Refresh Token cookie use `SameSite=Strict` and keeps it working in browsers that block third-party cookies. Cross-site deployments (e.g. `app.example.org` → `auth.yourdomain.com`) need `SameSite=None`. Safari and other privacy-hardened browsers block those cookies, so silent refresh becomes unreliable. That setup is **not recommended**.

### 3.3 Key Design Decisions

1. **Public Client + PKCE instead of a client secret.** Anything shipped to a browser is public. PKCE binds the authorization code to the browser tab that started the flow, so intercepting the code (browser history, logs, a malicious extension reading the URL) is not enough to redeem it.
2. **Audience is decoupled from `client_id`.** The party that _requests_ a token (`app_web`) is different from the party that _consumes_ it (`app_api`). Stamping `aud = "app_api"` prevents a token minted for one API from being replayed against another (`other_api` rejects it). Which audiences a client may request is an explicit allowlist (`oauth_client_audiences`).
3. **Asymmetric signing + JWKS.** Resource Servers hold no secrets and make no per-request network calls. Keys can rotate without redeploying APIs, because the `kid` in each JWT header selects the right key from the published set.
4. **Short-lived Access Tokens in memory, rotating Refresh Tokens in `HttpOnly` cookies.** XSS cannot read the Refresh Token. A leaked Access Token is useful for 15 minutes at most. Rotation plus reuse detection turns a stolen Refresh Token into a detectable event that ends the session.
5. **One Refresh Token cookie per client.** The cookie name embeds the `client_id` (`__Host-rt_app_web`). Sessions of different apps in the same browser therefore never overwrite each other.
6. **Two independent PKCE legs.** `app_web` ⇄ Auth Service PKCE protects the internal code. Auth Service ⇄ Google PKCE (plus `state` and `nonce`) protects the upstream Google code. Neither side ever sees the other's verifier.

## 4. Security Model

### 4.1 Technology Stack

| Layer                | Crate / Technology                          | Rationale                                                                                                       |
| -------------------- | ------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Web Framework**    | `axum` + `tower` + `tower-http`             | Ergonomic, type-safe extractors, native Tokio integration, CORS/trace middleware.                               |
| **Cookies**          | `axum-extra` (`CookieJar`, `PrivateCookieJar`) | Typed cookie handling. `PrivateCookieJar` encrypts and authenticates (AEAD) the transient OAuth state cookie. |
| **Database Layer**   | `sqlx` (PostgreSQL)                         | Compile-time checked SQL, async pooling, transactional `FOR UPDATE` locking, `#[sqlx::test]` isolation.          |
| **OIDC Client**      | `openidconnect`                             | Spec-compliant Google OIDC with PKCE, nonce, and JWKS-based ID token verification.                              |
| **JWT Signing**      | `jsonwebtoken`                              | `EdDSA` (Ed25519) signing and verification, `kid` header support, JWK decoding for verifier tests.              |
| **Cryptography**     | `sha2`, `rand` (`OsRng`), `base64`, `subtle` | CSPRNG for tokens/codes, SHA-256 hashing for storage and PKCE, Base64URL encoding, constant-time comparisons.   |
| **Observability**    | `tracing` + `tracing-subscriber`            | Structured, async-aware logs. Security events (refresh token reuse) are logged at `WARN` with user/family IDs.   |
| **Testing**          | `wiremock`, `tokio::test`, `tower::ServiceExt` | Deterministic mocking of Google OIDC endpoints and in-process router testing.                                 |

### 4.2 Client & Audience Registry

- **Public Clients (`oauth_clients`).** Each row describes one browser app: its `id` (the `client_id`, e.g. `app_web`), exact-match `allowed_redirect_uris`, and the `allowed_origins` that may call `/auth/token`, `/auth/refresh`, and `/auth/logout`. Only active clients may start a login or refresh a session.
- **Resource Servers (`api_resources`).** Each row describes one API by its audience identifier (e.g. `app_api`). Resource Servers have no secrets, redirect URIs, or origins in this registry. They only need an identity that tokens can be addressed to.
- **Audience allowlist (`oauth_client_audiences`).** Lists which audiences a client may request. A login for `client_id=app_web&audience=other_api` is rejected unless the pair `(app_web, other_api)` is registered.
- **Identifier format.** `client_id` and audience identifiers match `^[a-z0-9_]{1,64}$` (enforced by a `CHECK` constraint). This is required because `client_id` becomes part of a cookie name.
- **Exact matching only.** `redirect_uri` and `Origin` are compared as exact strings. No prefix, wildcard, or substring matching.

### 4.3 PKCE (Public Client ⇄ Auth Service)

- **Mandatory for every client.** `code_challenge_method` must be `S256`. `plain` is rejected.
- **`code_challenge`:** exactly 43 Base64URL characters without padding (`^[A-Za-z0-9_-]{43}$`), i.e. an encoded SHA-256 digest.
- **`code_verifier`:** 43–128 characters from the unreserved set `[A-Za-z0-9-._~]` (RFC 7636 §4.1). Clients should use 32 random bytes Base64URL-encoded (43 chars).
- **Binding:** The challenge is stored on the `authorization_codes` row. At `POST /auth/token` the Auth Service computes `BASE64URL(SHA-256(code_verifier))` and compares it to the stored challenge in **constant time**.
- **Burn on any attempt:** The first exchange attempt against an existing code marks it used, whether or not it succeeds. A wrong verifier cannot be retried.

### 4.4 Access Token Format

Access Tokens are JWTs (RFC 9068 profile) signed with **Ed25519 (`EdDSA`)**.

**Header:**

```json
{ "alg": "EdDSA", "typ": "at+jwt", "kid": "2026-11-a" }
```

**Claims:**

| Claim       | Example                                  | Meaning                                                                                                   |
| ----------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `iss`       | `https://auth.yourdomain.com`            | Issuer. Must equal the configured `AUTH_ISSUER`.                                                          |
| `sub`       | `f47ac10b-58cc-4372-a567-0e02b2c3d479`   | User's public UUID (`users.uuid`). Never the internal `BIGSERIAL` id. Stable even if the email changes.   |
| `aud`       | `app_api`                                | The **single** Resource Server this token is for. Taken from the authorization code or refresh token row. |
| `client_id` | `app_web`                                | Public Client that obtained the token.                                                                    |
| `email`     | `user@example.com`                       | Informational. Do not use it as a primary key.                                                            |
| `scopes`    | `["user"]`                               | User's global roles from `user_scopes`, re-read from the database on every issuance.                      |
| `iat`/`nbf` | `1762461561`                             | Issued-at / not-before (Unix seconds). Equal at issuance.                                                 |
| `exp`       | `1762462461`                             | Expiry (`iat + ACCESS_TOKEN_TTL_SECS`, default 900).                                                      |
| `jti`       | `0b6c1f0e-...`                           | Unique token ID (UUIDv4) for log correlation.                                                             |

### 4.5 Signing Keys & JWKS

- **Active signing key.** Exactly one Ed25519 private key (`JWT_SIGNING_KEY_PEM`) with its `kid` (`JWT_SIGNING_KEY_ID`) signs all new Access Tokens.
- **Published keys.** `GET /.well-known/jwks.json` publishes the active key's public half plus any **additional public keys** (`JWT_ADDITIONAL_PUBLIC_KEYS`). These are keys being retired, or the next key published ahead of a rotation. Private keys are never published or stored in the database.
- **JWK format (Ed25519, RFC 8037):**

  ```json
  { "kty": "OKP", "crv": "Ed25519", "kid": "2026-11-a", "use": "sig", "alg": "EdDSA", "x": "<base64url-public-key>" }
  ```

- **Caching.** The endpoint responds with `Cache-Control: public, max-age=300` (`JWKS_MAX_AGE_SECS`). Resource Servers must not cache keys longer than this.
- **Zero-downtime rotation procedure:**
  1. **Pre-publish:** generate key `K2` and add its public key to `JWT_ADDITIONAL_PUBLIC_KEYS`. The JWKS now lists `K1` (active) and `K2`. Wait at least `JWKS_MAX_AGE_SECS`.
  2. **Switch:** make `K2` the active signing key and move `K1`'s public key into `JWT_ADDITIONAL_PUBLIC_KEYS`.
  3. **Drain:** wait at least `ACCESS_TOKEN_TTL_SECS` + clock leeway + `JWKS_MAX_AGE_SECS`, so that every token signed by `K1` has expired.
  4. **Retire:** remove `K1` from `JWT_ADDITIONAL_PUBLIC_KEYS`.
- **Emergency rotation (key compromise):** skip the waits. Tokens signed by the compromised key are rejected as soon as each Resource Server's JWKS cache expires (≤ `JWKS_MAX_AGE_SECS`).

### 4.6 Refresh Tokens: Rotation & Reuse Detection

- **Format & storage.** 32 random bytes (`OsRng`), Base64URL-encoded (43 chars). Only `SHA-256(token)` is stored, hex-encoded, in `refresh_tokens.token_hash`.
- **Binding.** Each row is bound to `user_id`, `client_id`, and `audience`. A refresh always mints an Access Token for the same audience the session was created for.
- **Family.** The first token from a login gets a new `family_id` (UUID). Every rotation inserts a successor in the same family.
- **Rotation.** On a successful refresh, the presented token is marked `is_revoked = true` and a successor is issued with a fresh `REFRESH_TOKEN_TTL_SECS` expiry (idle timeout, default 14 days).
- **Reuse detection.** If an already-revoked token is presented, either an attacker or the legitimate client is holding a superseded token. The Auth Service revokes the **entire family**, clears the cookie, logs a `WARN` security event, and returns `401 TOKEN_COMPROMISED`. Both parties must sign in again.
- **Re-validation on every refresh.** The client must still be active, the audience must still be active and allowed for the client, and the user must not be soft-deleted. If any check fails, the family is revoked.

> [!WARNING]
> Because rotation is strict, **two concurrent refreshes with the same cookie look like a replay** and end the session. This can happen with parallel requests in one tab or several tabs refreshing at once. Public Clients must serialize refreshes (see §10.2).

### 4.7 Cookie Policy

All cookies are host-only cookies on the Auth Service host and use the `__Host-` prefix. Browsers then require `Secure` and `Path=/` and forbid a `Domain` attribute, so no sibling subdomain can set or read them.

| Cookie                     | Set by                                 | Attributes                                                                                       | Contents                                                                                     |
| -------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| `__Host-oauth_state`       | `GET /auth/google`                     | `HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=300`                                            | AEAD-encrypted `OAuthTransientState`. Cleared by the callback.                               |
| `__Host-rt_<client_id>`    | `POST /auth/token`, `POST /auth/refresh` | `HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=1209600`                                     | Raw Refresh Token. Cleared (`Max-Age=0`) on logout or any refresh failure.                   |

- `__Host-oauth_state` must be `SameSite=Lax`, because the browser returns from Google through a cross-site top-level navigation.
- `__Host-rt_<client_id>` uses `SameSite=Strict` by default (`REFRESH_COOKIE_SAMESITE`). Use `None` only for unavoidable cross-site deployments (see §3.2).

### 4.8 CORS & Origin Validation

- **Credentialed endpoints** (`POST /auth/token`, `/auth/refresh`, `/auth/logout`) are called with `fetch(..., { credentials: "include" })`.
  - The CORS layer answers preflights only for origins present in some active client's `allowed_origins`. It echoes the exact `Origin` with `Access-Control-Allow-Credentials: true`, `Access-Control-Allow-Methods: POST`, `Access-Control-Allow-Headers: Content-Type`, and `Vary: Origin`.
  - The handler then requires `Origin` ∈ `allowed_origins` **of the `client_id` in the request body**. Otherwise it returns `403 INVALID_ORIGIN`.
  - Requests must use `Content-Type: application/json`. This forces a preflight and blocks HTML form-based CSRF.
- **`GET /auth/me`** allows registered origins with the `Authorization` header. No credentials (cookies) are involved.
- **`GET /.well-known/jwks.json`** and **`GET /health`** are public: `Access-Control-Allow-Origin: *`.
- **Token responses** carry `Cache-Control: no-store`.

## 5. Authentication Lifecycle

The lifecycle has four phases: **sign-in**, **calling the API**, **refresh** (including page reloads), and **logout**. Step numbers in each table match the numbers in its diagram.

### 5.1 Sign-In: Authorization Code + PKCE, Brokered via Google

```
┌───────────────┐                 ┌───────────────┐                  ┌─────────────┐                    ┌───────────┐
│    app_web    │                 │  Auth Service │                  │  Google SSO │                    │  Postgres │
│ (Browser SPA) │                 │               │                  │             │                    │           │
└───────┬───────┘                 └───────┬───────┘                  └──────┬──────┘                    └─────┬─────┘
        │                                 │                                 │                                 │
        │ 1. Generate code_verifier,      │                                 │                                 │
        │    code_challenge, state        │                                 │                                 │
        │    (kept in sessionStorage)     │                                 │                                 │
        │                                 │                                 │                                 │
        │ 2. GET /auth/google             │                                 │                                 │
        │    ?client_id=app_web           │                                 │                                 │
        │    &redirect_uri=<callback>     │                                 │                                 │
        │    &audience=app_api            │                                 │                                 │
        │    &code_challenge=<S256>       │                                 │                                 │
        │    &code_challenge_method=S256  │                                 │                                 │
        │    &state=<spa_state>           │                                 │                                 │
        │────────────────────────────────►│                                 │                                 │
        │                                 │                                 │                                 │
        │                                 │ 3. Validate client_id, exact    │                                 │
        │                                 │    redirect_uri, audience       │                                 │
        │                                 │──────────────────────────────────────────────────────────────────►│
        │                                 │                                 │                                 │
        │                                 │ 4. Generate Google state,       │                                 │
        │                                 │    nonce, PKCE; seal all into   │                                 │
        │                                 │    __Host-oauth_state cookie    │                                 │
        │                                 │                                 │                                 │
        │ 5. 302 → accounts.google.com    │                                 │                                 │
        │    + Set-Cookie oauth_state     │                                 │                                 │
        │◄────────────────────────────────│                                 │                                 │
        │                                 │                                 │                                 │
        │ 6. User signs in at Google      │                                 │                                 │
        │──────────────────────────────────────────────────────────────────►│                                 │
        │                                 │                                 │                                 │
        │ 7. 302 → /auth/google/callback  │                                 │                                 │
        │    ?code=<g_code>&state=<g_st>  │                                 │                                 │
        │◄──────────────────────────────────────────────────────────────────│                                 │
        │                                 │                                 │                                 │
        │ 8. GET /auth/google/callback    │                                 │                                 │
        │    Cookie: __Host-oauth_state   │                                 │                                 │
        │────────────────────────────────►│                                 │                                 │
        │                                 │                                 │                                 │
        │                                 │ 9. Exchange g_code +            │                                 │
        │                                 │    Google PKCE verifier         │                                 │
        │                                 │────────────────────────────────►│                                 │
        │                                 │                                 │                                 │
        │                                 │ 10. id_token                    │                                 │
        │                                 │◄────────────────────────────────│                                 │
        │                                 │                                 │                                 │
        │                                 │ 11. Verify id_token sig,        │                                 │
        │                                 │     nonce, email_verified       │                                 │
        │                                 │                                 │                                 │
        │                                 │ 12. Upsert user by Google       │                                 │
        │                                 │     sub; store auth_code        │                                 │
        │                                 │     + code_challenge (60s)      │                                 │
        │                                 │──────────────────────────────────────────────────────────────────►│
        │                                 │                                 │                                 │
        │ 13. 302 → <redirect_uri>        │                                 │                                 │
        │     ?code=<auth_code>           │                                 │                                 │
        │     &state=<spa_state>          │                                 │                                 │
        │◄────────────────────────────────│                                 │                                 │
        │                                 │                                 │                                 │
        │ 14. Verify state matches        │                                 │                                 │
        │     sessionStorage              │                                 │                                 │
        │                                 │                                 │                                 │
        │ 15. POST /auth/token            │                                 │                                 │
        │     code, client_id,            │                                 │                                 │
        │     redirect_uri,               │                                 │                                 │
        │     code_verifier               │                                 │                                 │
        │────────────────────────────────►│                                 │                                 │
        │                                 │                                 │                                 │
        │                                 │ 16. Consume code; check         │                                 │
        │                                 │     SHA256(verifier) ==         │                                 │
        │                                 │     code_challenge; create      │                                 │
        │                                 │     refresh token family        │                                 │
        │                                 │──────────────────────────────────────────────────────────────────►│
        │                                 │                                 │                                 │
        │ 17. 200 { access_token }        │                                 │                                 │
        │     aud=app_api, azp=app_web    │                                 │                                 │
        │     + __Host-rt_app_web         │                                 │                                 │
        │◄────────────────────────────────│                                 │                                 │
        │                                 │                                 │                                 │
        │ 18. Keep access_token in        │                                 │                                 │
        │     memory only                 │                                 │                                 │
        │                                 │                                 │                                 │
```

| Step   | Actor        | What happens                                                                                                                                                                                                                                   |
| ------ | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1      | app_web      | Generates a random `code_verifier`, derives `code_challenge = BASE64URL(SHA-256(code_verifier))`, and generates a random `state`. Both are kept in `sessionStorage` only until the callback.                                                    |
| 2      | app_web      | Navigates the browser (full-page redirect) to `GET /auth/google` with `client_id`, `redirect_uri`, `audience`, `code_challenge`, `code_challenge_method=S256`, and `state`.                                                                     |
| 3      | Auth Service | Loads the client. Rejects unknown/inactive clients and non-exact `redirect_uri` with a `400` page (never redirects to an unverified URI). Checks that `audience` is active and allowed for the client and that the PKCE parameters are well-formed. |
| 4      | Auth Service | Generates the **upstream** Google `state`, `nonce`, and PKCE pair. Encrypts them, together with the client's parameters, into the `__Host-oauth_state` cookie.                                                                                 |
| 5–7    | Browser      | Redirects to Google. The user authenticates. Google redirects back to `/auth/google/callback` with its own code.                                                                                                                              |
| 8–11   | Auth Service | Decrypts the state cookie, checks Google `state`, exchanges Google's code with the upstream PKCE verifier, and verifies the ID token's signature (Google JWKS), `nonce`, and `email_verified`.                                                  |
| 12     | Auth Service | Upserts the user by `(provider='google', sub)`. Stores `SHA-256(auth_code)` with a 60s TTL, bound to `user_id`, `client_id`, `redirect_uri`, `audience`, and `code_challenge`.                                                                 |
| 13     | Auth Service | Clears `__Host-oauth_state` and redirects to `<redirect_uri>?code=<auth_code>&state=<spa_state>`.                                                                                                                                              |
| 14     | app_web      | Verifies `state` equals the value in `sessionStorage` (CSRF / login-injection protection). Removes `code` from the address bar (`history.replaceState`).                                                                                       |
| 15     | app_web      | `POST /auth/token` (credentials included) with `code`, `client_id`, `redirect_uri`, and the stored `code_verifier`, then deletes the verifier.                                                                                                  |
| 16     | Auth Service | Locks and burns the code, validates TTL, `client_id`, `redirect_uri`, and PKCE. Creates a new refresh-token family bound to `client_id` + `audience`.                                                                                           |
| 17     | Auth Service | Returns `{ access_token, token_type, expires_in }` with `aud=app_api`, `client_id=app_web`, and sets `__Host-rt_app_web`.                                                                                                                     |
| 18     | app_web      | Keeps the Access Token in memory (never `localStorage`/`sessionStorage`) and schedules a refresh shortly before `exp`.                                                                                                                         |

> [!NOTE]
> After step 2 has passed client and redirect validation, every later failure is sent back to the **validated** `redirect_uri` as an OAuth error (`?error=...&state=...`). Examples: disallowed audience, malformed PKCE, user cancelled at Google, disabled account. See §11.2. The only exception is a missing or tampered `__Host-oauth_state` cookie at the callback: no trusted destination exists then, so a `400` page is rendered.

### 5.2 Calling the Resource Server: Local Verification via JWKS

```
┌───────────────┐               ┌───────────────────┐               ┌───────────────┐
│    app_web    │               │      app_api      │               │  Auth Service │
│ (Browser SPA) │               │ (Resource Server) │               │               │
└───────┬───────┘               └─────────┬─────────┘               └───────┬───────┘
        │                                 │                                 │
        │                 ┄┄┄┄┄┄ A. app_api startup ┄┄┄┄┄┄                  │
        │                                 │                                 │
        │                                 │ 1. GET /.well-known/jwks.json   │
        │                                 │────────────────────────────────►│
        │                                 │                                 │
        │                                 │ 2. 200 { keys: [{kid, x}] }     │
        │                                 │    Cache-Control: max-age=300   │
        │                                 │◄────────────────────────────────│
        │                                 │                                 │
        │                                 │ 3. Cache public keys by kid     │
        │                                 │                                 │
        │                ┄┄┄┄┄┄ B. Every API request ┄┄┄┄┄┄                 │
        │                                 │                                 │
        │ 4. GET /<resource>              │                                 │
        │    Authorization: Bearer <AT>   │                                 │
        │────────────────────────────────►│                                 │
        │                                 │                                 │
        │                                 │ 5. Read kid from JWT header,    │
        │                                 │    select cached public key     │
        │                                 │ 6. Verify EdDSA signature       │
        │                                 │ 7. Check iss, aud == app_api,   │
        │                                 │    exp / nbf (60s leeway)       │
        │                                 │ 8. Authorize via sub, scopes    │
        │                                 │                                 │
        │ 9. 200 OK  |  401  |  403       │                                 │
        │◄────────────────────────────────│                                 │
        │                                 │                                 │
        │               ┄┄┄┄┄┄ C. Signing key rotated ┄┄┄┄┄┄                │
        │                                 │                                 │
        │ 10. Bearer <AT, new kid>        │                                 │
        │────────────────────────────────►│                                 │
        │                                 │                                 │
        │                                 │ 11. Unknown kid → refetch       │
        │                                 │     JWKS (rate-limited)         │
        │                                 │                                 │
        │                                 │ 12. GET /.well-known/jwks.json  │
        │                                 │────────────────────────────────►│
        │                                 │                                 │
        │                                 │ 13. 200 { keys }                │
        │                                 │◄────────────────────────────────│
        │                                 │                                 │
        │                                 │ 14. Verify with new key         │
        │                                 │                                 │
```

- **A. Startup (1–3).** `app_api` is configured with only three values: issuer `https://auth.yourdomain.com`, JWKS URL `https://auth.yourdomain.com/.well-known/jwks.json`, and expected audience `app_api`. It fetches the key set and caches it by `kid` for at most `max-age`.
- **B. Every request (4–9).** Verification is purely local and CPU-bound (one Ed25519 signature check), with no database or network access. Failures return `401` with `WWW-Authenticate: Bearer error="invalid_token"`. A valid token that lacks a required scope returns `403` with `error="insufficient_scope"`.
- **C. Rotation (10–14).** A token whose `kid` is not in the cache triggers **one** JWKS refetch. Refetches are rate-limited (e.g. at most once per 30s), so tokens with random `kid` values cannot be used to flood the Auth Service. If the `kid` is still unknown after refetching, the token is rejected.

> [!IMPORTANT]
> `app_api` never sees the Refresh Token and never talks to the Auth Service on the request path. Its trust is based entirely on the issuer's public keys and the `aud` claim.

### 5.3 Refresh, Page Reload & Breach Detection

```
┌───────────────────┐               ┌───────────────┐                 ┌───────────────┐                   ┌───────────┐
│      app_api      │               │    app_web    │                 │  Auth Service │                   │  Postgres │
│ (Resource Server) │               │ (Browser SPA) │                 │               │                   │           │
└─────────┬─────────┘               └───────┬───────┘                 └───────┬───────┘                   └─────┬─────┘
          │                                 │                                 │                                 │
          │ 1. Bearer <expired AT>          │                                 │                                 │
          │◄────────────────────────────────│                                 │                                 │
          │                                 │                                 │                                 │
          │ 2. 401 TOKEN_EXPIRED            │                                 │                                 │
          │────────────────────────────────►│                                 │                                 │
          │                                 │                                 │                                 │
          │                                 │ 3. POST /auth/refresh           │                                 │
          │                                 │    { client_id: app_web }       │                                 │
          │                                 │    Cookie: __Host-rt_app_web    │                                 │
          │                                 │────────────────────────────────►│                                 │
          │                                 │                                 │                                 │
          │                                 │                                 │ 4. Origin ∈ allowed_origins     │
          │                                 │                                 │    of client_id?                │
          │                                 │                                 │                                 │
          │                                 │                                 │ 5. SELECT … FOR UPDATE          │
          │                                 │                                 │    WHERE token_hash =           │
          │                                 │                                 │    SHA256(Token_A)              │
          │                                 │                                 │────────────────────────────────►│
          │                                 │                                 │                                 │
          │                            ┄┄┄┄┄┄ Case A: valid, not revoked ┄┄┄┄┄┄                                 │
          │                                 │                                 │                                 │
          │                                 │                                 │ 6a. Revoke Token_A; insert      │
          │                                 │                                 │     Token_B (same family,       │
          │                                 │                                 │     client_id, audience)        │
          │                                 │                                 │────────────────────────────────►│
          │                                 │                                 │                                 │
          │                                 │ 7a. 200 { access_token }        │                                 │
          │                                 │     Set-Cookie: Token_B         │                                 │
          │                                 │◄────────────────────────────────│                                 │
          │                                 │                                 │                                 │
          │ 8a. Retry with new AT           │                                 │                                 │
          │◄────────────────────────────────│                                 │                                 │
          │                                 │                                 │                                 │
          │                     ┄┄┄┄┄┄ Case B: Token_A already revoked (replay) ┄┄┄┄┄┄                          │
          │                                 │                                 │                                 │
          │                                 │                                 │ 6b. Revoke ALL tokens where     │
          │                                 │                                 │     family_id = A.family_id     │
          │                                 │                                 │────────────────────────────────►│
          │                                 │                                 │                                 │
          │                                 │ 7b. 401 TOKEN_COMPROMISED       │                                 │
          │                                 │     Clear cookie → re-login     │                                 │
          │                                 │◄────────────────────────────────│                                 │
          │                                 │                                 │                                 │
          │                    ┄┄┄┄┄┄ Case C: unknown / expired / client mismatch ┄┄┄┄┄┄                        │
          │                                 │                                 │                                 │
          │                                 │ 6c. 401 INVALID_CREDENTIALS     │                                 │
          │                                 │     Clear cookie → re-login     │                                 │
          │                                 │◄────────────────────────────────│                                 │
          │                                 │                                 │                                 │
```

- **When it runs:** (a) proactively shortly before the Access Token's `exp`, (b) reactively after `app_api` returns `401 TOKEN_EXPIRED` (refresh once, retry the request once), and (c) **on every page load**. The in-memory Access Token disappears on reload, so the SPA restores the session by calling `POST /auth/refresh`. A `401` there means "not signed in".
- **Case A (normal):** `Token_A` is revoked, `Token_B` is inserted in the same family with the same `client_id` and `audience`. Current scopes are re-read, so role changes take effect within one Access Token lifetime.
- **Case B (replay):** A revoked token being presented means the token was copied. The whole family is revoked, which also invalidates `Token_B` held by the other party.
- **Case C (unknown / expired / client mismatch / revalidation failure):** the cookie is cleared and the SPA returns to the signed-out state.

### 5.4 Logout

```
┌───────────────┐                 ┌───────────────┐                   ┌───────────┐
│    app_web    │                 │  Auth Service │                   │  Postgres │
│ (Browser SPA) │                 │               │                   │           │
└───────┬───────┘                 └───────┬───────┘                   └─────┬─────┘
        │                                 │                                 │
        │ 1. Drop access_token from       │                                 │
        │    memory                       │                                 │
        │                                 │                                 │
        │ 2. POST /auth/logout            │                                 │
        │    { client_id: app_web }       │                                 │
        │    Cookie: __Host-rt_app_web    │                                 │
        │────────────────────────────────►│                                 │
        │                                 │                                 │
        │                                 │ 3. Revoke every token in        │
        │                                 │    the cookie's family_id       │
        │                                 │────────────────────────────────►│
        │                                 │                                 │
        │ 4. 204 No Content               │                                 │
        │    Clear cookie (Max-Age=0)     │                                 │
        │◄────────────────────────────────│                                 │
        │                                 │                                 │
```

- Logout revokes the **whole family** on the server and clears the cookie in the browser. `POST /auth/logout` is idempotent and always returns `204`.
- **Access Token caveat:** JWTs are stateless. An Access Token copied before logout stays valid at `app_api` until its `exp` (≤ 15 minutes). This is the deliberate trade-off for zero-call verification. If immediate revocation becomes a requirement, see §13.

## 6. Database Schema

### 6.1 Entity-Relationship Diagram

```
┌────────────────────┐    ┌────────────────────┐    ┌────────────────────┐    ┌────────────────────┐
│       scopes       │    │    user_scopes     │    │       users        │    │  user_identities   │
├────────────────────┤    ├────────────────────┤    ├────────────────────┤    ├────────────────────┤
│ PK id              │1  N│ PK,FK user_id      │N  1│ PK id              │1  N│ PK id              │
│    name (UQ)       ├────┤ PK,FK scope_id     ├────┤    uuid (UQ)       ├────┤ FK user_id         │
│                    │    │                    │    │    email (UQ)      │    │    provider        │
│                    │    │                    │    │    deleted_at      │    │    provider_subject│
└────────────────────┘    └────────────────────┘    └─────────┬──────────┘    └────────────────────┘
                                                              │ 1
                         ┌────────────────────────────────────┤
                         │ N                                  │ N
        ┌────────────────┴─────────────────┐       ┌──────────┴───────────────────────┐
        │       authorization_codes        │       │          refresh_tokens          │
        ├──────────────────────────────────┤       ├──────────────────────────────────┤
        │ PK id                            │       │ PK id                            │
        │ FK user_id   → users.id          │       │ FK user_id   → users.id          │
        │ FK client_id → oauth_clients.id  │       │ FK client_id → oauth_clients.id  │
        │ FK audience  → api_resources.id  │       │ FK audience  → api_resources.id  │
        │    code_hash (UQ, SHA-256)       │       │    token_hash (UQ, SHA-256)      │
        │    redirect_uri                  │       │    family_id                     │
        │    code_challenge                │       │    is_revoked                    │
        │    code_challenge_method         │       │    expires_at                    │
        │    is_used, expires_at           │       │    user_agent, ip_address        │
        └──────────────────────────────────┘       └──────────────────────────────────┘

┌────────────────────────────┐    ┌────────────────────────────┐    ┌────────────────────────────┐
│       oauth_clients        │    │   oauth_client_audiences   │    │       api_resources        │
├────────────────────────────┤    ├────────────────────────────┤    ├────────────────────────────┤
│ PK id   (e.g. "app_web")   │1  N│ PK,FK client_id            │N  1│ PK id   (e.g. "app_api")   │
│    client_name             ├────┤ PK,FK audience             ├────┤    name                    │
│    allowed_redirect_uris   │    │                            │    │    is_active               │
│    allowed_origins         │    │                            │    │                            │
│    is_active               │    │                            │    │                            │
└────────────────────────────┘    └────────────────────────────┘    └────────────────────────────┘
```

| Relationship                                        | Cardinality | Purpose                                                                                     |
| --------------------------------------------------- | ----------- | ------------------------------------------------------------------------------------------- |
| `users` → `user_identities`                         | 1 : N       | Links a user to upstream IdP subjects (`('google', sub)`).                                  |
| `users` ↔ `scopes` via `user_scopes`                | N : M       | Global roles embedded in Access Tokens (`scopes` claim).                                    |
| `oauth_clients` ↔ `api_resources` via `oauth_client_audiences` | N : M | Which audiences each Public Client may request.                                    |
| `authorization_codes` → `users`, `oauth_clients`, `api_resources` | N : 1 each | A single-use code is bound to one user, one client, and one audience.            |
| `refresh_tokens` → `users`, `oauth_clients`, `api_resources`      | N : 1 each | A session family is bound to one user, one client, and one audience.             |

### 6.2 PostgreSQL Migration (`migrations/20261107000001_init_auth_schema.sql`)

```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Public Clients (browser apps that initiate login)
CREATE TABLE oauth_clients (
    id VARCHAR(64) PRIMARY KEY                -- client_id, e.g. 'app_web' (also embedded in cookie name)
        CHECK (id ~ '^[a-z0-9_]{1,64}$'),
    client_name VARCHAR(100) NOT NULL,
    allowed_redirect_uris TEXT[] NOT NULL,    -- Exact-match callback URLs
    allowed_origins TEXT[] NOT NULL,          -- Exact-match origins for /auth/token, /auth/refresh, /auth/logout
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Resource Servers (APIs that accept Access Tokens), identified by audience
CREATE TABLE api_resources (
    id VARCHAR(64) PRIMARY KEY                -- audience, e.g. 'app_api' (becomes the JWT 'aud' claim)
        CHECK (id ~ '^[a-z0-9_]{1,64}$'),
    name VARCHAR(100) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Audience allowlist: which APIs a client may request tokens for
CREATE TABLE oauth_client_audiences (
    client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    audience VARCHAR(64) NOT NULL REFERENCES api_resources(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, audience)
);

-- 4. Users
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(), -- Public identifier (JWT 'sub')
    email VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- 5. Scopes (global roles)
CREATE TABLE scopes (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO scopes (name) VALUES ('user'), ('admin');

-- 6. User Scopes (junction)
CREATE TABLE user_scopes (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope_id BIGINT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, scope_id)
);

-- 7. User Identities (upstream IdP links)
CREATE TABLE user_identities (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL,            -- e.g. 'google'
    provider_subject VARCHAR(255) NOT NULL,   -- Immutable upstream 'sub'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_subject)
);

CREATE INDEX idx_user_identities_user ON user_identities(user_id);

-- 8. Single-use Internal Authorization Codes (60s TTL), bound to client, redirect, audience and PKCE
CREATE TABLE authorization_codes (
    id BIGSERIAL PRIMARY KEY,
    code_hash CHAR(64) NOT NULL UNIQUE,       -- Hex SHA-256 of the raw code
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    audience VARCHAR(64) NOT NULL REFERENCES api_resources(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,               -- Must match exactly at POST /auth/token
    code_challenge CHAR(43) NOT NULL,         -- BASE64URL(SHA-256(code_verifier)), no padding
    code_challenge_method VARCHAR(8) NOT NULL DEFAULT 'S256'
        CHECK (code_challenge_method = 'S256'),
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_authorization_codes_expires ON authorization_codes(expires_at);

-- 9. Rotating Refresh Tokens, bound to client and audience
CREATE TABLE refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    audience VARCHAR(64) NOT NULL REFERENCES api_resources(id) ON DELETE CASCADE,
    token_hash CHAR(64) NOT NULL UNIQUE,      -- Hex SHA-256 of the raw token
    family_id UUID NOT NULL,                  -- Groups one login's rotation chain
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_agent TEXT,
    ip_address INET
);

CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
```

> [!NOTE]
> `UNIQUE` constraints (`code_hash`, `token_hash`, `uuid`, `email`) already create B-tree indexes, so no separate lookup indexes are declared for them. The `expires_at` indexes support the periodic cleanup job (§8.2).

### 6.3 Example Registration (seed data / admin tooling, not part of the migration)

```sql
INSERT INTO api_resources (id, name) VALUES ('app_api', 'App API');

INSERT INTO oauth_clients (id, client_name, allowed_redirect_uris, allowed_origins)
VALUES ('app_web', 'App Web',
        ARRAY['https://app.yourdomain.com/callback'],
        ARRAY['https://app.yourdomain.com']);

INSERT INTO oauth_client_audiences (client_id, audience) VALUES ('app_web', 'app_api');
```

## 7. Rust Domain Models & Structures

### 7.1 Database & Domain Entities (`src/domain/models.rs`)

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// A registered Public Client (browser app), e.g. `app_web`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct OAuthClient {
    pub id: String,
    pub client_name: String,
    pub allowed_redirect_uris: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A registered Resource Server, identified by its audience, e.g. `app_api`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiResource {
    pub id: String,
    pub name: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub uuid: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Scope {
    pub id: i64,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserWithScopes {
    pub user: User,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorizationCodeRecord {
    pub id: i64,
    pub code_hash: String,
    pub user_id: i64,
    pub client_id: String,
    pub audience: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String, // Always "S256"
    pub is_used: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshTokenRecord {
    pub id: i64,
    pub user_id: i64,
    pub client_id: String,
    pub audience: String,
    pub token_hash: String,
    pub family_id: Uuid,
    pub is_revoked: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub user_agent: Option<String>,
    pub ip_address: Option<IpAddr>,
}
```

### 7.2 JWT Claims & OAuth State (`src/domain/claims.rs`)

```rust
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// RFC 9068-style Access Token claims. Header: { alg: "EdDSA", typ: "at+jwt", kid }.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccessTokenClaims {
    pub iss: String,         // Issuer, e.g. "https://auth.yourdomain.com"
    pub sub: Uuid,           // User's public UUID (never the internal i64 id)
    pub aud: String,         // Resource Server audience, e.g. "app_api"
    pub client_id: String,   // Public Client that obtained the token, e.g. "app_web"
    pub email: String,       // Informational only
    pub scopes: Vec<String>, // Global roles, e.g. ["user"]
    pub iat: i64,            // Issued at (Unix seconds)
    pub nbf: i64,            // Not before (Unix seconds, == iat)
    pub exp: i64,            // Expiry (iat + ACCESS_TOKEN_TTL_SECS)
    pub jti: Uuid,           // Unique token id for log correlation
}

/// Sealed (AEAD-encrypted) into `__Host-oauth_state` between /auth/google and its callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTransientState {
    // Downstream leg: Public Client -> Auth Service
    pub client_id: String,             // Validated client, e.g. "app_web"
    pub redirect_uri: String,          // Validated exact-match callback URL
    pub audience: String,              // Validated audience, e.g. "app_api"
    pub client_state: String,          // Opaque CSRF value from the client, echoed back
    pub code_challenge: String,        // Client PKCE challenge, copied onto the auth code
    pub code_challenge_method: String, // Always "S256"
    // Upstream leg: Auth Service -> Google
    pub google_csrf_state: String,     // `state` sent to Google
    pub google_nonce: String,          // OIDC replay nonce sent to Google
    pub google_pkce_verifier: String,  // PKCE verifier for Google's token endpoint
    pub issued_at: i64,                // Rejected if older than 300s
}

#[derive(Debug, Clone)]
pub struct VerifiedGoogleIdentity {
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
}
```

### 7.3 Signing Keys & JWKS (`src/domain/jwks.rs`)

```rust
use serde::{Deserialize, Serialize};

/// Response body of GET /.well-known/jwks.json
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// Ed25519 public key in JWK form (RFC 8037).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Jwk {
    pub kty: String,                // "OKP"
    pub crv: String,                // "Ed25519"
    pub kid: String,                // Key ID, matches the JWT header `kid`
    #[serde(rename = "use")]
    pub use_: String,               // "sig"
    pub alg: String,                // "EdDSA"
    pub x: String,                  // Base64URL-encoded 32-byte public key
}

/// The single key currently used to sign new Access Tokens.
pub struct ActiveSigningKey {
    pub kid: String,
    pub encoding_key: jsonwebtoken::EncodingKey,
    pub public_jwk: Jwk,
}
```

## 8. Configuration & Operations

### 8.1 Environment Variables (`AppConfig::from_env()`)

| Variable                      | Required | Default                       | Description                                                                                         |
| ----------------------------- | -------- | ----------------------------- | --------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`                | Yes      |                               | PostgreSQL connection string.                                                                       |
| `AUTH_ISSUER`                 | Yes      |                               | Public base URL, e.g. `https://auth.yourdomain.com`. Used as the `iss` claim.                       |
| `JWT_SIGNING_KEY_PEM`         | Yes      |                               | Active Ed25519 private key (PKCS#8 PEM).                                                            |
| `JWT_SIGNING_KEY_ID`          | Yes      |                               | `kid` of the active key, e.g. `2026-11-a`.                                                          |
| `JWT_ADDITIONAL_PUBLIC_KEYS`  | No       | `[]`                          | JSON array `[{ "kid": "...", "public_key_pem": "..." }]` of extra keys to publish (rotation).       |
| `ACCESS_TOKEN_TTL_SECS`       | No       | `900`                         | Access Token lifetime.                                                                              |
| `REFRESH_TOKEN_TTL_SECS`      | No       | `1209600`                     | Refresh Token idle lifetime (14 days).                                                              |
| `AUTH_CODE_TTL_SECS`          | No       | `60`                          | Internal Authorization Code lifetime.                                                               |
| `JWKS_MAX_AGE_SECS`           | No       | `300`                         | `Cache-Control: max-age` of the JWKS response.                                                      |
| `GOOGLE_CLIENT_ID`            | Yes      |                               | The Auth Service's own Google OAuth client ID.                                                      |
| `GOOGLE_CLIENT_SECRET`        | Yes      |                               | The Auth Service's Google client secret (confidential upstream client).                             |
| `GOOGLE_REDIRECT_URI`         | Yes      |                               | `https://auth.yourdomain.com/auth/google/callback`.                                                 |
| `GOOGLE_ISSUER_URL`           | No       | `https://accounts.google.com` | OIDC discovery base. Overridden by `wiremock` in tests.                                             |
| `STATE_COOKIE_KEY`            | Yes      |                               | 64-byte Base64 key for encrypting `__Host-oauth_state`.                                             |
| `REFRESH_COOKIE_SAMESITE`     | No       | `Strict`                      | `Strict` or `None` (cross-site deployments only, see §3.2).                                         |

### 8.2 Operational Requirements

- **Never log secrets.** Raw authorization codes, refresh tokens, access tokens, PKCE verifiers, and Google codes must never appear in logs. Log hashes or `jti`/`family_id` instead.
- **Cleanup job.** A background Tokio task deletes `authorization_codes` and `refresh_tokens` rows whose `expires_at` is more than 1 day in the past.
- **Rate limiting.** Apply per-IP limits on `/auth/google`, `/auth/token`, `/auth/refresh`, and `/auth/logout`.
- **Clock synchronization.** All hosts run NTP. Verifiers allow at most 60s of leeway on `exp`/`nbf`.

## 9. API Endpoints Specification

| Method | Path                        | Caller               | Purpose                                                    |
| ------ | --------------------------- | -------------------- | ---------------------------------------------------------- |
| GET    | `/health`                   | Load balancer        | Liveness check.                                            |
| GET    | `/.well-known/jwks.json`    | Resource Servers     | Publish public verification keys.                          |
| GET    | `/auth/google`              | Browser (navigation) | Validate the client request and start Google sign-in.      |
| GET    | `/auth/google/callback`     | Browser (navigation) | Finish Google sign-in and return an internal code.         |
| POST   | `/auth/token`               | Public Client (fetch)| Exchange code + PKCE verifier for tokens.                  |
| POST   | `/auth/refresh`             | Public Client (fetch)| Rotate the Refresh Token and issue a new Access Token.     |
| POST   | `/auth/logout`              | Public Client (fetch)| Revoke the session family.                                 |
| GET    | `/auth/me`                  | Public Client (fetch)| Return the current user's profile.                         |

### 9.1 `GET /health`

- **Auth Required:** None
- **Response (`200 OK`):**
  ```json
  { "status": "ok" }
  ```

### 9.2 `GET /.well-known/jwks.json`

Publishes the public keys Resource Servers use to verify Access Token signatures.

- **Auth Required:** None
- **Response (`200 OK`):**
  - **Headers:** `Content-Type: application/json`, `Cache-Control: public, max-age=300`, `Access-Control-Allow-Origin: *`
  - **Body:**
    ```json
    {
      "keys": [
        {
          "kty": "OKP",
          "crv": "Ed25519",
          "kid": "2026-11-a",
          "use": "sig",
          "alg": "EdDSA",
          "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }
      ]
    }
    ```
- **Behavior:** Returns the active key followed by every entry of `JWT_ADDITIONAL_PUBLIC_KEYS`. Built once at startup from configuration, with no database access.

### 9.3 `GET /auth/google`

Validates the Public Client's authorization request and starts the upstream Google OIDC flow. Reached by a **full-page navigation**, not `fetch`.

- **Auth Required:** None
- **Query Parameters (all required):**

  | Parameter               | Example                                 | Rule                                                        |
  | ----------------------- | --------------------------------------- | ----------------------------------------------------------- |
  | `client_id`             | `app_web`                               | Active row in `oauth_clients`.                              |
  | `redirect_uri`          | `https://app.yourdomain.com/callback`   | Exact match in the client's `allowed_redirect_uris`.        |
  | `audience`              | `app_api`                               | Active row in `api_resources`, allowed for the client.      |
  | `code_challenge`        | `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM` | `^[A-Za-z0-9_-]{43}$`                                 |
  | `code_challenge_method` | `S256`                                  | Must be `S256`.                                             |
  | `state`                 | `af0ifjsldkj`                           | Opaque, 1–512 chars. Echoed back unchanged.                 |

- **Behavior:**
  1. Load `client_id` (`is_active = true`). On failure → `400 INVALID_CLIENT` (rendered, **no redirect**).
  2. Exact-match `redirect_uri`. On failure → `400 INVALID_REDIRECT_URI` (rendered, **no redirect**).
  3. _From here on, errors redirect to the validated `redirect_uri` (§11.2)._ Verify `audience` is active and present in `oauth_client_audiences` for this client. Otherwise → `error=invalid_target`.
  4. Validate `code_challenge`, `code_challenge_method`, and `state`. Otherwise → `error=invalid_request`.
  5. Generate `google_csrf_state`, `google_nonce`, and a Google PKCE pair.
  6. Seal `OAuthTransientState` into `__Host-oauth_state` (`HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=300`).
- **Response (`302 Found`):**
  - `Location: https://accounts.google.com/o/oauth2/v2/auth?client_id=<GOOGLE_CLIENT_ID>&redirect_uri=<GOOGLE_REDIRECT_URI>&response_type=code&scope=openid%20email%20profile&state=<google_csrf_state>&nonce=<google_nonce>&code_challenge=<google_challenge>&code_challenge_method=S256`

### 9.4 `GET /auth/google/callback`

Completes the Google flow, provisions the user, and returns a single-use internal code to the Public Client.

- **Query Parameters:** `?code=<google_code>&state=<google_csrf_state>` (or `?error=...` from Google)
- **Cookies Required:** `__Host-oauth_state`
- **Behavior:**
  1. Decrypt `__Host-oauth_state`. If missing, tampered, or older than 300s → `400 OAUTH_FAILED` (rendered, **no redirect**: there is no trusted destination).
  2. If Google returned `error` → redirect to the client with `error=access_denied`.
  3. Compare `state` with `google_csrf_state` (constant time). On mismatch → `400 OAUTH_FAILED` (rendered).
  4. Exchange `google_code` + `google_pkce_verifier` at Google's token endpoint. Verify the ID token's signature (Google JWKS), `iss`, `aud`, `exp`, and `nonce`, and require `email_verified = true`. Upstream failure → `error=server_error`. Unverified email → `error=access_denied`.
  5. Upsert the user by `('google', sub)` in one transaction, granting the `user` scope on first sign-in. Soft-deleted user → `error=access_denied`.
  6. Generate a 32-byte `auth_code`. Store `SHA-256(auth_code)` with `user_id`, `client_id`, `redirect_uri`, `audience`, `code_challenge`, `code_challenge_method`, and `expires_at = NOW() + 60s`.
- **Response (`302 Found`):**
  - Clears `__Host-oauth_state` (`Max-Age=0`)
  - `Location: <redirect_uri>?code=<auth_code>&state=<client_state>`

### 9.5 `POST /auth/token`

Exchanges the internal code and PKCE verifier for an Access Token and sets the Refresh Token cookie.

- **Headers Required:** `Origin`, `Content-Type: application/json`
- **Request Body:**
  ```json
  {
    "code": "SplxlOBeZQQYbYS6WxSbIA...",
    "client_id": "app_web",
    "redirect_uri": "https://app.yourdomain.com/callback",
    "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  }
  ```
- **Behavior:**
  1. Load the client (active) and require `Origin` ∈ its `allowed_origins`. Otherwise → `400 INVALID_CLIENT` / `403 INVALID_ORIGIN`.
  2. Validate the `code_verifier` format. Otherwise → `400 INVALID_REQUEST`.
  3. In a transaction: `SELECT ... FROM authorization_codes WHERE code_hash = $1 FOR UPDATE`. Not found or `is_used = true` → `400 INVALID_AUTH_CODE`.
  4. Set `is_used = true` immediately (the code is burned even if a later check fails).
  5. Require `expires_at > NOW()`, matching `client_id` and `redirect_uri`, and `BASE64URL(SHA-256(code_verifier)) == code_challenge` (constant time). Any failure → commit the burn, return `400 INVALID_AUTH_CODE` (the specific reason is logged, not returned).
  6. Load the user with current scopes. Soft-deleted → `403 ACCOUNT_DISABLED`. Re-check that the audience is still active and allowed.
  7. Insert a Refresh Token row (new `family_id`, `client_id`, `audience`, `REFRESH_TOKEN_TTL_SECS`, user agent, IP).
  8. Sign the Access Token (`aud = code.audience`, `client_id = code.client_id`, `kid = active key`). Commit.
- **Response (`200 OK`):**
  - **Headers:**
    - `Set-Cookie: __Host-rt_app_web=<raw_token>; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1209600`
    - `Cache-Control: no-store`
  - **Body:**
    ```json
    {
      "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImtpZCI6IjIwMjYtMTEtYSJ9...",
      "token_type": "Bearer",
      "expires_in": 900
    }
    ```

### 9.6 `POST /auth/refresh`

Rotates the Refresh Token and issues a fresh Access Token for the same audience. Also used to restore the session after a page reload.

- **Headers Required:** `Origin`, `Content-Type: application/json`
- **Cookies Required:** `__Host-rt_<client_id>`
- **Request Body:**
  ```json
  { "client_id": "app_web" }
  ```
- **Behavior:**
  1. Load the client (active) and require `Origin` ∈ its `allowed_origins`.
  2. Read `__Host-rt_<client_id>`. If missing → `401 INVALID_CREDENTIALS`.
  3. In a transaction: `SELECT ... FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`.
  4. **Not found, or `client_id` mismatch** → clear cookie, `401 INVALID_CREDENTIALS`.
  5. **`is_revoked = true` (replay)** → revoke every token with the same `family_id`, log a `WARN` security event, clear cookie, `401 TOKEN_COMPROMISED`.
  6. **`expires_at <= NOW()`** → clear cookie, `401 TOKEN_EXPIRED`.
  7. **Re-validate:** user not soft-deleted (otherwise revoke family, `403 ACCOUNT_DISABLED`). Audience still active and allowed (otherwise revoke family, `401 INVALID_CREDENTIALS`).
  8. **Rotate:** set `is_revoked = true` on the current row. Insert a successor with the same `family_id`, `client_id`, and `audience` and a fresh expiry.
  9. Load current scopes, sign an Access Token with `aud = record.audience`, and commit.
- **Response (`200 OK`):** Same headers and body shape as §9.5, with the new cookie value.

### 9.7 `POST /auth/logout`

Revokes the session family and clears the client's cookie.

- **Headers Required:** `Origin`, `Content-Type: application/json`
- **Cookies:** `__Host-rt_<client_id>` (optional; logout is idempotent)
- **Request Body:**
  ```json
  { "client_id": "app_web" }
  ```
- **Behavior:** Validate client and `Origin`. If the cookie maps to a token row for this client, set `is_revoked = true` on every row in its `family_id`.
- **Response (`204 No Content`):**
  - **Headers:** `Set-Cookie: __Host-rt_app_web=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`

### 9.8 `GET /auth/me`

Returns the profile behind an Access Token. Intended for the Public Client's UI (e.g. showing the signed-in user). Resource Servers should rely on token claims instead of calling this endpoint.

- **Headers Required:** `Authorization: Bearer <access_token>`
- **Behavior:** Verify the token like a Resource Server would (signature by `kid`, `alg = EdDSA`, `typ = at+jwt`, `iss`, `exp`/`nbf`). The audience must be a **registered, active** `api_resources` entry (the issuer accepts its own tokens for any audience it minted). Then load the user from the database (`403 ACCOUNT_DISABLED` if soft-deleted).
- **Response (`200 OK`):**
  ```json
  {
    "uuid": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "email": "user@example.com",
    "client_id": "app_web",
    "audience": "app_api",
    "scopes": ["user"]
  }
  ```

## 10. Integration Contracts

### 10.1 Resource Server (`app_api`) Requirements

A Resource Server needs **no secrets** and **no registration as a client**. It needs only:

| Setting             | Value                                                |
| ------------------- | ---------------------------------------------------- |
| `ISSUER`            | `https://auth.yourdomain.com`                        |
| `JWKS_URI`          | `https://auth.yourdomain.com/.well-known/jwks.json`  |
| `EXPECTED_AUDIENCE` | `app_api` (its row id in `api_resources`)            |

For every request it must:

1. Extract the token from `Authorization: Bearer <token>`. If it is missing → `401`.
2. **Pin the algorithm:** accept only `alg = EdDSA` and `typ = at+jwt`. Never trust the header to choose the algorithm, and reject `none` and `HS*`.
3. Select the public key by the header's `kid` from its JWKS cache. On an unknown `kid`, refetch the JWKS once (rate-limited). If the `kid` is still unknown → `401`.
4. Verify the Ed25519 signature.
5. Require `iss == ISSUER`, `aud == EXPECTED_AUDIENCE`, `exp > now − 60s`, and `nbf ≤ now + 60s`.
6. Identify the user by `sub` (UUID). Do not key data by `email`.
7. Enforce coarse roles with `scopes`. Fine-grained authorization (e.g. ownership of a record) is the Resource Server's own domain logic.
8. Respond `401` + `WWW-Authenticate: Bearer error="invalid_token"` for any verification failure, and `403` + `error="insufficient_scope"` for missing roles.
9. Allow CORS from `app_web`'s origin with the `Authorization` header. No cookies (`credentials`) are needed for API calls.

### 10.2 Public Client (`app_web`) Requirements

1. **PKCE generation:** `code_verifier` = 32 bytes from `crypto.getRandomValues`, Base64URL-encoded. `code_challenge` = Base64URL of `crypto.subtle.digest("SHA-256", verifier)`. Also generate a random `state`.
2. **Transient storage:** keep `code_verifier` and `state` in `sessionStorage` only between the redirect and the callback, then delete them.
3. **Callback:** require the returned `state` to match. Strip `code`/`state` from the URL with `history.replaceState`, then call `POST /auth/token` with `credentials: "include"`.
4. **Token storage:** keep the Access Token **in memory only**. The Refresh Token is never visible to JavaScript.
5. **Session restore:** on every app start, call `POST /auth/refresh`. `200` → signed in. `401` → signed out.
6. **Refresh scheduling:** refresh about 60s before `exp`. After a `401` from `app_api`, refresh once and retry the request once.
7. **Serialize refreshes:** share a single in-flight refresh promise within a tab, and coordinate across tabs with the Web Locks API (`navigator.locks.request("auth-refresh", ...)`) or a `BroadcastChannel`. Concurrent refreshes with the same cookie trigger reuse detection (§4.6).
8. **Credentials:** use `credentials: "include"` only for Auth Service `/auth/token`, `/auth/refresh`, and `/auth/logout` calls. Send the Access Token as a Bearer header to `app_api`.
9. **Logout:** drop the in-memory token, call `POST /auth/logout`, and route to the signed-out view.
10. **XSS hardening:** use a strict Content Security Policy. In-memory tokens are still reachable by injected scripts while the page is open.

## 11. Error Handling

### 11.1 JSON Error Matrix

JSON responses use a consistent envelope:

```json
{
  "error": {
    "code": "INVALID_AUTH_CODE",
    "message": "The authorization code is invalid, expired, or has already been used."
  }
}
```

| Rust `AuthError` Variant | HTTP Status          | Error Code             | Trigger Condition                                                                         |
| ------------------------ | -------------------- | ---------------------- | ----------------------------------------------------------------------------------------- |
| `InvalidRequest`         | `400 Bad Request`    | `INVALID_REQUEST`      | Missing or malformed parameter (e.g. bad `code_verifier`, non-JSON body).                 |
| `InvalidClient`          | `400 Bad Request`    | `INVALID_CLIENT`       | Unknown or inactive `client_id`.                                                          |
| `InvalidRedirectUri`     | `400 Bad Request`    | `INVALID_REDIRECT_URI` | `redirect_uri` not an exact match in the client's `allowed_redirect_uris`.                |
| `InvalidAudience`        | `400 Bad Request`    | `INVALID_AUDIENCE`     | Audience unknown, inactive, or not allowed for the client.                                |
| `InvalidAuthCode`        | `400 Bad Request`    | `INVALID_AUTH_CODE`    | Code not found, used, expired, client/redirect mismatch, or PKCE verification failed.     |
| `OAuthValidationFailed`  | `400 Bad Request`    | `OAUTH_FAILED`         | Missing/tampered state cookie, Google state mismatch, invalid ID token or nonce.          |
| `InvalidCredentials`     | `401 Unauthorized`   | `INVALID_CREDENTIALS`  | Missing, malformed, unknown, or unverifiable token/cookie (incl. wrong `iss`/`aud`).      |
| `TokenExpired`           | `401 Unauthorized`   | `TOKEN_EXPIRED`        | Access or Refresh Token past its expiry.                                                  |
| `TokenCompromised`       | `401 Unauthorized`   | `TOKEN_COMPROMISED`    | Revoked Refresh Token replayed; family revoked.                                           |
| `InvalidOrigin`          | `403 Forbidden`      | `INVALID_ORIGIN`       | `Origin` header missing or not in the client's `allowed_origins`.                         |
| `InsufficientScope`      | `403 Forbidden`      | `FORBIDDEN`            | Valid token, but missing a scope required by the route.                                   |
| `UserSoftDeleted`        | `403 Forbidden`      | `ACCOUNT_DISABLED`     | User record has non-null `deleted_at`.                                                    |
| `DatabaseError`          | `500 Internal Error` | `INTERNAL_ERROR`       | Unexpected SQLx error (details logged, hidden from caller).                               |

### 11.2 Redirect Errors (`/auth/google`, `/auth/google/callback`)

Once `client_id` and `redirect_uri` have been validated, errors are returned to the client as standard OAuth 2.0 redirect errors instead of JSON:

```
302 Location: https://app.yourdomain.com/callback?error=invalid_target&error_description=...&state=<client_state>
```

| `error`          | Cause                                                                              |
| ---------------- | ---------------------------------------------------------------------------------- |
| `invalid_request`| Missing/malformed `code_challenge`, `code_challenge_method != S256`, bad `state`.  |
| `invalid_target` | `audience` unknown, inactive, or not allowed for the client (RFC 8707).            |
| `access_denied`  | User cancelled at Google, email not verified, or account disabled.                 |
| `server_error`   | Google token exchange or ID token verification failed unexpectedly.                |

Unknown client, unregistered `redirect_uri`, and missing/tampered state cookie are **never** redirected. They render a `400` error page.

## 12. Out of Scope / Future Work

- **OIDC / OAuth discovery document** (`/.well-known/oauth-authorization-server`) so clients and Resource Servers can auto-configure from the issuer URL.
- **Immediate Access Token revocation** via token introspection (RFC 7662) or a short-TTL denylist, for APIs that cannot tolerate the 15-minute window.
- **Machine-to-machine access** (`client_credentials` grant for confidential backend clients calling `app_api`).
- **Per-audience permissions** (API-specific scopes such as `app_api:write`) instead of global roles only.
- **Absolute session lifetime** on refresh-token families, in addition to the 14-day idle timeout.
- **Refresh reuse grace window** (e.g. a few seconds) to tolerate benign client races, traded against weaker reuse detection.
- **Revoking tokens issued from a replayed authorization code** (RFC 6749 §4.1.2 recommendation).
- **Sender-constrained tokens** (DPoP, RFC 9449) to bind Access Tokens to a browser-held key.
- **Additional upstream IdPs** (GitHub, Microsoft) via the `OAuthProvider` trait and `user_identities.provider`.
