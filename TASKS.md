# Task Milestones

## TDD Implementation Plan (Achievable Milestones)

### Milestone 1: Bootstrap & Configuration

- **Test (`tests/health.rs`):** Send `GET /health` to the Axum router via `tower::ServiceExt::oneshot`; assert `200 OK`.
- **Test (`src/config.rs`):**
  1. `AppConfig::from_env()` fails gracefully when required keys (`DATABASE_URL`, `AUTH_ISSUER`, `JWT_SIGNING_KEY_PEM`, `JWT_SIGNING_KEY_ID`, `STATE_COOKIE_KEY`) are missing.
  2. Rejects a `JWT_SIGNING_KEY_PEM` that is not an Ed25519 PKCS#8 key, and malformed `JWT_ADDITIONAL_PUBLIC_KEYS` JSON.
- **Implementation:** Workspace setup, `AppConfig`, `AuthError` (`IntoResponse`), `/health` route.

### Milestone 2: Migrations, Client/Audience Registry & User Repository

- **Test (`src/repository/client_repo.rs` via `#[sqlx::test]`):**
  1. `validate_redirect_uri_allows_exact_match`: Seed `app_web` with `https://app.yourdomain.com/callback`; assert exact match succeeds.
  2. `validate_redirect_uri_rejects_unregistered_or_partial_match`: `https://app.yourdomain.com/callback/evil` and `https://evil.com` → `AuthError::InvalidRedirectUri`.
  3. `inactive_client_is_rejected`: `is_active = false` → `AuthError::InvalidClient`.
  4. `audience_allowed_only_when_registered_for_client`: Seed `app_api` and `other_api`, link only `(app_web, app_api)`. `app_api` passes; `other_api` → `AuthError::InvalidAudience`.
  5. `inactive_api_resource_is_rejected`: Deactivate `app_api` → `AuthError::InvalidAudience`.
  6. `origin_must_match_client_allowed_origins`: `https://app.yourdomain.com` passes; `https://evil.com` → `AuthError::InvalidOrigin`.
- **Test (`src/repository/user_repo.rs` via `#[sqlx::test]`):**
  1. `upsert_google_user_creates_new_user_and_default_scope`: Rows exist in `users`, `user_identities`, and `user_scopes` (`'user'`).
  2. `upsert_google_user_returns_existing_user`: Same Google `sub` twice → one user row.
  3. `soft_deleted_user_cannot_authenticate`: `deleted_at = NOW()` → `AuthError::UserSoftDeleted`.
- **Implementation:** `migrations/20261107000001_init_auth_schema.sql`, `ClientRepository` (clients, audiences, origins), `UserRepository`.

### Milestone 3: Pure Cryptographic Service

- **Test (`src/services/crypto_service.rs` via `#[test]`):**
  1. `jwt_roundtrip_preserves_claims_and_header`: Sign claims with `aud: "app_api"`, `client_id: "app_web"`; verify with the public key; assert claims match and header has `alg=EdDSA`, `typ=at+jwt`, `kid`.
  2. `jwt_rejects_wrong_audience`: Token with `aud: "app_api"` verified with expected audience `other_api` → `AuthError::InvalidCredentials`.
  3. `jwt_rejects_wrong_issuer`: Mismatched `iss` → `AuthError::InvalidCredentials`.
  4. `jwt_rejects_expired_token`: `exp = now − 120` → `AuthError::TokenExpired`.
  5. `jwt_rejects_tampered_scopes`: Inject `"admin"` into the payload → signature failure.
  6. `jwt_rejects_alg_none_and_hs256`: Hand-crafted `none` and `HS256` tokens are rejected.
  7. `pkce_s256_matches_rfc7636_vector`: `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` → `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`.
  8. `pkce_rejects_malformed_verifier_and_challenge`: Too-short, too-long, or out-of-charset inputs fail validation.
  9. `high_entropy_token_generation_and_sha256_hashing`: Tokens/codes are 43 Base64URL chars; hashes are 64 hex chars.
- **Implementation:** `CryptoService` wrapping `jsonwebtoken`, `sha2`, `rand`, `base64`, `subtle`.

### Milestone 4: Signing Keys & JWKS Endpoint

- **Test (`src/services/key_service.rs` via `#[test]`):**
  1. `jwks_contains_active_and_additional_keys`: Active `kid` first, followed by every configured additional key.
  2. `jwk_x_verifies_issued_token`: Build a `jsonwebtoken::DecodingKey::from_jwk` from the published JWK and verify a freshly signed token.
- **Test (`tests/jwks_test.rs`):**
  1. `GET /.well-known/jwks.json` → `200`, `Cache-Control: public, max-age=300`, `Access-Control-Allow-Origin: *`, and only public fields (`kty, crv, kid, use, alg, x`), no `d`.
- **Implementation:** `KeyService` (loads the active key and additional public keys at startup), JWKS handler.

### Milestone 5: Authorization Code & Refresh Token State Machines

- **Test (`src/services/token_service.rs` via `#[sqlx::test]`):**
  1. `issue_and_consume_auth_code_succeeds_once`: Issue a code for `(app_web, app_api)` with a challenge; exchange with the right verifier → succeeds; second exchange → `AuthError::InvalidAuthCode`.
  2. `auth_code_rejects_mismatched_client_or_redirect_uri`: Exchange with `other_web` or a different `redirect_uri` → `AuthError::InvalidAuthCode`.
  3. `auth_code_rejects_wrong_verifier_and_burns_code`: Wrong verifier → `InvalidAuthCode`; a retry with the correct verifier also fails.
  4. `auth_code_expires_after_ttl`: Expired code → `AuthError::InvalidAuthCode`.
  5. `issued_tokens_carry_code_audience`: Access Token `aud == "app_api"`, `client_id == "app_web"`; refresh row has the same `client_id` and `audience`.
  6. `rotate_valid_token_revokes_old_and_keeps_family_and_audience`: `Token_A` → `Token_B`; `Token_A.is_revoked`, same `family_id`, same `audience`.
  7. `replay_of_revoked_token_revokes_entire_family`: Rotate `A` → `B`, replay `A` → `AuthError::TokenCompromised` and `B.is_revoked == true`.
  8. `refresh_rejects_client_mismatch`: Present `app_web`'s token as `other_web` → `AuthError::InvalidCredentials`.
  9. `refresh_revokes_family_when_audience_disallowed`: Remove `(app_web, app_api)` link, refresh → failure and family revoked.
- **Implementation:** `TokenRepository` and `TokenService` using SQL transactions (`BEGIN ... FOR UPDATE`).

### Milestone 6: Google OIDC Client & Verification

- **Test (`src/services/oauth_service.rs` via `#[tokio::test]` + `wiremock`):**
  1. `authorization_url_contains_pkce_state_and_nonce`: Generated URL has `code_challenge_method=S256`, `state`, and `nonce`.
  2. `callback_verifies_id_token_against_mock_jwks`: `wiremock` serves mock discovery, JWKS, and `/token`; `exchange_code()` returns `VerifiedGoogleIdentity`.
  3. `callback_rejects_mismatched_nonce`: ID token with a different `nonce` → `AuthError::OAuthValidationFailed`.
  4. `callback_rejects_unverified_email`: `email_verified = false` → rejected.
- **Implementation:** `OAuthProvider` trait and `GoogleOidcProvider` using `openidconnect`.

### Milestone 7: HTTP Handlers, Cookie & CORS Policies

- **Test (`tests/auth_flow_test.rs`):**
  1. `GET /auth/google?client_id=app_web&redirect_uri=https://evil.com&...` → `400 INVALID_REDIRECT_URI` (no `Location` header).
  2. `GET /auth/google` with `audience=other_api` (not allowed) → `302` to `https://app.yourdomain.com/callback?error=invalid_target&state=xyz`.
  3. `GET /auth/google` with `code_challenge_method=plain` → `302` with `error=invalid_request`.
  4. Valid `GET /auth/google?client_id=app_web&redirect_uri=https://app.yourdomain.com/callback&audience=app_api&code_challenge=<c>&code_challenge_method=S256&state=xyz` → `302` to Google; capture `__Host-oauth_state` (`Path=/; SameSite=Lax`).
  5. `GET /auth/google/callback?code=mock_google_code&state=...` with the cookie → `302` to `https://app.yourdomain.com/callback?code=<auth_code>&state=xyz`; state cookie cleared.
  6. `POST /auth/token` with `Origin: https://evil.com` → `403 INVALID_ORIGIN`.
  7. `POST /auth/token` with the wrong `code_verifier` → `400 INVALID_AUTH_CODE`.
  8. `POST /auth/token` (fresh flow, correct verifier, `Origin: https://app.yourdomain.com`) → `200`, `Cache-Control: no-store`, `Set-Cookie: __Host-rt_app_web=...; Path=/; HttpOnly; Secure; SameSite=Strict`; decoded token has `aud=app_api`, `client_id=app_web`.
  9. `POST /auth/refresh` `{client_id: "app_web"}` with the cookie → rotated cookie and new `access_token`; replaying the old cookie → `401 TOKEN_COMPROMISED`.
  10. `POST /auth/logout` → `204` and `Max-Age=0`; a subsequent refresh → `401`.
  11. CORS preflight from `https://app.yourdomain.com` → echoed origin with `Allow-Credentials: true`; from `https://evil.com` → no CORS headers.
- **Implementation:** `src/handlers/auth_handler.rs`, `src/handlers/jwks_handler.rs`, dynamic CORS middleware backed by `oauth_clients.allowed_origins`.

### Milestone 8: Bearer Extractor, Scope Guard & Resource-Server Conformance

- **Test (`tests/middleware_test.rs`):**
  1. `GET /auth/me` with no header → `401`.
  2. `GET /auth/me` with a valid `Bearer <access_token>` → `200` with `uuid`, `client_id`, `audience`, `scopes`.
  3. Test route `/admin-only` with a `"user"`-scoped token → `403 FORBIDDEN`.
- **Test (`tests/resource_server_test.rs`), the contract an `app_api` relies on:**
  1. Fetch `/.well-known/jwks.json` from the router, build a verifier configured as `app_api` (issuer, JWKS, `aud = app_api`), and verify a token issued by the full flow → success.
  2. The same token against a verifier configured for `other_api` → rejected.
  3. Token signed by a key published only after rotation (new `kid`) → verifier refetches JWKS and succeeds. Token with a random `kid` → rejected.
- **Implementation:** `FromRequestParts` for `AuthenticatedUser` in `src/middleware/auth.rs`. It is built on the same verification routine described in §10.1, parameterized by expected audience.
