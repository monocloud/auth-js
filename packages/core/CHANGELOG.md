# @monocloud/auth-core

## 0.2.6

### Patch Changes

- e19236d: - added `validateLogoutToken()` to `MonoCloudOidcClient` for validating OpenID Connect Back-Channel Logout Tokens, throwing `MonoCloudTokenError` on failure. Exported the new `LogoutTokenClaims` type.

## 0.2.5

### Patch Changes

- fda4ecf: - added a `code` discriminator to `MonoCloudTokenError` (`invalid_token`, `insufficient_scope`, `insufficient_groups`)
  - added optional `status` and `statusText` to `MonoCloudHttpError`
  - `validateAccessTokenClaims` and `validateCertificateBinding` are now `protected` so subclasses can revalidate cached claims
- fda4ecf: - added a `raw` property to every error raised from an unsuccessful HTTP response, exposing the response `status`, `statusText`, `headers` and unparsed `body`. Repeated headers are combined into a single comma-separated value and `set-cookie` is excluded.
  - a `401` from the introspection endpoint is now reported as `invalid_client` rather than a generic `introspection_failed`, per RFC 6749 §5.2
  - a standard OAuth error body is now read from a `401` as well as a `400` at the pushed authorization, token, refresh, revocation and device endpoints, instead of being discarded
  - error responses whose body is empty or is not JSON no longer fail with a parse error; they fall back to the endpoint's standard error code
  - a failed userinfo request now raises a `MonoCloudTokenError` instead of a `MonoCloudOPError`, since it describes the presented token. `403` responses are now handled as `insufficient_scope`, and a `401` without a `WWW-Authenticate` challenge no longer surfaces as an unexpected status code

## 0.2.4

### Patch Changes

- 7687569: - Build the `client_secret_basic` `Authorization` header from the credential's UTF-8 bytes instead of calling `btoa` directly, which threw `InvalidCharacterError` for any client id or secret containing a character outside Latin-1.
  - Supplying a JWK as the client secret together with `client_secret_basic` now throws instead of silently sending `[object Object]` as the password.
- 7687569: - Correct the documented default for `MonoCloudOidcBackendClientOptions.clockTolerance`.
- 7687569: - Enforce `max_age` when the ID token omits `auth_time`.
- 7687569: - JWT access token validation no longer rejects tokens based on the `typ` header. Previously any token with a `typ` other than `at+jwt` was rejected with an `Invalid token type` error. This relaxes the tokens accepted by `protectApi()`; all other validation (issuer, audience, expiry, algorithm and signature) is unchanged.
- 7687569: - Compare the certificate binding hash (`cnf` / `x5t#S256`) during access token validation and the ID token `at_hash` / `c_hash` values using a timing safe, non-short-circuiting comparison (matching the semantics of .NET's `CryptographicOperations.FixedTimeEquals` and Go's `crypto/subtle.ConstantTimeCompare`) instead of `===`.
- 7687569: - Keep the cached issuer metadata and JSON Web Key Set when a forced refresh (`getMetadata(true)` / `getJwks(true)`) fails.
- 7687569: - Match the `openid` scope exactly instead of substring-testing the granted scope string.

## 0.2.3

### Patch Changes

- 001e0ce: Add support for mTLS endpoint aliases and per-trust-store ("additional") mTLS endpoint aliases from the OpenID Connect discovery document (RFC 8705).

  - When a client authenticates with a mutual-TLS client authentication method (`tls_client_auth`, `self_signed_tls_client_auth`, or `spiffe_x509`), the token, revocation, introspection, device authorization, and pushed authorization request (PAR) endpoints are now resolved from `mtls_endpoint_aliases` in the issuer metadata. If no matching alias is published, a `MonoCloudValidationError` is thrown rather than silently falling back to the regular endpoint.
  - New `trustStoreId` option selects a specific trust store's endpoints from `mtls_additional_endpoint_aliases`.
  - New `metadataResolver` option supplies the issuer metadata out-of-band — for example, mTLS endpoint aliases for a private/hidden trust store that is not published in the tenant's public discovery document.
  - New `jwksResolver` option supplies the JSON Web Key Set out-of-band — for example, signing keys for a private trust store that is not published in the tenant's public JWKS.
  - `@monocloud/auth-node-core` now forwards `clientAuthMethod`, `trustStoreId`, `metadataResolver`, `fetcher`, and the (previously resolved but unused) `jwksCacheDuration` / `metadataCacheDuration` to the underlying OIDC client. New env vars: `MONOCLOUD_AUTH_CLIENT_AUTH_METHOD`, `MONOCLOUD_AUTH_TRUST_STORE_ID`. `@monocloud/backend-node` adds `MONOCLOUD_BACKEND_TRUST_STORE_ID`.
  - `clientSecret` in `@monocloud/auth-node-core` and `@monocloud/backend-node` now accepts a JWK for `private_key_jwt` — supply it as a JSON string in `MONOCLOUD_AUTH_CLIENT_SECRET` / `MONOCLOUD_BACKEND_CLIENT_SECRET` (or as an object programmatically) and it is parsed and validated automatically. Previously the client secret was always treated as a plain string, so `private_key_jwt` could not be configured through these SDKs.

## 0.2.2

### Patch Changes

- a214087: Correct stale README content: supported Node.js/Next.js/React version floors now match the enforced `engines`/`peerDependencies` ranges, the core feature list includes the Device Authorization Grant, the backend caching bullet is scoped to introspection results, `getSession()` is documented as returning `undefined` when signed out, and the web-js README gains Quickstart/SDK Reference links.

## 0.2.1

### Patch Changes

- 22835a3: Include the `audience` and `id_token_hint` parameters in Pushed Authorization Requests (PAR). Previously they were only sent on the authorization URL, so both were silently dropped when `usePar` was enabled.

## 0.2.0

### Minor Changes

- 34e8a50: Add `audience` and `idTokenHint` authorization parameters and allow a manual `idTokenHint` on sign-out.

  - `AuthorizationParams` gains `audience` (sent as `audience`) and `idTokenHint` (sent as `id_token_hint`); both are exposed on the sign-in/sign-up flows and on the `<SignIn>`/`<SignUp>` components, and are accepted as query-param overrides on the Next.js sign-in route.
  - Sign-out now accepts a manual `idTokenHint` (on `signOut()` options, the `<SignOut>` components, and the Next.js sign-out route) which overrides the ID token from the current session as the `id_token_hint`.
  - `Authenticators`, `Prompt`, and `DisplayOptions` now accept any string in addition to the documented values (open string unions), so custom authenticators/prompts/display modes can be passed.

  **Breaking:** `EndSessionParameters.idToken` is renamed to `idTokenHint` for consistency; node-core's `SignOutOptions` exposes `idTokenHint` (the previously inherited, no-op `idToken` field is removed).

- c462f08: Add SPIFFE client authentication methods `spiffe_jwt` and `spiffe_x509` to `clientAuthMethod`.

  - `spiffe_x509` authenticates via mutual TLS using an X.509-SVID (presented at the TLS transport layer, the same as `tls_client_auth`).
  - `spiffe_jwt` sends a SPIFFE JWT-SVID (obtained from the SPIFFE Workload API and provided as the `clientSecret` string) as the `client_assertion`, with `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`.

### Patch Changes

- c462f08: Update dependency package versions

## 0.1.15

### Patch Changes

- 69ff518: - Added Device Authorization Flow

## 0.1.14

### Patch Changes

- 766e7f3: - Lowered PBKDF2_ITERATIONS to 100k

## 0.1.13

### Patch Changes

- e69c256: - Validate at_hash and s_hash id token claims in the implicit flow
  - Make clockTolerance configurable in node-cre and default clockSkew to 0, clockTolerance to 60

## 0.1.12

### Patch Changes

- 6d595b2: Parse scope from callback params and assorted test/docs fixes

## 0.1.11

### Patch Changes

- d4a07a0: Update dependency package versions

## 0.1.10

### Patch Changes

- 0bfdf86: Floor unix timestamps, return refreshed user from userinfo, correct scopes length check

## 0.1.9

### Patch Changes

- fdf0a05: - Rename 'user' to 'claims' in authenticated request types
  - Removed `jti` claim from IdTokenClaims

## 0.1.8

### Patch Changes

- f3f475a: Added Node.js backend SDK with Express and Fastify support

## 0.1.7

### Patch Changes

- f20edaa: - Implement `strictProfileSync` option for syncing the user profile during session refresh.

## 0.1.6

### Patch Changes

- 7a24686: Improve comments and descriptions

## 0.1.5

### Patch Changes

- d1dedf5: # Add initialize wrappers, rename protect client API, and overhaul docs/build pipeline
  - Added initialize.ts as the top-level function API layer with lazy singleton delegation to MonoCloudNextClient, and re-exported it from index.ts.
  - Renamed client page guard API from protectPage to protectClientPage (protect-client-page.tsx), updated client exports, related components, tests, and examples.
  - Renamed type usage from JWSAlgorithm to SecurityAlgorithms and propagated it through core/node-core APIs.
  - Added/expanded TypeDoc-friendly JSDoc categories and API comments in core/node-core/nextjs files (errors, classes, hooks, components, handler types).
  - Updated OIDC client defaults in monocloud-oidc-client.ts (JWKS/metadata cache durations from 60s to 300s).
  - Changed node-core default behavior in defaults.ts: allowQueryParamOverrides now defaults to true.
  - Fixed text typos.
  - Added split (html + markdown) docs generation:
  - Added docs generation hooks/configs in docs-gen/ (including hook-html.mjs, hook.mjs, post-generate.mjs, typedoc.html.mjs, typedoc.markdown.mjs; removed typedoc.json).
  - Added package-specific TypeDoc entry configs: typedoc.json, typedoc.json, typedoc.json.
  - Adjusted package publishing/build setup for core/node-core: Source-based local main/types/exports with dist mapping moved under publishConfig.
  - Split tsdown output configs for CJS and ESM+DTS.
  - Updated Next.js examples to use package-level helper exports directly (removed example-local monocloud.ts files) and refreshed route matcher examples.

## 0.1.4

### Patch Changes

- abc0bc5: Updated packages
- 1a22540: Updated Readme files

## 0.1.3

### Patch Changes

- 05568e9: - fix JSON error assertion for Node > 20. Node.js updated JSON.parse error messages to include line/column numbers in newer versions. Updated the message to assert according to the running Node version.
- 05568e9: - Added matrix testing for all packages on Node.js version 20, 22, and 24.
- 05568e9: - Moved vitest reporter to the respective configs.
  - Added default reporter back to see the test results.

## 0.1.2

### Patch Changes

- 21a411c: Added documentation links to README.md

## 0.1.1

### Patch Changes

- be680ec: Bump Release

## 0.1.0

### Minor Changes

- c0e8cd3: Initial Release of SDKs
