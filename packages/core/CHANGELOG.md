# @monocloud/auth-core

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
