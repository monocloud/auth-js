# @monocloud/auth-web-js

## 0.2.5

### Patch Changes

- Updated dependencies [fda4ecf]
- Updated dependencies [fda4ecf]
  - @monocloud/auth-core@0.2.5

## 0.2.4

### Patch Changes

- 7687569: - Compare the certificate binding hash (`cnf` / `x5t#S256`) during access token validation and the ID token `at_hash` / `c_hash` values using a timing safe, non-short-circuiting comparison (matching the semantics of .NET's `CryptographicOperations.FixedTimeEquals` and Go's `crypto/subtle.ConstantTimeCompare`) instead of `===`.
- 7687569: - Match the `openid` scope exactly instead of substring-testing the granted scope string.
- Updated dependencies [7687569]
- Updated dependencies [7687569]
- Updated dependencies [7687569]
- Updated dependencies [7687569]
- Updated dependencies [7687569]
- Updated dependencies [7687569]
- Updated dependencies [7687569]
  - @monocloud/auth-core@0.2.4

## 0.2.3

### Patch Changes

- Updated dependencies [001e0ce]
  - @monocloud/auth-core@0.2.3

## 0.2.2

### Patch Changes

- a214087: Correct stale README content: supported Node.js/Next.js/React version floors now match the enforced `engines`/`peerDependencies` ranges, the core feature list includes the Device Authorization Grant, the backend caching bullet is scoped to introspection results, `getSession()` is documented as returning `undefined` when signed out, and the web-js README gains Quickstart/SDK Reference links.
- Updated dependencies [a214087]
  - @monocloud/auth-core@0.2.2

## 0.2.1

### Patch Changes

- Updated dependencies [22835a3]
  - @monocloud/auth-core@0.2.1

## 0.2.0

### Minor Changes

- 34e8a50: Add `audience` and `idTokenHint` authorization parameters and allow a manual `idTokenHint` on sign-out.

  - `AuthorizationParams` gains `audience` (sent as `audience`) and `idTokenHint` (sent as `id_token_hint`); both are exposed on the sign-in/sign-up flows and on the `<SignIn>`/`<SignUp>` components, and are accepted as query-param overrides on the Next.js sign-in route.
  - Sign-out now accepts a manual `idTokenHint` (on `signOut()` options, the `<SignOut>` components, and the Next.js sign-out route) which overrides the ID token from the current session as the `id_token_hint`.
  - `Authenticators`, `Prompt`, and `DisplayOptions` now accept any string in addition to the documented values (open string unions), so custom authenticators/prompts/display modes can be passed.

  **Breaking:** `EndSessionParameters.idToken` is renamed to `idTokenHint` for consistency; node-core's `SignOutOptions` exposes `idTokenHint` (the previously inherited, no-op `idToken` field is removed).

### Patch Changes

- c462f08: Update dependency package versions
- Updated dependencies [34e8a50]
- Updated dependencies [c462f08]
- Updated dependencies [c462f08]
  - @monocloud/auth-core@0.2.0

## 0.1.4

### Patch Changes

- Updated dependencies [69ff518]
  - @monocloud/auth-core@0.1.15

## 0.1.3

### Patch Changes

- Updated dependencies [766e7f3]
  - @monocloud/auth-core@0.1.14

## 0.1.2

### Patch Changes

- e69c256: - Validate at_hash and s_hash id token claims in the implicit flow
  - Make clockTolerance configurable in node-cre and default clockSkew to 0, clockTolerance to 60
- Updated dependencies [e69c256]
  - @monocloud/auth-core@0.1.13

## 0.1.1

### Patch Changes

- b255d26: Inital release of @monocloud/auth-web-js
- b255d26: Refine sign-out and redirect URI handling in `@monocloud/auth-web-js`:
  - Renamed the `signOutCallbackPath` option to `signOutPath`.
  - Made `appUrl` optional; it now defaults to the current page's origin (`window.location.origin`).
  - Sign-out now always sends a `post_logout_redirect_uri`, defaulting to the app root when `signOutPath` is not set (mirroring how `callbackPath` defaults to the root for sign-in).
  - Redirect and post-logout redirect URIs now have any trailing slash trimmed, and callback URL matching in `processCallback()` trims trailing slashes too, so they compare consistently.
