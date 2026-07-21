# @monocloud/auth-react

## 0.2.3

### Patch Changes

- @monocloud/auth-web-js@0.2.3

## 0.2.2

### Patch Changes

- a214087: Correct stale README content: supported Node.js/Next.js/React version floors now match the enforced `engines`/`peerDependencies` ranges, the core feature list includes the Device Authorization Grant, the backend caching bullet is scoped to introspection results, `getSession()` is documented as returning `undefined` when signed out, and the web-js README gains Quickstart/SDK Reference links.
- Updated dependencies [a214087]
  - @monocloud/auth-web-js@0.2.2

## 0.2.1

### Patch Changes

- @monocloud/auth-web-js@0.2.1

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
  - @monocloud/auth-web-js@0.2.0

## 0.1.2

### Patch Changes

- @monocloud/auth-web-js@0.1.4

## 0.1.1

### Patch Changes

- 2ee1136: - React SDK Initial Release
  - @monocloud/auth-web-js@0.1.3
