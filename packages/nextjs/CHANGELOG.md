# @monocloud/auth-nextjs

## 0.2.5

### Patch Changes

- Updated dependencies [649e777]
  - @monocloud/auth-node-core@0.2.5

## 0.2.4

### Patch Changes

- 7687569: - Concurrent sign ins no longer overwrite each other. Each authorization transaction is now stored in its own cookie, named after the transaction it holds (`state.{hash}`), so a sign in started in one tab can still be completed after another one is started or completed elsewhere. Previously the second sign in clobbered the shared `state` cookie, failing the first tab's callback with `Invalid state` or `Invalid Authentication State`.
  - The state cookie now expires. The lifetime is configurable through `state.duration` or `MONOCLOUD_AUTH_STATE_DURATION`, defaults to 900 seconds (15 minutes) and cannot be lower than 300 seconds (5 minutes). The duration is applied to both the cookie and the encrypted state, so an abandoned sign in cannot be completed once it elapses.
  - Completing a sign in or signing out discards every transaction still in progress, since the session they would establish is shared by every tab. A sign in started before another one can still be completed; it is only the transactions left pending afterwards that are cleared. The number of concurrent transactions retained while sign ins are in progress is configurable through `state.maxConcurrent` or `MONOCLOUD_AUTH_STATE_MAX_CONCURRENT` (`1`–`20`, default `5`), with the earliest ones evicted first. Set it to `1` for sequential sign ins, where starting a new sign in discards the previous pending one.
  - Configurations where the state cookie name equals the session cookie name, or where either extends the other across a `.` boundary (for example `session` and `session.x`), are now rejected at client construction, as the two cookies would be indistinguishable.
  - Sign ins which were already in progress when this version is deployed cannot be completed, as their transaction is not stored under the new cookie name. Those users will need to sign in again; the leftover cookie is never read, and is cleaned up on the next sign out.
  - **Breaking:** removed `state.cookie.persistent` and `MONOCLOUD_AUTH_STATE_COOKIE_PERSISTENT`. The option had no effect, and state cookies now always expire with `state.duration`. Remove it from your configuration if you set it.
- Updated dependencies [7687569]
- Updated dependencies [7687569]
- Updated dependencies [7687569]
- Updated dependencies [7687569]
- Updated dependencies [7687569]
- Updated dependencies [7687569]
- Updated dependencies [7687569]
- Updated dependencies [7687569]
  - @monocloud/auth-core@0.2.4
  - @monocloud/auth-node-core@0.2.4

## 0.2.3

### Patch Changes

- Updated dependencies [001e0ce]
  - @monocloud/auth-core@0.2.3
  - @monocloud/auth-node-core@0.2.3

## 0.2.2

### Patch Changes

- a214087: Correct stale README content: supported Node.js/Next.js/React version floors now match the enforced `engines`/`peerDependencies` ranges, the core feature list includes the Device Authorization Grant, the backend caching bullet is scoped to introspection results, `getSession()` is documented as returning `undefined` when signed out, and the web-js README gains Quickstart/SDK Reference links.
- Updated dependencies [a214087]
  - @monocloud/auth-core@0.2.2
  - @monocloud/auth-node-core@0.2.2

## 0.2.1

### Patch Changes

- Updated dependencies [22835a3]
  - @monocloud/auth-core@0.2.1
  - @monocloud/auth-node-core@0.2.1

## 0.2.0

### Minor Changes

- 34e8a50: Add `audience` and `idTokenHint` authorization parameters and allow a manual `idTokenHint` on sign-out.

  - `AuthorizationParams` gains `audience` (sent as `audience`) and `idTokenHint` (sent as `id_token_hint`); both are exposed on the sign-in/sign-up flows and on the `<SignIn>`/`<SignUp>` components, and are accepted as query-param overrides on the Next.js sign-in route.
  - Sign-out now accepts a manual `idTokenHint` (on `signOut()` options, the `<SignOut>` components, and the Next.js sign-out route) which overrides the ID token from the current session as the `id_token_hint`.
  - `Authenticators`, `Prompt`, and `DisplayOptions` now accept any string in addition to the documented values (open string unions), so custom authenticators/prompts/display modes can be passed.

  **Breaking:** `EndSessionParameters.idToken` is renamed to `idTokenHint` for consistency; node-core's `SignOutOptions` exposes `idTokenHint` (the previously inherited, no-op `idToken` field is removed).

- c462f08: Require Node.js >= 20. This matches the minimum Node version already required by the SDKs' dependencies (e.g. `joi` 18) and the versions tested in CI.

### Patch Changes

- c462f08: Update dependency package versions
- c462f08: Fix `` `cookies`/`headers` was called outside a request scope `` thrown by `getSession()`/`getTokens()` in App Router Server Components and Route Handlers on Next.js 16. The build was rewriting `next/headers` to `next/headers.js`, and Next.js 16 / Turbopack only bind `cookies()`/`headers()` to the request scope for the exact `next/headers` specifier. `next/*` subpaths are now emitted as bare external specifiers.
- Updated dependencies [34e8a50]
- Updated dependencies [c462f08]
- Updated dependencies [c462f08]
- Updated dependencies [c462f08]
  - @monocloud/auth-core@0.2.0
  - @monocloud/auth-node-core@0.2.0

## 0.1.20

### Patch Changes

- Updated dependencies [69ff518]
  - @monocloud/auth-core@0.1.15
  - @monocloud/auth-node-core@0.1.19

## 0.1.19

### Patch Changes

- 766e7f3: - Resolve the claim from the core option at the group-check call sites
  instead of reading `process.env` directly; the standalone `isUserInGroup`
  method defers to node-core's resolution. `NEXT_PUBLIC_MONOCLOUD_AUTH_GROUPS_CLAIM`
  is unchanged for client components.
- Updated dependencies [766e7f3]
- Updated dependencies [766e7f3]
  - @monocloud/auth-node-core@0.1.18
  - @monocloud/auth-core@0.1.14

## 0.1.18

### Patch Changes

- Updated dependencies [e69c256]
  - @monocloud/auth-node-core@0.1.17
  - @monocloud/auth-core@0.1.13

## 0.1.17

### Patch Changes

- Updated dependencies [6d595b2]
  - @monocloud/auth-node-core@0.1.16
  - @monocloud/auth-core@0.1.12

## 0.1.16

### Patch Changes

- d4a07a0: Update dependency package versions
- Updated dependencies [d4a07a0]
  - @monocloud/auth-node-core@0.1.15
  - @monocloud/auth-core@0.1.11

## 0.1.15

### Patch Changes

- Updated dependencies [0bfdf86]
  - @monocloud/auth-node-core@0.1.14
  - @monocloud/auth-core@0.1.10

## 0.1.14

### Patch Changes

- Updated dependencies [fdf0a05]
  - @monocloud/auth-core@0.1.9
  - @monocloud/auth-node-core@0.1.13

## 0.1.13

### Patch Changes

- 353048d: Use 307 redirect and no-cache for auth endpoints
- Updated dependencies [353048d]
  - @monocloud/auth-node-core@0.1.12

## 0.1.12

### Patch Changes

- Updated dependencies [f3f475a]
  - @monocloud/auth-core@0.1.8
  - @monocloud/auth-node-core@0.1.11

## 0.1.11

### Patch Changes

- f20edaa: - Update SDK Reference link in README.md
  - Added `"use client";` to Next.js <Protected/> component
- f20edaa: - Added `refetchUserInfo` option to `getSession()` which will fetch the user profile from userinfo endpoint and update the session.
- f20edaa: - Implement `strictProfileSync` option for syncing the user profile during session refresh.
- Updated dependencies [f20edaa]
- Updated dependencies [f20edaa]
  - @monocloud/auth-node-core@0.1.10
  - @monocloud/auth-core@0.1.7

## 0.1.10

### Patch Changes

- Updated dependencies [855e1b9]
  - @monocloud/auth-node-core@0.1.9

## 0.1.9

### Patch Changes

- Updated dependencies [1d4ba47]
  - @monocloud/auth-node-core@0.1.8

## 0.1.8

### Patch Changes

- 7a24686: Fixes incosistency when setting options.scope and options.resource
- 7a24686: Improve comments and descriptions
- Updated dependencies [7a24686]
  - @monocloud/auth-node-core@0.1.7
  - @monocloud/auth-core@0.1.6

## 0.1.7

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

- Updated dependencies [d1dedf5]
  - @monocloud/auth-node-core@0.1.6
  - @monocloud/auth-core@0.1.5

## 0.1.6

### Patch Changes

- abc0bc5: Renamed groupFallback to onGroupAccessDenied
- abc0bc5: Updated packages
- 1a22540: Updated Readme files
- abc0bc5: - **Fix:** Resolved Edge Runtime compatibility issues by removing `node:http` imports and implementing safe duck-typing for Node.js request/response checks.
- Updated dependencies [abc0bc5]
- Updated dependencies [1a22540]
  - @monocloud/auth-node-core@0.1.5

## 0.1.5

### Patch Changes

- 8f223c5: - Split the single onAccessDenied callback into distinct handlers for unauthenticated vs unauthorized (group) scenarios across server-side APIs, SSR pages, and middleware
  - Add onGroupAccessDenied for server-side (App Router, Page Router, middleware) — receives the authenticated user object, only fires on group check failures
  - Rename client-side onAccessDenied to fallback / groupFallback for the protectPage HOC and <Protected> component
  - Added tests: group fallback behavior, priority of onGroupAccessDenied over onAccessDenied, no fallback leakage between auth and group denial paths
  - Update getSession Page Router doc example with improved typing (satisfies GetServerSideProps)

## 0.1.4

### Patch Changes

- 05568e9: - Fixed an error where Next.js Request was created incorrectly that throws an error on Node.js 24
  - Added duplex property to Next.js Request creation in utils to support Node.js streaming response
  - Refactored Next.js response creation from raw response
  - Added tests for the utils method `getNextRequest()` and `getNextResponse()`
- 05568e9: - Added matrix testing for all packages on Node.js version 20, 22, and 24.
- 05568e9: - Moved vitest reporter to the respective configs.
  - Added default reporter back to see the test results.
- Updated dependencies [05568e9]
- Updated dependencies [05568e9]
  - @monocloud/auth-node-core@0.1.4

## 0.1.3

### Patch Changes

- 21a411c: Added documentation links to README.md
- Updated dependencies [21a411c]
  - @monocloud/auth-node-core@0.1.3

## 0.1.2

### Patch Changes

- e8912d0: Removed getRoute() method from MonoCloudRequest interface
- e8912d0: Added docs
- e8912d0: Added support for raw Request and Response
- e8912d0: Fixed import errors (could not find 'next/server') errors for page router applications
- Updated dependencies [e8912d0]
  - @monocloud/auth-node-core@0.1.2

## 0.1.1

### Patch Changes

- be680ec: Bump Release
- Updated dependencies [be680ec]
  - @monocloud/auth-node-core@0.1.1

## 0.1.0

### Minor Changes

- c0e8cd3: Initial Release of SDKs

### Patch Changes

- Updated dependencies [c0e8cd3]
  - @monocloud/auth-node-core@0.1.0
