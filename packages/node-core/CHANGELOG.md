# @monocloud/auth-node-core

## 0.1.16

### Patch Changes

- 6d595b2: Parse scope from callback params and assorted test/docs fixes
- Updated dependencies [6d595b2]
  - @monocloud/auth-core@0.1.12

## 0.1.15

### Patch Changes

- d4a07a0: Update dependency package versions
- Updated dependencies [d4a07a0]
  - @monocloud/auth-core@0.1.11

## 0.1.14

### Patch Changes

- 0bfdf86: Floor unix timestamps, return refreshed user from userinfo, correct scopes length check
- Updated dependencies [0bfdf86]
  - @monocloud/auth-core@0.1.10

## 0.1.13

### Patch Changes

- Updated dependencies [fdf0a05]
  - @monocloud/auth-core@0.1.9

## 0.1.12

### Patch Changes

- 353048d: Use 307 redirect and no-cache for auth endpoints

## 0.1.11

### Patch Changes

- Updated dependencies [f3f475a]
  - @monocloud/auth-core@0.1.8

## 0.1.10

### Patch Changes

- f20edaa: - Added `refetchUserInfo` option to `getSession()` which will fetch the user profile from userinfo endpoint and update the session.
- f20edaa: - Implement `strictProfileSync` option for syncing the user profile during session refresh.
- Updated dependencies [f20edaa]
  - @monocloud/auth-core@0.1.7

## 0.1.9

### Patch Changes

- 855e1b9: - Rename userInfo to fetchUserInfo across the codebase

## 0.1.8

### Patch Changes

- 1d4ba47: Handle missing refresh token error when access token is expired

## 0.1.7

### Patch Changes

- 7a24686: Improve comments and descriptions
- Updated dependencies [7a24686]
  - @monocloud/auth-core@0.1.6

## 0.1.6

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
  - @monocloud/auth-core@0.1.5

## 0.1.5

### Patch Changes

- abc0bc5: Updated packages
- 1a22540: Updated Readme files
- Updated dependencies [abc0bc5]
- Updated dependencies [1a22540]
  - @monocloud/auth-core@0.1.4

## 0.1.4

### Patch Changes

- 05568e9: - Added matrix testing for all packages on Node.js version 20, 22, and 24.
- 05568e9: - Moved vitest reporter to the respective configs.
  - Added default reporter back to see the test results.
- Updated dependencies [05568e9]
- Updated dependencies [05568e9]
- Updated dependencies [05568e9]
  - @monocloud/auth-core@0.1.3

## 0.1.3

### Patch Changes

- 21a411c: Added documentation links to README.md
- Updated dependencies [21a411c]
  - @monocloud/auth-core@0.1.2

## 0.1.2

### Patch Changes

- e8912d0: Removed getRoute() method from MonoCloudRequest interface

## 0.1.1

### Patch Changes

- be680ec: Bump Release
- Updated dependencies [be680ec]
  - @monocloud/auth-core@0.1.1

## 0.1.0

### Minor Changes

- c0e8cd3: Initial Release of SDKs

### Patch Changes

- Updated dependencies [c0e8cd3]
  - @monocloud/auth-core@0.1.0
