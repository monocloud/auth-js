# @monocloud/auth-nextjs

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
