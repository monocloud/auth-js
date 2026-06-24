# @monocloud/auth-web-js

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
