---
'@monocloud/auth-web-js': patch
---

Refine sign-out and redirect URI handling in `@monocloud/auth-web-js`:

- Renamed the `signOutCallbackPath` option to `signOutPath`.
- Made `appUrl` optional; it now defaults to the current page's origin (`window.location.origin`).
- Sign-out now always sends a `post_logout_redirect_uri`, defaulting to the app root when `signOutPath` is not set (mirroring how `callbackPath` defaults to the root for sign-in).
- Redirect and post-logout redirect URIs now have any trailing slash trimmed, and callback URL matching in `processCallback()` trims trailing slashes too, so they compare consistently.
