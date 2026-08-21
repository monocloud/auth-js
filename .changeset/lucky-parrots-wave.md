---
'@monocloud/auth-node-core': patch
---

- `backChannelLogout()` now answers a missing or invalid Logout Token with `400 Bad Request` (with an `{ error, error_description }` body) instead of `500`, per the Back-Channel Logout spec. `500` is reserved for configuration, discovery/JWKS, and callback failures.
- `backChannelLogout()` now accepts an options argument with an `onError` callback, matching the other handlers. Invalid logout tokens reach it as a `MonoCloudTokenError`. Exported the new `BackChannelLogoutOptions` type.
- logout token verification moved to `@monocloud/auth-core`'s `validateLogoutToken()`; the `jose` dependency was removed and the JWKS now honors a configured `jwksResolver` and the shared cache.
- replaced the `uuid` dependency with the built-in `crypto.randomUUID()` for session store keys.
