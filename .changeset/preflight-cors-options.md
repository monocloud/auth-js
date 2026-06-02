---
'@monocloud/auth-node-core': minor
'@monocloud/auth-nextjs': minor
---

feat: handle CORS preflight (`OPTIONS`) requests on the built-in auth endpoints (`signin`, `callback`, `userinfo`, `signout`)

A genuine CORS preflight (an `OPTIONS` request carrying an `Access-Control-Request-Method` header) is now answered with `204 No Content` and the appropriate `Access-Control-*` headers, without running the auth flow, instead of returning `405 Method Not Allowed`. A bare `OPTIONS` request (without the preflight header) still returns `405`.

To support this, `getHeader(name)` was added to `MonoCloudRequest` and `setHeader(name, value)` to `MonoCloudResponse`.
