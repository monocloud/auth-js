---
'@monocloud/auth-core': patch
---

- added `validateLogoutToken()` to `MonoCloudOidcClient` for validating OpenID Connect Back-Channel Logout Tokens, throwing `MonoCloudTokenError` on failure. Exported the new `LogoutTokenClaims` type.
