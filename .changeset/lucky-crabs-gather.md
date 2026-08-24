---
'@monocloud/auth-core': patch
---

- `introspectAccessToken()` now throws the new `inactive_token` error code when the authorization server reports `active: false`.
