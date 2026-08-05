---
'@monocloud/auth-core': patch
---

- Build the `client_secret_basic` `Authorization` header from the credential's UTF-8 bytes instead of calling `btoa` directly, which threw `InvalidCharacterError` for any client id or secret containing a character outside Latin-1.
- Supplying a JWK as the client secret together with `client_secret_basic` now throws instead of silently sending `[object Object]` as the password.
