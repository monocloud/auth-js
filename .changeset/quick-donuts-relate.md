---
'@monocloud/auth-core': patch
'@monocloud/backend-node': patch
---

- JWT access token validation no longer rejects tokens based on the `typ` header. Previously any token with a `typ` other than `at+jwt` was rejected with an `Invalid token type` error. This relaxes the tokens accepted by `protectApi()`; all other validation (issuer, audience, expiry, algorithm and signature) is unchanged.
