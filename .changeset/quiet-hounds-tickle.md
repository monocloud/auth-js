---
'@monocloud/auth-core': patch
'@monocloud/backend-node': patch
'@monocloud/auth-web-js': patch
---

- Compare the certificate binding hash (`cnf` / `x5t#S256`) during access token validation and the ID token `at_hash` / `c_hash` values using a timing safe, non-short-circuiting comparison (matching the semantics of .NET's `CryptographicOperations.FixedTimeEquals` and Go's `crypto/subtle.ConstantTimeCompare`) instead of `===`.
