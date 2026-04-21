---
'@monocloud/backend-node': patch
'@monocloud/auth-core': patch
---

- Rename 'user' to 'claims' in authenticated request types
- Removed `jti` claim from IdTokenClaims
