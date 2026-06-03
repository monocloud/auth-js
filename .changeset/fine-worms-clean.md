---
'@monocloud/backend-node': patch
'@monocloud/auth-node-core': patch
'@monocloud/auth-web-js': patch
'@monocloud/auth-core': patch
---

- Validate at_hash and s_hash id token claims in the implicit flow
- Make clockTolerance configurable in node-cre and default clockSkew to 0, clockTolerance to 60