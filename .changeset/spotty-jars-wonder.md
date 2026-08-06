---
'@monocloud/auth-core': patch
---

- Keep the cached issuer metadata and JSON Web Key Set when a forced refresh (`getMetadata(true)` / `getJwks(true)`) fails.