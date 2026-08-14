---
'@monocloud/backend-node': patch
---

- introspection cache hits now re-check scopes, groups and certificate binding instead of returning cached claims unvalidated
- `protectApi` 401 and 403 responses now include a `WWW-Authenticate` challenge
- authorization server outages now return `503` and configuration failures return `500`, instead of a misleading `401`
- the 401 vs 403 split is now based on `MonoCloudTokenError.code` instead of error message strings
- tokens requiring introspection now fail immediately when no introspection credentials are configured
- `protectApi` now trims the token returned by a custom `tokenResolver`
