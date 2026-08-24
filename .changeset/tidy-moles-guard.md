---
'@monocloud/backend-node': patch
---

- added a `responseTimeout` option and `MONOCLOUD_BACKEND_RESPONSE_TIMEOUT` environment variable, defaulting to `10000` milliseconds, bounding the discovery, JWKS, and introspection requests made while validating an access token.
