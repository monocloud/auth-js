---
'@monocloud/auth-core': patch
---

- added a `raw` property to every error raised from an unsuccessful HTTP response, exposing the response `status`, `statusText`, `headers` and unparsed `body`. Repeated headers are combined into a single comma-separated value and `set-cookie` is excluded.
- a `401` from the introspection endpoint is now reported as `invalid_client` rather than a generic `introspection_failed`, per RFC 6749 §5.2
- a standard OAuth error body is now read from a `401` as well as a `400` at the pushed authorization, token, refresh, revocation and device endpoints, instead of being discarded
- error responses whose body is empty or is not JSON no longer fail with a parse error; they fall back to the endpoint's standard error code
- a failed userinfo request now raises a `MonoCloudTokenError` instead of a `MonoCloudOPError`, since it describes the presented token. `403` responses are now handled as `insufficient_scope`, and a `401` without a `WWW-Authenticate` challenge no longer surfaces as an unexpected status code
