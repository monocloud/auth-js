---
'@monocloud/backend-node': patch
---

- `validateCertificateBinding` is now a client option (`MONOCLOUD_BACKEND_VALIDATE_CERTIFICATE_BINDING`) taking `'when_present'` (default), `'required'`, or `'dangerously_ignore'`, and is removed from `ProtectOptions`; tokens carrying a `cnf` claim are now validated by default.
- introspection results are cached as soon as they are returned; scope, group, and certificate binding checks run per route on the cached claims.
- added `introspectionCacheDuration` (`MONOCLOUD_BACKEND_INTROSPECTION_CACHE_DURATION`, default 300 seconds), capping cached claims and also caching `active: false` verdicts; `0` disables caching.
