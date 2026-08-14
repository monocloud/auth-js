---
'@monocloud/auth-core': patch
---

- added a `code` discriminator to `MonoCloudTokenError` (`invalid_token`, `insufficient_scope`, `insufficient_groups`)
- added optional `status` and `statusText` to `MonoCloudHttpError`
- `validateAccessTokenClaims` and `validateCertificateBinding` are now `protected` so subclasses can revalidate cached claims
