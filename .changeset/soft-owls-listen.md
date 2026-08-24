---
'@monocloud/auth-core': patch
---

- added an optional `responseTimeout` (in milliseconds) client option. Requests to the authorization server are aborted once it elapses, throwing `MonoCloudHttpError`.
- `MonoCloudOidcClientBaseOptions` now extends `MonoCloudClientOptionsBase` instead of redeclaring the eight fields they shared. It additionally accepts `clientSecret`, which `MonoCloudOidcClientBase` ignores.
