---
"@monocloud/auth-core": minor
"@monocloud/backend-node": minor
"@monocloud/auth-node-core": minor
---

Add support for mTLS endpoint aliases and per-trust-store ("additional") mTLS endpoint aliases from the OpenID Connect discovery document (RFC 8705).

- When a client authenticates with a mutual-TLS client authentication method (`tls_client_auth`, `self_signed_tls_client_auth`, or `spiffe_x509`), the token, revocation, introspection, device authorization, and pushed authorization request (PAR) endpoints are now resolved from `mtls_endpoint_aliases` in the issuer metadata. If no matching alias is published, a `MonoCloudValidationError` is thrown rather than silently falling back to the regular endpoint.
- New `trustStoreId` option selects a specific trust store's endpoints from `mtls_additional_endpoint_aliases`.
- New `metadataResolver` option supplies the issuer metadata out-of-band — for example, mTLS endpoint aliases for a private/hidden trust store that is not published in the tenant's public discovery document.
- New `jwksResolver` option supplies the JSON Web Key Set out-of-band — for example, signing keys for a private trust store that is not published in the tenant's public JWKS.
- `@monocloud/auth-node-core` now forwards `clientAuthMethod`, `trustStoreId`, `metadataResolver`, `fetcher`, and the (previously resolved but unused) `jwksCacheDuration` / `metadataCacheDuration` to the underlying OIDC client. New env vars: `MONOCLOUD_AUTH_CLIENT_AUTH_METHOD`, `MONOCLOUD_AUTH_TRUST_STORE_ID`. `@monocloud/backend-node` adds `MONOCLOUD_BACKEND_TRUST_STORE_ID`.
- `clientSecret` in `@monocloud/auth-node-core` and `@monocloud/backend-node` now accepts a JWK for `private_key_jwt` — supply it as a JSON string in `MONOCLOUD_AUTH_CLIENT_SECRET` / `MONOCLOUD_BACKEND_CLIENT_SECRET` (or as an object programmatically) and it is parsed and validated automatically. Previously the client secret was always treated as a plain string, so `private_key_jwt` could not be configured through these SDKs.
