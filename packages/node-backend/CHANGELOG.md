# @monocloud/backend-node

## 0.3.4

### Patch Changes

- 1590a33: Remove the `delete` method from the `IIntrospectionCache` interface. The introspection cache is only ever read from (`get`) and written to (`set`) — the SDK never called `delete` — so requiring implementers to provide it (and enforcing it in options validation) served no purpose. Custom cache adapters no longer need a `delete` method; adapters that still implement one remain compatible.

## 0.3.3

### Patch Changes

- 001e0ce: Add support for mTLS endpoint aliases and per-trust-store ("additional") mTLS endpoint aliases from the OpenID Connect discovery document (RFC 8705).

  - When a client authenticates with a mutual-TLS client authentication method (`tls_client_auth`, `self_signed_tls_client_auth`, or `spiffe_x509`), the token, revocation, introspection, device authorization, and pushed authorization request (PAR) endpoints are now resolved from `mtls_endpoint_aliases` in the issuer metadata. If no matching alias is published, a `MonoCloudValidationError` is thrown rather than silently falling back to the regular endpoint.
  - New `trustStoreId` option selects a specific trust store's endpoints from `mtls_additional_endpoint_aliases`.
  - New `metadataResolver` option supplies the issuer metadata out-of-band — for example, mTLS endpoint aliases for a private/hidden trust store that is not published in the tenant's public discovery document.
  - New `jwksResolver` option supplies the JSON Web Key Set out-of-band — for example, signing keys for a private trust store that is not published in the tenant's public JWKS.
  - `@monocloud/auth-node-core` now forwards `clientAuthMethod`, `trustStoreId`, `metadataResolver`, `fetcher`, and the (previously resolved but unused) `jwksCacheDuration` / `metadataCacheDuration` to the underlying OIDC client. New env vars: `MONOCLOUD_AUTH_CLIENT_AUTH_METHOD`, `MONOCLOUD_AUTH_TRUST_STORE_ID`. `@monocloud/backend-node` adds `MONOCLOUD_BACKEND_TRUST_STORE_ID`.
  - `clientSecret` in `@monocloud/auth-node-core` and `@monocloud/backend-node` now accepts a JWK for `private_key_jwt` — supply it as a JSON string in `MONOCLOUD_AUTH_CLIENT_SECRET` / `MONOCLOUD_BACKEND_CLIENT_SECRET` (or as an object programmatically) and it is parsed and validated automatically. Previously the client secret was always treated as a plain string, so `private_key_jwt` could not be configured through these SDKs.

- Updated dependencies [001e0ce]
  - @monocloud/auth-core@0.2.3

## 0.3.2

### Patch Changes

- a214087: Correct stale README content: supported Node.js/Next.js/React version floors now match the enforced `engines`/`peerDependencies` ranges, the core feature list includes the Device Authorization Grant, the backend caching bullet is scoped to introspection results, `getSession()` is documented as returning `undefined` when signed out, and the web-js README gains Quickstart/SDK Reference links.
- Updated dependencies [a214087]
  - @monocloud/auth-core@0.2.2

## 0.3.1

### Patch Changes

- Updated dependencies [22835a3]
  - @monocloud/auth-core@0.2.1

## 0.3.0

### Minor Changes

- c462f08: Require Node.js >= 20. This matches the minimum Node version already required by the SDKs' dependencies (e.g. `joi` 18) and the versions tested in CI.
- c462f08: Add SPIFFE client authentication methods `spiffe_jwt` and `spiffe_x509` to `clientAuthMethod`.

  - `spiffe_x509` authenticates via mutual TLS using an X.509-SVID (presented at the TLS transport layer, the same as `tls_client_auth`).
  - `spiffe_jwt` sends a SPIFFE JWT-SVID (obtained from the SPIFFE Workload API and provided as the `clientSecret` string) as the `client_assertion`, with `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`.

### Patch Changes

- c462f08: Update dependency package versions
- Updated dependencies [34e8a50]
- Updated dependencies [c462f08]
- Updated dependencies [c462f08]
  - @monocloud/auth-core@0.2.0

## 0.2.0

### Minor Changes

- 3299765: - Rename the `ICache` interface to `IIntrospectionCache` and cache only introspection results.

## 0.1.9

### Patch Changes

- Updated dependencies [69ff518]
  - @monocloud/auth-core@0.1.15

## 0.1.8

### Patch Changes

- Updated dependencies [766e7f3]
  - @monocloud/auth-core@0.1.14

## 0.1.7

### Patch Changes

- e69c256: - Validate at_hash and s_hash id token claims in the implicit flow
  - Make clockTolerance configurable in node-cre and default clockSkew to 0, clockTolerance to 60
- Updated dependencies [e69c256]
  - @monocloud/auth-core@0.1.13

## 0.1.6

### Patch Changes

- 6d595b2: Parse scope from callback params and assorted test/docs fixes
- Updated dependencies [6d595b2]
  - @monocloud/auth-core@0.1.12

## 0.1.5

### Patch Changes

- d4a07a0: Update dependency package versions
- Updated dependencies [d4a07a0]
  - @monocloud/auth-core@0.1.11

## 0.1.4

### Patch Changes

- a0e6b6d: - Add comprehensive test suite for fastify framework and related utilities
- Updated dependencies [0bfdf86]
  - @monocloud/auth-core@0.1.10

## 0.1.3

### Patch Changes

- 36e1345: Removed node backend client options from Express and Fastify middlewares.

## 0.1.2

### Patch Changes

- fdf0a05: - Rename 'user' to 'claims' in authenticated request types
  - Removed `jti` claim from IdTokenClaims
- Updated dependencies [fdf0a05]
  - @monocloud/auth-core@0.1.9

## 0.1.1

### Patch Changes

- f3f475a: Added Node.js backend SDK with Express and Fastify support
- Updated dependencies [f3f475a]
  - @monocloud/auth-core@0.1.8
