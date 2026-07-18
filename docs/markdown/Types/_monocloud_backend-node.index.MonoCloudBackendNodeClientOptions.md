---
rootSdk: Node.js Backend
title: "MonoCloudBackendNodeClientOptions"
category: Types
description: "Configuration options for the MonoCloudBackendNodeClient. When both are provided, constructor options override environment variables."
---

# Type: MonoCloudBackendNodeClientOptions

Configuration options for the [MonoCloudBackendNodeClient](/sdks/nodejs-backend/api-reference/classes/monocloudbackendnodeclient).

## Configuration Sources

Configuration values can be provided using either:

- **Constructor options** - passed when creating the client instance.
- **Environment variables** - using `MONOCLOUD_BACKEND_*` variables.

When both are provided, **constructor options override environment variables**.

## Environment Variables

### Core Configuration (Required)

| Environment Variable              | Description                                                                                 |
| --------------------------------- | ------------------------------------------------------------------------------------------- |
| `MONOCLOUD_BACKEND_TENANT_DOMAIN` | The domain of your MonoCloud tenant (for example, `https://your-tenant.us.monocloud.com`).  |
| `MONOCLOUD_BACKEND_AUDIENCE`      | The expected audience for access token validation (for example, `https://api.example.com`). |

### Introspection

| Environment Variable                   | Description                                                                                                                                                                                                     |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MONOCLOUD_BACKEND_CLIENT_ID`          | Unique identifier for your application/client.                                                                                                                                                                  |
| `MONOCLOUD_BACKEND_CLIENT_SECRET`      | Application/client secret used for authentication.                                                                                                                                                              |
| `MONOCLOUD_BACKEND_CLIENT_AUTH_METHOD` | Client authentication method (for example, `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth`, `spiffe_jwt`, `spiffe_x509`). |

### Token Validation

| Environment Variable                      | Description                                                                                |
| ----------------------------------------- | ------------------------------------------------------------------------------------------ |
| `MONOCLOUD_BACKEND_CLOCK_SKEW`            | Allowed clock drift (in seconds) when validating token timestamps.                         |
| `MONOCLOUD_BACKEND_CLOCK_TOLERANCE`       | Additional time tolerance (in seconds) for time-based claim validation.                    |
| `MONOCLOUD_BACKEND_INTROSPECT_JWT_TOKENS` | When `true`, JWT tokens are introspected at the server instead of being validated locally. |

### Group Validation

| Environment Variable                 | Description                                                      |
| ------------------------------------ | ---------------------------------------------------------------- |
| `MONOCLOUD_BACKEND_GROUPS_CLAIM`     | The claim name in the token that contains group memberships.     |
| `MONOCLOUD_BACKEND_GROUPS_MATCH_ALL` | When `true`, requires the token to contain all specified groups. |

### Caching

| Environment Variable                        | Description                                                                       |
| ------------------------------------------- | --------------------------------------------------------------------------------- |
| `MONOCLOUD_BACKEND_JWKS_CACHE_DURATION`     | Duration (in seconds) to cache the JSON Web Key Set (JWKS) used to verify tokens. |
| `MONOCLOUD_BACKEND_METADATA_CACHE_DURATION` | Duration (in seconds) to cache the OpenID Connect discovery metadata.             |

## Extends

- [`MonoCloudOidcBackendClientOptions`](/sdks/nodejs-backend/api-reference/types/monocloudoidcbackendclientoptions)

## Properties

| Property                                                    | Type                                                                                                                                                                                 | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `audience`                            | `string`                                                                                                                                                                             | The expected audience URI for access token validation (e.g. `https://api.example.com`).                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `cache?`                                 | [`IIntrospectionCache`](/sdks/nodejs-backend/api-reference/types/iintrospectioncache)                                                                                                        | Optional cache for access token introspection results. Only tokens validated via introspection are cached (opaque tokens, and JWTs when `introspectJwtTokens` is `true`); locally-validated JWTs are not cached.                                                                                                                                                                                                                                                                                                         |
| `clientAuthMethod?`           | [`ClientAuthMethod`](/sdks/nodejs-backend/api-reference/enums/clientauthmethod)                                                                                           | Client authentication method used when communicating with the token endpoint.                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `clientId?`                           | `string`                                                                                                                                                                             | Client identifier of the application registered in MonoCloud.                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `clientSecret?`                   | `string` \| [`Jwk`](/sdks/nodejs-backend/api-reference/types/jwk)                                                                                                                            | Client secret or key material used for client authentication. When `clientAuthMethod` is `client_secret_jwt` and a plain-text secret is provided, the default signing algorithm is `HS256`. To use a different algorithm, provide a symmetric JSON Web Key (JWK) (`kty: "oct"`) with the desired algorithm specified in its `alg` property. When `clientAuthMethod` is `spiffe_jwt`, provide the SPIFFE JWT-SVID (obtained from the SPIFFE Workload API) as the plain-text string; it is sent as the `client_assertion`. |
| `clockSkew?`                         | `number`                                                                                                                                                                             | Number of seconds to adjust the current time to account for clock differences.                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `clockTolerance?`               | `number`                                                                                                                                                                             | Additional time tolerance in seconds for time-based claim validation.                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `fetcher?`                             | \{(`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`): `Promise`\<`Response`\>; (`input`: `string` \| `URL` \| `Request`, `init?`: `RequestInit`): `Promise`\<`Response`\>; \} | Optional custom `fetch` implementation used for network requests.                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `groupOptions?`                   | [`IsUserInGroupOptions`](/sdks/nodejs-backend/api-reference/types/isuseringroupoptions)                                                                                                      | Options for group membership validation applied to all token validations performed by this client.                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `introspectJwtTokens?`     | `boolean`                                                                                                                                                                            | When `true`, JWT access tokens are introspected instead of locally validated. This skips JWT signature/header/payload checks and always uses the introspection endpoint.                                                                                                                                                                                                                                                                                                                                                 |
| `jwksCacheDuration?`         | `number`                                                                                                                                                                             | Duration (in seconds) to cache the JSON Web Key Set (JWKS) retrieved from the authorization server.                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `metadataCacheDuration?` | `number`                                                                                                                                                                             | Duration (in seconds) to cache OpenID Connect discovery metadata.                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `tenantDomain`                    | `string`                                                                                                                                                                             | The MonoCloud tenant domain URL (e.g. `https://example.monocloud.dev`).                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
