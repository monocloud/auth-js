---
rootSdk: Node.js Backend
title: "MonoCloudBackendNodeClientOptions"
category: Types
framework: Express
description: "Configuration options for the MonoCloudBackendNodeClient. When both are provided, constructor options override environment variables."
---

# Type: MonoCloudBackendNodeClientOptions

Configuration options for the [MonoCloudBackendNodeClient](/sdks/express-backend/api-reference/classes/monocloudbackendnodeclient).

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

| Environment Variable                   | Description                                                                                                                                                                 |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MONOCLOUD_BACKEND_CLIENT_ID`          | Unique identifier for your application/client.                                                                                                                              |
| `MONOCLOUD_BACKEND_CLIENT_SECRET`      | Application/client secret used for authentication. When `clientAuthMethod` is `private_key_jwt`, provide the private key JWK as a JSON string (it is parsed automatically). |
| `MONOCLOUD_BACKEND_CLIENT_AUTH_METHOD` | Client authentication method.                                                                                                                                               |

### mTLS

| Environment Variable               | Description                                                                                                                                                                                                                                   |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MONOCLOUD_BACKEND_TRUST_STORE_ID` | Identifier of the trust store whose mTLS endpoint aliases (`mtls_additional_endpoint_aliases`) should be used when authenticating with a mutual-TLS client authentication method. When omitted, the default `mtls_endpoint_aliases` are used. |

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

- [`MonoCloudOidcBackendClientOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions)

## audience

> **audience**: `string`

The expected audience URI for access token validation (e.g. `https://api.example.com`).

---

## cache
> `optional` **cache**: [`IIntrospectionCache`](/sdks/express-backend/api-reference/types/iintrospectioncache)

Optional cache for access token introspection results. Only tokens validated via
introspection are cached (opaque tokens, and JWTs when `introspectJwtTokens` is `true`);
locally-validated JWTs are not cached.

---

## clientAuthMethod
> `optional` **clientAuthMethod**: [`ClientAuthMethod`](/sdks/express-backend/api-reference/enums/clientauthmethod)

Client authentication method used when the client authenticates to the authorization server.

### Default Value

```ts
"client_secret_basic";
```

### Inherited from

[`MonoCloudOidcBackendClientOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions).[`clientAuthMethod`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions#clientauthmethod)

---

## clientId
> `optional` **clientId**: `string`

Client identifier of the application registered in MonoCloud.

### Inherited from

[`MonoCloudOidcBackendClientOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions).[`clientId`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions#clientid)

---

## clientSecret
> `optional` **clientSecret**: `string` \| [`Jwk`](/sdks/express-backend/api-reference/types/jwk)

Client secret or key material used for client authentication.

When `clientAuthMethod` is `client_secret_jwt` and a plain-text secret is provided, the default signing algorithm is `HS256`.

To use a different algorithm, provide a symmetric JSON Web Key (JWK) (`kty: "oct"`) with the desired algorithm specified in its `alg` property.

When `clientAuthMethod` is `spiffe_jwt`, provide the SPIFFE JWT-SVID (obtained from the SPIFFE Workload API) as the plain-text string; it is sent as the `client_assertion`.

### Inherited from

[`MonoCloudOidcBackendClientOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions).[`clientSecret`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions#clientsecret)

---

## clockSkew
> `optional` **clockSkew**: `number`

Number of seconds to adjust the current time to account for clock differences.

### Default Value

```ts
0;
```

### Inherited from

[`MonoCloudOidcBackendClientOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions).[`clockSkew`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions#clockskew)

---

## clockTolerance
> `optional` **clockTolerance**: `number`

Additional time tolerance (in seconds) applied when validating time-based claims
(`exp` and `nbf`) on access tokens.

### Default Value

```ts
60;
```

### Inherited from

[`MonoCloudOidcBackendClientOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions).[`clockTolerance`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions#clocktolerance)

---

## fetcher
> `optional` **fetcher**: \{(`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`): `Promise`\<`Response`\>; (`input`: `string` \| `URL` \| `Request`, `init?`: `RequestInit`): `Promise`\<`Response`\>; \}

Optional custom `fetch` implementation used for network requests.

### Call Signature

> (`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`): `Promise`\<`Response`\>

[MDN Reference](https://developer.mozilla.org/docs/Web/API/Window/fetch)

#### Parameters

| Parameter | Type                   |
| --------- | ---------------------- |
| `input`   | `URL` \| `RequestInfo` |
| `init?`   | `RequestInit`          |

#### Returns

`Promise`\<`Response`\>

### Call Signature

> (`input`: `string` \| `URL` \| `Request`, `init?`: `RequestInit`): `Promise`\<`Response`\>

[MDN Reference](https://developer.mozilla.org/docs/Web/API/Window/fetch)

#### Parameters

| Parameter | Type                           |
| --------- | ------------------------------ |
| `input`   | `string` \| `URL` \| `Request` |
| `init?`   | `RequestInit`                  |

#### Returns

`Promise`\<`Response`\>

### Inherited from

[`MonoCloudOidcBackendClientOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions).[`fetcher`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions#fetcher)

---

## groupOptions
> `optional` **groupOptions**: [`IsUserInGroupOptions`](/sdks/express-backend/api-reference/types/isuseringroupoptions)

Options for group membership validation applied to all token validations performed by this client.

### Inherited from

[`MonoCloudOidcBackendClientOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions).[`groupOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions#groupoptions)

---

## introspectJwtTokens
> `optional` **introspectJwtTokens**: `boolean`

When `true`, JWT access tokens are introspected instead of locally validated.

This skips JWT signature/header/payload checks and always uses the introspection endpoint.

### Default Value

```ts
false;
```

---

## jwksCacheDuration
> `optional` **jwksCacheDuration**: `number`

Duration (in seconds) to cache the JSON Web Key Set (JWKS) retrieved from the authorization server.

### Default Value

```ts
300;
```

### Inherited from

[`MonoCloudOidcBackendClientOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions).[`jwksCacheDuration`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions#jwkscacheduration)

---

## jwksResolver
> `optional` **jwksResolver**: () => [`Jwks`](/sdks/express-backend/api-reference/types/jwks) \| `Promise`\<[`Jwks`](/sdks/express-backend/api-reference/types/jwks)\>

Optional custom resolver for the JSON Web Key Set (JWKS).

### Returns

[`Jwks`](/sdks/express-backend/api-reference/types/jwks) \| `Promise`\<[`Jwks`](/sdks/express-backend/api-reference/types/jwks)\>

### Inherited from

[`MonoCloudOidcBackendClientOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions).[`jwksResolver`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions#jwksresolver)

---

## metadataCacheDuration
> `optional` **metadataCacheDuration**: `number`

Duration (in seconds) to cache OpenID Connect discovery metadata.

### Default Value

```ts
300;
```

### Inherited from

[`MonoCloudOidcBackendClientOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions).[`metadataCacheDuration`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions#metadatacacheduration)

---

## metadataResolver
> `optional` **metadataResolver**: () => [`IssuerMetadata`](/sdks/express-backend/api-reference/types/issuermetadata) \| `Promise`\<[`IssuerMetadata`](/sdks/express-backend/api-reference/types/issuermetadata)\>

Optional custom resolver for the issuer metadata (OpenID Connect discovery document).

### Returns

[`IssuerMetadata`](/sdks/express-backend/api-reference/types/issuermetadata) \| `Promise`\<[`IssuerMetadata`](/sdks/express-backend/api-reference/types/issuermetadata)\>

### Inherited from

[`MonoCloudOidcBackendClientOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions).[`metadataResolver`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions#metadataresolver)

---

## tenantDomain

> **tenantDomain**: `string`

The MonoCloud tenant domain URL (e.g. `https://example.monocloud.dev`).

---

## trustStoreId
> `optional` **trustStoreId**: `string`

Identifier of the trust store whose mTLS endpoint aliases should be used when
authenticating with a mutual-TLS client authentication method.

### Inherited from

[`MonoCloudOidcBackendClientOptions`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions).[`trustStoreId`](/sdks/express-backend/api-reference/types/monocloudoidcbackendclientoptions#truststoreid)
