---
rootSdk: Node.js Backend
title: "MonoCloudBackendNodeClient"
category: Classes
framework: Fastify
description: "Backend client for validating access tokens in Node.js server applications."
---

# Class: MonoCloudBackendNodeClient

Backend client for validating access tokens in Node.js server applications.

Extends the core OIDC backend client with caching support and automatic
detection of JWT vs. opaque token formats.

## Extends

- [`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient)

## clockSkew

> `protected` **clockSkew**: `number` = `0`

Number of seconds to adjust the current time to account for clock differences between the client and server during time-based claim validation. Defaults to 0.

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`clockSkew`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#clockskew)

---

## clockTolerance

> `protected` **clockTolerance**: `number` = `300`

Additional time tolerance in seconds applied when validating time-based claims (`exp`, `nbf`). Defaults to 300 (5 minutes).

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`clockTolerance`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#clocktolerance)

---

## Constructor

> **new MonoCloudBackendNodeClient**(`options?`: `Partial`\<[`MonoCloudBackendNodeClientOptions`](/sdks/fastify-backend/api-reference/types/monocloudbackendnodeclientoptions)\>): [`MonoCloudBackendNodeClient`](/sdks/fastify-backend/api-reference/classes/monocloudbackendnodeclient)

Creates a new instance of MonoCloudBackendNodeClient.

### Parameters

| Parameter  | Type                                                                                                                            | Description                                                                                   |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `options?` | `Partial`\<[`MonoCloudBackendNodeClientOptions`](/sdks/fastify-backend/api-reference/types/monocloudbackendnodeclientoptions)\> | Client configuration options. When omitted, configuration is read from environment variables. |

### Returns

[`MonoCloudBackendNodeClient`](/sdks/fastify-backend/api-reference/classes/monocloudbackendnodeclient)

### Overrides

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`constructor`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#constructor)

---

## decodeJwt()

> `static` **decodeJwt**(`jwt`: `string`): [`JwtClaims`](/sdks/fastify-backend/api-reference/types/jwtclaims)

Decodes the payload of a JSON Web Token (JWT) and returns it as an object.

> Note: THIS METHOD DOES NOT VERIFY JWT TOKENS.

### Parameters

| Parameter | Type     | Description    |
| --------- | -------- | -------------- |
| `jwt`     | `string` | JWT to decode. |

### Returns

[`JwtClaims`](/sdks/fastify-backend/api-reference/types/jwtclaims)

Decoded payload.

### Throws

[MonoCloudTokenError](/sdks/fastify-backend/api-reference/error-classes/monocloudtokenerror) - If decoding fails

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`decodeJwt`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#decodejwt)

---

## fetcher()?

> `protected` `optional` **fetcher**: \{(`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`): `Promise`\<`Response`\>; (`input`: `string` \| `URL` \| `Request`, `init?`: `RequestInit`): `Promise`\<`Response`\>; \}

Custom fetch implementation used for making HTTP requests. Falls back to the global `fetch` if not provided.

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

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`fetcher`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#fetcher)

---

## getJwks()

> **getJwks**(`forceRefresh`: `boolean`): `Promise`\<[`Jwks`](/sdks/fastify-backend/api-reference/types/jwks)\>

Fetches the JSON Web Keys used to sign the ID token.
The JWKS is cached for 5 minutes by default.

### Parameters

| Parameter      | Type      | Description                                                                  |
| -------------- | --------- | ---------------------------------------------------------------------------- |
| `forceRefresh` | `boolean` | If `true`, bypasses the cache and fetches fresh set of JWKS from the server. |

### Returns

`Promise`\<[`Jwks`](/sdks/fastify-backend/api-reference/types/jwks)\>

The JSON Web Key Set containing the public keys for token verification.

### Throws

[MonoCloudHttpError](/sdks/fastify-backend/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`getJwks`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#getjwks)

---

## getMetadata()

> **getMetadata**(`forceRefresh`: `boolean`): `Promise`\<[`IssuerMetadata`](/sdks/fastify-backend/api-reference/types/issuermetadata)\>

Fetches the authorization server metadata from the .well-known endpoint.
The metadata is cached for 5 minutes by default.

### Parameters

| Parameter      | Type      | Description                                                               |
| -------------- | --------- | ------------------------------------------------------------------------- |
| `forceRefresh` | `boolean` | If `true`, bypasses the cache and fetches fresh metadata from the server. |

### Returns

`Promise`\<[`IssuerMetadata`](/sdks/fastify-backend/api-reference/types/issuermetadata)\>

The issuer metadata for the tenant, retrieved from the OpenID Connect discovery endpoint.

### Throws

[MonoCloudHttpError](/sdks/fastify-backend/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`getMetadata`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#getmetadata)

---

## introspectAccessToken()

> **introspectAccessToken**(`accessToken`: `string`, `options?`: [`IntrospectOptions`](/sdks/fastify-backend/api-reference/types/introspectoptions)): `Promise`\<[`AccessTokenClaims`](/sdks/fastify-backend/api-reference/types/accesstokenclaims)\>

Validates an opaque access token using the OAuth 2.0 Token Introspection endpoint (RFC 7662).

### Parameters

| Parameter     | Type                                                                               | Description                            |
| ------------- | ---------------------------------------------------------------------------------- | -------------------------------------- |
| `accessToken` | `string`                                                                           | The access token string to introspect. |
| `options?`    | [`IntrospectOptions`](/sdks/fastify-backend/api-reference/types/introspectoptions) | Claims validation options.             |

### Returns

`Promise`\<[`AccessTokenClaims`](/sdks/fastify-backend/api-reference/types/accesstokenclaims)\>

Validated access token claims (without the `active` field).

### Throws

[MonoCloudTokenError](/sdks/fastify-backend/api-reference/error-classes/monocloudtokenerror) - If the token is not active or claim validation fails.

### Throws

[MonoCloudOPError](/sdks/fastify-backend/api-reference/error-classes/monocloudoperror) - When the introspection endpoint returns a standardized
OAuth 2.0 error response.

### Throws

[MonoCloudHttpError](/sdks/fastify-backend/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

### Throws

[MonoCloudValidationError](/sdks/fastify-backend/api-reference/error-classes/monocloudvalidationerror) - When the access token is empty or the introspection
endpoint is not available in the issuer metadata or claims validation fails.

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`introspectAccessToken`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#introspectaccesstoken)

---

## jwks?

> `protected` `optional` **jwks**: [`Jwks`](/sdks/fastify-backend/api-reference/types/jwks)

Cached JSON Web Key Set retrieved from the issuer's JWKS endpoint.

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`jwks`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#jwks)

---

## jwksCacheDuration

> `protected` **jwksCacheDuration**: `number` = `300`

Duration (in seconds) for which the JWKS is cached. Defaults to 300 (5 minutes).

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`jwksCacheDuration`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#jwkscacheduration)

---

## jwksCacheExpiry

> `protected` **jwksCacheExpiry**: `number` = `0`

Timestamp (in seconds) when the cached JWKS expires.

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`jwksCacheExpiry`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#jwkscacheexpiry)

---

## metadata?

> `protected` `optional` **metadata**: [`IssuerMetadata`](/sdks/fastify-backend/api-reference/types/issuermetadata)

Cached issuer metadata retrieved from the OpenID Connect discovery endpoint.

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`metadata`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#metadata)

---

## metadataCacheDuration

> `protected` **metadataCacheDuration**: `number` = `300`

Duration (in seconds) for which the metadata is cached. Defaults to 300 (5 minutes).

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`metadataCacheDuration`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#metadatacacheduration)

---

## metadataCacheExpiry

> `protected` **metadataCacheExpiry**: `number` = `0`

Timestamp (in seconds) when the cached metadata expires.

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`metadataCacheExpiry`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#metadatacacheexpiry)

---

## setClockSkew()

> **setClockSkew**(`clockSkew`: `number`): `void`

Sets clock skew used for access token time-based claim validation.

### Parameters

| Parameter   | Type     | Description                                                                    |
| ----------- | -------- | ------------------------------------------------------------------------------ |
| `clockSkew` | `number` | Number of seconds to adjust the current time to account for clock differences. |

### Returns

`void`

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`setClockSkew`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#setclockskew)

---

## setClockTolerance()

> **setClockTolerance**(`clockTolerance`: `number`): `void`

Sets clock tolerance used for access token time-based claim validation.

### Parameters

| Parameter        | Type     | Description                                                           |
| ---------------- | -------- | --------------------------------------------------------------------- |
| `clockTolerance` | `number` | Additional time tolerance in seconds for time-based claim validation. |

### Returns

`void`

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`setClockTolerance`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#setclocktolerance)

---

## tenantDomain

> `protected` `readonly` **tenantDomain**: `string`

The normalized tenant domain URL used as the base for discovery endpoints.

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`tenantDomain`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#tenantdomain)

---

## validateAccessToken()

> **validateAccessToken**(`accessToken`: `string`, `options?`: [`ValidateAccessTokenOptions`](/sdks/fastify-backend/api-reference/types/validateaccesstokenoptions)): `Promise`\<[`AccessTokenClaims`](/sdks/fastify-backend/api-reference/types/accesstokenclaims)\>

Validates an access token by automatically detecting its format.

### Parameters

| Parameter     | Type                                                                                                 | Description                          |
| ------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `accessToken` | `string`                                                                                             | The access token string to validate. |
| `options?`    | [`ValidateAccessTokenOptions`](/sdks/fastify-backend/api-reference/types/validateaccesstokenoptions) | Validation options.                  |

### Returns

`Promise`\<[`AccessTokenClaims`](/sdks/fastify-backend/api-reference/types/accesstokenclaims)\>

Validated access token claims.

### Throws

[MonoCloudValidationError](/sdks/fastify-backend/api-reference/error-classes/monocloudvalidationerror) - When the access token is empty.

### Throws

[MonoCloudTokenError](/sdks/fastify-backend/api-reference/error-classes/monocloudtokenerror) - If token validation fails.

### Throws

[MonoCloudOPError](/sdks/fastify-backend/api-reference/error-classes/monocloudoperror) - When the introspection endpoint returns a standardized
OAuth 2.0 error response.

### Throws

[MonoCloudHttpError](/sdks/fastify-backend/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

---

## validateJwtAccessToken()

> **validateJwtAccessToken**(`accessToken`: `string`, `options?`: [`ValidateJwtAccessTokenOptions`](/sdks/fastify-backend/api-reference/types/validatejwtaccesstokenoptions)): `Promise`\<[`AccessTokenClaims`](/sdks/fastify-backend/api-reference/types/accesstokenclaims)\>

Validates a JWT access token by verifying the signature and claims.

### Parameters

| Parameter     | Type                                                                                                       | Description                              |
| ------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `accessToken` | `string`                                                                                                   | The access token JWT string to validate. |
| `options?`    | [`ValidateJwtAccessTokenOptions`](/sdks/fastify-backend/api-reference/types/validatejwtaccesstokenoptions) | Validation options.                      |

### Returns

`Promise`\<[`AccessTokenClaims`](/sdks/fastify-backend/api-reference/types/accesstokenclaims)\>

Validated access token claims.

### Throws

[MonoCloudTokenError](/sdks/fastify-backend/api-reference/error-classes/monocloudtokenerror) - If JWT parsing, signature verification, or claim validation fails.

### Throws

[MonoCloudHttpError](/sdks/fastify-backend/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

### Throws

[MonoCloudValidationError](/sdks/fastify-backend/api-reference/error-classes/monocloudvalidationerror) - When the access token is empty or claims validation fails.

### Inherited from

[`MonoCloudOidcBackendClient`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient).[`validateJwtAccessToken`](/sdks/fastify-backend/api-reference/classes/monocloudoidcbackendclient#validatejwtaccesstoken)
