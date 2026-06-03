---
rootSdk: Node.js
title: "MonoCloudOidcBackendClient"
category: Classes
description: "MonoCloudOidcBackendClient is a class in the MonoCloud Node.js SDK."
---

# Class: MonoCloudOidcBackendClient

## Extends

- [`MonoCloudOidcClientBase`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase)

## Constructors

### Constructor

> **new MonoCloudOidcBackendClient**(`tenantDomain`: `string`, `audience`: `string`, `options?`: [`MonoCloudOidcBackendClientOptions`](/sdks/nodejs/api-reference/types/monocloudoidcbackendclientoptions)): `MonoCloudOidcBackendClient`

Creates a new instance of MonoCloudOidcBackendClient.

#### Parameters

| Parameter      | Type                                                                                                            | Description                                                                    |
| -------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `tenantDomain` | `string`                                                                                                        | The tenant domain URL.                                                         |
| `audience`     | `string`                                                                                                        | The expected audience value used to validate the `aud` claim in access tokens. |
| `options?`     | [`MonoCloudOidcBackendClientOptions`](/sdks/nodejs/api-reference/types/monocloudoidcbackendclientoptions) | Additional client configuration options.                                       |

#### Returns

`MonoCloudOidcBackendClient`

#### Overrides

[`MonoCloudOidcClientBase`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase).[`constructor`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase#constructor)

## Properties

| Property                                                   | Type                                                                                                                                                                                 | Description                                                                                                                                                    |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `clockSkew`                         | `number`                                                                                                                                                                             | Number of seconds to adjust the current time to account for clock differences between the client and server during time-based claim validation. Defaults to 0. |
| `clockTolerance`               | `number`                                                                                                                                                                             | Additional time tolerance in seconds applied when validating time-based claims (`exp`, `nbf`). Defaults to 60 (1 minute).                                      |
| `fetcher?`                            | \{(`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`): `Promise`\<`Response`\>; (`input`: `string` \| `URL` \| `Request`, `init?`: `RequestInit`): `Promise`\<`Response`\>; \} | Custom fetch implementation used for making HTTP requests. Falls back to the global `fetch` if not provided.                                                   |
| `jwks?`                                  | [`Jwks`](/sdks/nodejs/api-reference/types/jwks)                                                                                                                                | Cached JSON Web Key Set retrieved from the issuer's JWKS endpoint.                                                                                             |
| `jwksCacheDuration`         | `number`                                                                                                                                                                             | Duration (in seconds) for which the JWKS is cached. Defaults to 300 (5 minutes).                                                                               |
| `jwksCacheExpiry`             | `number`                                                                                                                                                                             | Timestamp (in seconds) when the cached JWKS expires.                                                                                                           |
| `metadata?`                          | [`IssuerMetadata`](/sdks/nodejs/api-reference/types/issuermetadata)                                                                                                            | Cached issuer metadata retrieved from the OpenID Connect discovery endpoint.                                                                                   |
| `metadataCacheDuration` | `number`                                                                                                                                                                             | Duration (in seconds) for which the metadata is cached. Defaults to 300 (5 minutes).                                                                           |
| `metadataCacheExpiry`     | `number`                                                                                                                                                                             | Timestamp (in seconds) when the cached metadata expires.                                                                                                       |
| `tenantDomain`                   | `string`                                                                                                                                                                             | The normalized tenant domain URL used as the base for discovery endpoints.                                                                                     |

## Methods

### decodeJwt()

> `static` **decodeJwt**(`jwt`: `string`): [`JwtClaims`](/sdks/nodejs/api-reference/types/jwtclaims)

Decodes the payload of a JSON Web Token (JWT) and returns it as an object.

> Note: THIS METHOD DOES NOT VERIFY JWT TOKENS.

#### Parameters

| Parameter | Type     | Description    |
| --------- | -------- | -------------- |
| `jwt`     | `string` | JWT to decode. |

#### Returns

[`JwtClaims`](/sdks/nodejs/api-reference/types/jwtclaims)

Decoded payload.

#### Throws

[MonoCloudTokenError](/sdks/nodejs/api-reference/error-classes/monocloudtokenerror) - If decoding fails

#### Inherited from

[`MonoCloudOidcClientBase`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase).[`decodeJwt`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase#decodejwt)

---

### getJwks()

> **getJwks**(`forceRefresh?`: `boolean`): `Promise`\<[`Jwks`](/sdks/nodejs/api-reference/types/jwks)\>

Fetches the JSON Web Keys used to sign the ID token.
The JWKS is cached for 5 minutes by default.

#### Parameters

| Parameter      | Type      | Description                                                                  |
| -------------- | --------- | ---------------------------------------------------------------------------- |
| `forceRefresh` | `boolean` | If `true`, bypasses the cache and fetches fresh set of JWKS from the server. |

#### Returns

`Promise`\<[`Jwks`](/sdks/nodejs/api-reference/types/jwks)\>

The JSON Web Key Set containing the public keys for token verification.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

#### Inherited from

[`MonoCloudOidcClientBase`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase).[`getJwks`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase#getjwks)

---

### getMetadata()

> **getMetadata**(`forceRefresh?`: `boolean`): `Promise`\<[`IssuerMetadata`](/sdks/nodejs/api-reference/types/issuermetadata)\>

Fetches the authorization server metadata from the .well-known endpoint.
The metadata is cached for 5 minutes by default.

#### Parameters

| Parameter      | Type      | Description                                                               |
| -------------- | --------- | ------------------------------------------------------------------------- |
| `forceRefresh` | `boolean` | If `true`, bypasses the cache and fetches fresh metadata from the server. |

#### Returns

`Promise`\<[`IssuerMetadata`](/sdks/nodejs/api-reference/types/issuermetadata)\>

The issuer metadata for the tenant, retrieved from the OpenID Connect discovery endpoint.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

#### Inherited from

[`MonoCloudOidcClientBase`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase).[`getMetadata`](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase#getmetadata)

---

### introspectAccessToken()

> **introspectAccessToken**(`accessToken`: `string`, `options?`: [`IntrospectOptions`](/sdks/nodejs/api-reference/types/introspectoptions)): `Promise`\<[`AccessTokenClaims`](/sdks/nodejs/api-reference/types/accesstokenclaims)\>

Validates an opaque access token using the OAuth 2.0 Token Introspection endpoint (RFC 7662).

#### Parameters

| Parameter     | Type                                                                            | Description                            |
| ------------- | ------------------------------------------------------------------------------- | -------------------------------------- |
| `accessToken` | `string`                                                                        | The access token string to introspect. |
| `options?`    | [`IntrospectOptions`](/sdks/nodejs/api-reference/types/introspectoptions) | Claims validation options.             |

#### Returns

`Promise`\<[`AccessTokenClaims`](/sdks/nodejs/api-reference/types/accesstokenclaims)\>

Validated access token claims (without the `active` field).

#### Throws

[MonoCloudTokenError](/sdks/nodejs/api-reference/error-classes/monocloudtokenerror) - If the token is not active or claim validation fails.

#### Throws

[MonoCloudOPError](/sdks/nodejs/api-reference/error-classes/monocloudoperror) - When the introspection endpoint returns a standardized
OAuth 2.0 error response.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

#### Throws

[MonoCloudValidationError](/sdks/nodejs/api-reference/error-classes/monocloudvalidationerror) - When the access token is empty or the introspection
endpoint is not available in the issuer metadata or claims validation fails.

---

### setClockSkew()

> **setClockSkew**(`clockSkew`: `number`): `void`

Sets clock skew used for access token time-based claim validation.

#### Parameters

| Parameter   | Type     | Description                                                                    |
| ----------- | -------- | ------------------------------------------------------------------------------ |
| `clockSkew` | `number` | Number of seconds to adjust the current time to account for clock differences. |

#### Returns

`void`

---

### setClockTolerance()

> **setClockTolerance**(`clockTolerance`: `number`): `void`

Sets clock tolerance used for access token time-based claim validation.

#### Parameters

| Parameter        | Type     | Description                                                           |
| ---------------- | -------- | --------------------------------------------------------------------- |
| `clockTolerance` | `number` | Additional time tolerance in seconds for time-based claim validation. |

#### Returns

`void`

---

### validateJwtAccessToken()

> **validateJwtAccessToken**(`accessToken`: `string`, `options?`: [`ValidateJwtAccessTokenOptions`](/sdks/nodejs/api-reference/types/validatejwtaccesstokenoptions)): `Promise`\<[`AccessTokenClaims`](/sdks/nodejs/api-reference/types/accesstokenclaims)\>

Validates a JWT access token by verifying the signature and claims.

#### Parameters

| Parameter     | Type                                                                                                    | Description                              |
| ------------- | ------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `accessToken` | `string`                                                                                                | The access token JWT string to validate. |
| `options?`    | [`ValidateJwtAccessTokenOptions`](/sdks/nodejs/api-reference/types/validatejwtaccesstokenoptions) | Validation options.                      |

#### Returns

`Promise`\<[`AccessTokenClaims`](/sdks/nodejs/api-reference/types/accesstokenclaims)\>

Validated access token claims.

#### Throws

[MonoCloudTokenError](/sdks/nodejs/api-reference/error-classes/monocloudtokenerror) - If JWT parsing, signature verification, or claim validation fails.

#### Throws

[MonoCloudHttpError](/sdks/nodejs/api-reference/error-classes/monocloudhttperror) - Thrown if there is a network error during the request or
unexpected status code during the request or a serialization error while processing the response.

#### Throws

[MonoCloudValidationError](/sdks/nodejs/api-reference/error-classes/monocloudvalidationerror) - When the access token is empty or claims validation fails.
