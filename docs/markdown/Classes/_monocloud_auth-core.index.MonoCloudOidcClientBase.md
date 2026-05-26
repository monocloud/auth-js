---
rootSdk: Node.js
title: "MonoCloudOidcClientBase"
category: Classes
description: "MonoCloudOidcClientBase is a class in the MonoCloud Node.js SDK."
---

# Class: MonoCloudOidcClientBase

## Constructors

### Constructor

> **new MonoCloudOidcClientBase**(`tenantDomain`: `string`, `metadataCacheDuration?`: `number`, `jwksCacheDuration?`: `number`, `fetcher?`: \{(`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`): `Promise`\<`Response`\>; (`input`: `string` \| `URL` \| `Request`, `init?`: `RequestInit`): `Promise`\<`Response`\>; \}): `MonoCloudOidcClientBase`

Creates a new instance of MonoCloudOidcClientBase.

#### Parameters

| Parameter                | Type                                                                                                                                                                                 | Description                                                                                                    |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| `tenantDomain`           | `string`                                                                                                                                                                             | The tenant domain URL.                                                                                         |
| `metadataCacheDuration?` | `number`                                                                                                                                                                             | Duration (in seconds) to cache OpenID Connect discovery metadata. Defaults to 300 (5 minutes).                 |
| `jwksCacheDuration?`     | `number`                                                                                                                                                                             | Duration (in seconds) to cache the JSON Web Key Set (JWKS). Defaults to 300 (5 minutes).                       |
| `fetcher?`               | \{(`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`): `Promise`\<`Response`\>; (`input`: `string` \| `URL` \| `Request`, `init?`: `RequestInit`): `Promise`\<`Response`\>; \} | Custom `fetch` implementation used for making HTTP requests. Falls back to the global `fetch` if not provided. |

#### Returns

`MonoCloudOidcClientBase`

## Properties

| Property                                                   | Type                                                                                                                                                                                 | Description                                                                                                  |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| `fetcher?`                            | \{(`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`): `Promise`\<`Response`\>; (`input`: `string` \| `URL` \| `Request`, `init?`: `RequestInit`): `Promise`\<`Response`\>; \} | Custom fetch implementation used for making HTTP requests. Falls back to the global `fetch` if not provided. |
| `jwks?`                                  | [`Jwks`](/sdks/nodejs/api-reference/types/jwks)                                                                                                                                | Cached JSON Web Key Set retrieved from the issuer's JWKS endpoint.                                           |
| `jwksCacheDuration`         | `number`                                                                                                                                                                             | Duration (in seconds) for which the JWKS is cached. Defaults to 300 (5 minutes).                             |
| `jwksCacheExpiry`             | `number`                                                                                                                                                                             | Timestamp (in seconds) when the cached JWKS expires.                                                         |
| `metadata?`                          | [`IssuerMetadata`](/sdks/nodejs/api-reference/types/issuermetadata)                                                                                                            | Cached issuer metadata retrieved from the OpenID Connect discovery endpoint.                                 |
| `metadataCacheDuration` | `number`                                                                                                                                                                             | Duration (in seconds) for which the metadata is cached. Defaults to 300 (5 minutes).                         |
| `metadataCacheExpiry`     | `number`                                                                                                                                                                             | Timestamp (in seconds) when the cached metadata expires.                                                     |
| `tenantDomain`                   | `string`                                                                                                                                                                             | The normalized tenant domain URL used as the base for discovery endpoints.                                   |

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
