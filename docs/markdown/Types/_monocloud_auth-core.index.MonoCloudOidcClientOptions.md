---
rootSdk: Node.js
title: "MonoCloudOidcClientOptions"
category: Types
description: "Configuration options used to initialize the MonoCloudOidcClient."
---

# Type: MonoCloudOidcClientOptions

Configuration options used to initialize the MonoCloudOidcClient.

## Extends

- [`MonoCloudClientOptionsBase`](/sdks/nodejs/api-reference/types/monocloudclientoptionsbase)

## Properties

| Property                                                        | Type                                                                                                                                                                                 | Description                                                                                                                                                                                                                                                                                                                                 |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `clientAuthMethod?`               | [`ClientAuthMethod`](/sdks/nodejs/api-reference/enums/clientauthmethod)                                                                                              | Client authentication method used when communicating with the token endpoint.                                                                                                                                                                                                                                                               |
| `clientSecret?`                       | `string` \| [`Jwk`](/sdks/nodejs/api-reference/types/jwk)                                                                                                                               | Client secret or key material used for client authentication. When `clientAuthMethod` is `client_secret_jwt` and a plain-text secret is provided, the default signing algorithm is `HS256`. To use a different algorithm, provide a symmetric JSON Web Key (JWK) (`kty: "oct"`) with the desired algorithm specified in its `alg` property. |
| `fetcher?`                                 | \{(`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`): `Promise`\<`Response`\>; (`input`: `string` \| `URL` \| `Request`, `init?`: `RequestInit`): `Promise`\<`Response`\>; \} | Optional custom `fetch` implementation used for network requests.                                                                                                                                                                                                                                                                           |
| `idTokenSigningAlgorithm?` | [`SecurityAlgorithms`](/sdks/nodejs/api-reference/enums/securityalgorithms)                                                                                          | Expected signing algorithm for validating ID tokens.                                                                                                                                                                                                                                                                                        |
| `jwksCacheDuration?`             | `number`                                                                                                                                                                             | Duration (in seconds) to cache the JSON Web Key Set (JWKS) retrieved from the authorization server.                                                                                                                                                                                                                                         |
| `metadataCacheDuration?`     | `number`                                                                                                                                                                             | Duration (in seconds) to cache OpenID Connect discovery metadata.                                                                                                                                                                                                                                                                           |
