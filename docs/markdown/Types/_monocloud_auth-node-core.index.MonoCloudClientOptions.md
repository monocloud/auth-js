---
rootSdk: Node.js Core
title: "MonoCloudClientOptions"
category: Types
---

# Type: MonoCloudClientOptions

Configuration options used to initialize the MonoCloudClient.

## Properties

| Property                                                        | Type                                                                                             | Description                                                                                                                                                                                                                                                                                                                 |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `clientAuthMethod?`               | [`ClientAuthMethod`](/sdks/nodejs-core/api-reference/enums/clientauthmethod)     | Client authentication method used when communicating with the token endpoint.                                                                                                                                                                                                                                               |
| `clientSecret?`                       | `string` \| [`Jwk`](/sdks/nodejs-core/api-reference/types/jwk)                                      | Client secret used for client authentication. When `clientAuthMethod` is `client_secret_jwt` and a plain-text secret is provided, the default signing algorithm is `HS256`. To use a different algorithm, provide a symmetric JSON Web Key (JWK) (`kty: "oct"`) with the desired algorithm specified in its `alg` property. |
| `idTokenSigningAlgorithm?` | [`SecurityAlgorithms`](/sdks/nodejs-core/api-reference/enums/securityalgorithms) | Expected signing algorithm for validating ID tokens.                                                                                                                                                                                                                                                                        |
| `jwksCacheDuration?`             | `number`                                                                                         | Duration (in seconds) to cache the JSON Web Key Set (JWKS) retrieved from the authorization server.                                                                                                                                                                                                                         |
| `metadataCacheDuration?`     | `number`                                                                                         | Duration (in seconds) to cache OpenID Connect discovery metadata.                                                                                                                                                                                                                                                           |
