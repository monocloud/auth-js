---
rootSdk: JavaScript
title: "MonoCloudClientOptionsBase"
category: Types
description: "Shared configuration options for MonoCloud OIDC clients. These options are common to both MonoCloudOidcClientOptions and MonoCloudOidcBackendClientOptions."
---

# Type: MonoCloudClientOptionsBase

Shared configuration options for MonoCloud OIDC clients.

These options are common to both [MonoCloudOidcClientOptions](/sdks/nodejs/api-reference/types/monocloudoidcclientoptions)
and [MonoCloudOidcBackendClientOptions](/sdks/nodejs/api-reference/types/monocloudoidcbackendclientoptions).

## Properties

| Property                                                    | Type                                                                                      | Description                                                                                                                                                                                                                                                                                                                                 |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `clientAuthMethod?`           | [`ClientAuthMethod`](/sdks/web-js/api-reference/enums/clientauthmethod) | Client authentication method used when communicating with the token endpoint.                                                                                                                                                                                                                                                               |
| `clientSecret?`                   | `string` \| [`Jwk`](/sdks/web-js/api-reference/types/jwk)                                  | Client secret or key material used for client authentication. When `clientAuthMethod` is `client_secret_jwt` and a plain-text secret is provided, the default signing algorithm is `HS256`. To use a different algorithm, provide a symmetric JSON Web Key (JWK) (`kty: "oct"`) with the desired algorithm specified in its `alg` property. |
| `fetcher?`                             | (`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`) => `Promise`\<`Response`\>      | Optional custom `fetch` implementation used for network requests.                                                                                                                                                                                                                                                                           |
| `jwksCacheDuration?`         | `number`                                                                                  | Duration (in seconds) to cache the JSON Web Key Set (JWKS) retrieved from the authorization server.                                                                                                                                                                                                                                         |
| `metadataCacheDuration?` | `number`                                                                                  | Duration (in seconds) to cache OpenID Connect discovery metadata.                                                                                                                                                                                                                                                                           |
