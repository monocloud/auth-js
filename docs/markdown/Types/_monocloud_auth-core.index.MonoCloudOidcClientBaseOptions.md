---
rootSdk: Node.js
title: "MonoCloudOidcClientBaseOptions"
category: Types
description: "Constructor options for MonoCloudOidcClientBase."
---

# Type: MonoCloudOidcClientBaseOptions

Constructor options for [MonoCloudOidcClientBase](/sdks/nodejs/api-reference/classes/monocloudoidcclientbase).

## Properties

| Property                                                    | Type                                                                                                                                                                                 | Description                                                                                                    |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| `clientAuthMethod?`           | [`ClientAuthMethod`](/sdks/nodejs/api-reference/enums/clientauthmethod)                                                                                              | Client authentication method. Determines whether mTLS-aliased endpoints are used.                              |
| `fetcher?`                             | \{(`input`: `URL` \| `RequestInfo`, `init?`: `RequestInit`): `Promise`\<`Response`\>; (`input`: `string` \| `URL` \| `Request`, `init?`: `RequestInit`): `Promise`\<`Response`\>; \} | Custom `fetch` implementation used for making HTTP requests. Falls back to the global `fetch` if not provided. |
| `jwksCacheDuration?`         | `number`                                                                                                                                                                             | Duration (in seconds) to cache the JSON Web Key Set (JWKS).                                                    |
| `jwksResolver?`                   | () => [`Jwks`](/sdks/nodejs/api-reference/types/jwks) \| `Promise`\<[`Jwks`](/sdks/nodejs/api-reference/types/jwks)\>                                                                      | Optional custom resolver for the JSON Web Key Set (JWKS), replacing the default JWKS request.                  |
| `metadataCacheDuration?` | `number`                                                                                                                                                                             | Duration (in seconds) to cache OpenID Connect discovery metadata.                                              |
| `metadataResolver?`           | () => [`IssuerMetadata`](/sdks/nodejs/api-reference/types/issuermetadata) \| `Promise`\<[`IssuerMetadata`](/sdks/nodejs/api-reference/types/issuermetadata)\>                              | Optional custom resolver for the issuer metadata, replacing the default discovery request.                     |
| `tenantDomain`                    | `string`                                                                                                                                                                             | The tenant domain URL.                                                                                         |
| `trustStoreId?`                   | `string`                                                                                                                                                                             | Identifier of the trust store whose mTLS endpoint aliases should be used.                                      |
