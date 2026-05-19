---
rootSdk: Node.js Backend
title: "getPublicSigKeyFromIssuerJwks"
category: Other
description: "Retrieves a public CryptoKey from a JWK set based on the JWS header."
---

# getPublicSigKeyFromIssuerJwks

> **getPublicSigKeyFromIssuerJwks**(`jwks`: [`Jwk`](/sdks/nodejs-backend/api-reference/types/jwk)[], `header`: [`JwsHeaderParameters`](/sdks/nodejs-backend/api-reference/types/jwsheaderparameters)): `Promise`\<`CryptoKey`\>

Retrieves a public CryptoKey from a JWK set based on the JWS header.

## Parameters

| Parameter | Type                                                                                   | Description                                         |
| --------- | -------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `jwks`    | [`Jwk`](/sdks/nodejs-backend/api-reference/types/jwk)[]                               | The set of JSON Web Keys.                           |
| `header`  | [`JwsHeaderParameters`](/sdks/nodejs-backend/api-reference/types/jwsheaderparameters) | The JWS header containing the algorithm and key ID. |

## Returns

`Promise`\<`CryptoKey`\>

A promise that resolves to the CryptoKey.

## Throws

If no applicable key or multiple keys are found or the algorithm is unsupported.
