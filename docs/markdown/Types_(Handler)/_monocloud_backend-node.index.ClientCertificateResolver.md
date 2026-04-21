---
rootSdk: Node.js Backend
title: "ClientCertificateResolver"
category: Handler Types
---

# Handler Type: ClientCertificateResolver

> **ClientCertificateResolver**\<`T`\> = (`req`: `T`) => `Promise`\<`string` \| `undefined`\>

Callback that resolves a PEM-encoded client certificate from the incoming request.

The returned certificate can include or omit the `-----BEGIN CERTIFICATE-----` /
`-----END CERTIFICATE-----` delimiters.

## Type Parameters

| Type Parameter | Description         |
| -------------- | ------------------- |
| `T`            | Type of the request |

## Parameters

| Parameter | Type |
| --------- | ---- |
| `req`     | `T`  |

## Returns

`Promise`\<`string` \| `undefined`\>
