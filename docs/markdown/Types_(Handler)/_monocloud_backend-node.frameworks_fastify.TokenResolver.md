---
rootSdk: Node.js Backend
title: "TokenResolver"
category: Handler Types
framework: Fastify
---

# Handler Type: TokenResolver

> **TokenResolver**\<`T`\> = (`req`: `T`) => `Promise`\<`string`\>

Callback that resolves an access token from the incoming request.

When provided, this takes precedence over the default `Authorization: Bearer` header extraction.

## Type Parameters

| Type Parameter | Description         |
| -------------- | ------------------- |
| `T`            | Type of the request |

## Parameters

| Parameter | Type |
| --------- | ---- |
| `req`     | `T`  |

## Returns

`Promise`\<`string`\>
