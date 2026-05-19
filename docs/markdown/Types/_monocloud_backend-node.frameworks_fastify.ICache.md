---
rootSdk: Node.js Backend
title: "ICache"
category: Types
framework: Fastify
description: "Cache adapter for storing validated access token claims."
---

# Type: ICache

Cache adapter for storing validated access token claims.

Implement this interface to persist validated claims in an external store such as
Redis, Memcached, or an in-memory cache.

## delete()

> **delete**(`key`: `string`): `Promise`\<`void`\>

Removes an entry from the cache.

### Parameters

| Parameter | Type     | Description              |
| --------- | -------- | ------------------------ |
| `key`     | `string` | The cache key to delete. |

### Returns

`Promise`\<`void`\>

---

## get()

> **get**(`key`: `string`): `Promise`\<[`AccessTokenClaims`](/sdks/fastify-backend/api-reference/types/accesstokenclaims) \| `null` \| `undefined`\>

Retrieves cached claims by key.

### Parameters

| Parameter | Type     | Description    |
| --------- | -------- | -------------- |
| `key`     | `string` | The cache key. |

### Returns

`Promise`\<[`AccessTokenClaims`](/sdks/fastify-backend/api-reference/types/accesstokenclaims) \| `null` \| `undefined`\>

The cached claims, or `null`/`undefined` if the entry does not exist or has expired.

---

## set()

> **set**(`key`: `string`, `claims`: [`AccessTokenClaims`](/sdks/fastify-backend/api-reference/types/accesstokenclaims), `expiresAt`: `number`): `Promise`\<`void`\>

Stores validated claims in the cache.

### Parameters

| Parameter   | Type                                                                      | Description                                                      |
| ----------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `key`       | `string`                                                                  | The cache key (access token).                                    |
| `claims`    | [`AccessTokenClaims`](/sdks/fastify-backend/api-reference/types/accesstokenclaims) | The validated access token claims to cache.                      |
| `expiresAt` | `number`                                                                  | The token's expiration time as a Unix epoch timestamp (seconds). |

### Returns

`Promise`\<`void`\>
