---
rootSdk: Node.js Backend
title: "IIntrospectionCache"
category: Types
description: "Cache adapter for storing access token introspection results."
---

# Type: IIntrospectionCache

Cache adapter for storing access token introspection results.

Implement this interface to persist introspection results in an external store such as
Redis, Memcached, or an in-memory cache.

## Methods

### get()

> **get**(`key`: `string`): `Promise`\<[`AccessTokenClaims`](/sdks/nodejs-backend/api-reference/types/accesstokenclaims) \| `null` \| `undefined`\>

Retrieves cached claims by key.

#### Parameters

| Parameter | Type     | Description    |
| --------- | -------- | -------------- |
| `key`     | `string` | The cache key. |

#### Returns

`Promise`\<[`AccessTokenClaims`](/sdks/nodejs-backend/api-reference/types/accesstokenclaims) \| `null` \| `undefined`\>

The cached claims, or `null`/`undefined` if the entry does not exist or has expired.

---

### set()

> **set**(`key`: `string`, `claims`: [`AccessTokenClaims`](/sdks/nodejs-backend/api-reference/types/accesstokenclaims), `expiresAt`: `number`): `Promise`\<`void`\>

Stores introspected access token claims in the cache.

#### Parameters

| Parameter   | Type                                                                      | Description                                                      |
| ----------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `key`       | `string`                                                                  | The cache key (access token).                                    |
| `claims`    | [`AccessTokenClaims`](/sdks/nodejs-backend/api-reference/types/accesstokenclaims) | The introspected access token claims to cache.                   |
| `expiresAt` | `number`                                                                  | The token's expiration time as a Unix epoch timestamp (seconds). |

#### Returns

`Promise`\<`void`\>
