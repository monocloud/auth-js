---
rootSdk: Next.js
title: "MonoCloudSessionStore"
category: Types
---

# Type: MonoCloudSessionStore

Defines a storage adapter used to persist authentication sessions.

Implement this interface to store sessions outside the default cookie-based storage — for example in Redis, a database, or a distributed cache.

## Methods

### delete()

> **delete**(`key`: `string`): `Promise`\<`void`\>

Removes a session from the store.

#### Parameters

| Parameter | Type     | Description                                 |
| --------- | -------- | ------------------------------------------- |
| `key`     | `string` | Unique identifier of the session to delete. |

#### Returns

`Promise`\<`void`\>

---

### get()

> **get**(`key`: `string`): `Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `null` \| `undefined`\>

Retrieves a session associated with the provided key.

#### Parameters

| Parameter | Type     | Description                       |
| --------- | -------- | --------------------------------- |
| `key`     | `string` | Unique identifier of the session. |

#### Returns

`Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `null` \| `undefined`\>

Returns the stored session, or `undefined` / `null` if no session exists.

---

### set()

> **set**(`key`: `string`, `data`: [`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession), `lifetime`: [`SessionLifetime`](/sdks/nextjs/api-reference/types/sessionlifetime)): `Promise`\<`void`\>

Persists or updates a session.

The provided lifetime information can be used by the store to configure TTL/expiration policies.

#### Parameters

| Parameter  | Type                                                                   | Description                                               |
| ---------- | ---------------------------------------------------------------------- | --------------------------------------------------------- |
| `key`      | `string`                                                               | Unique identifier of the session.                         |
| `data`     | [`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) | The session data to persist.                              |
| `lifetime` | [`SessionLifetime`](/sdks/nextjs/api-reference/types/sessionlifetime)   | Session lifetime metadata (creation, update, expiration). |

#### Returns

`Promise`\<`void`\>
