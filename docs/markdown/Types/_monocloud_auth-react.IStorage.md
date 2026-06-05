---
rootSdk: @monocloud/auth-react
title: "IStorage"
category: Types
description: "Defines a storage adapter used to persist session data."
---

# Type: IStorage

Defines a storage adapter used to persist session data.

Implement this interface to plug a custom storage backend (for example, an
encrypted store, secure cookie helper, or a wrapper around `IndexedDB`) into
`MonoCloudWebJSClient`.

Built-in implementations:

- [LocalStorage](/sdks/react/api-reference/classes/localstorage) (default) - backed by `window.localStorage`.
- [SessionStorage](/sdks/react/api-reference/classes/sessionstorage) - backed by `window.sessionStorage`.
- [MemoryStorage](/sdks/react/api-reference/classes/memorystorage) - in-memory store, useful for testing.

## Methods

### getItem()

> **getItem**(`key`: `string`): `Promise`\<`string` \| `null`\>

Retrieves the value associated with the given key.

#### Parameters

| Parameter | Type     | Description                                |
| --------- | -------- | ------------------------------------------ |
| `key`     | `string` | The unique identifier for the stored item. |

#### Returns

`Promise`\<`string` \| `null`\>

The stored value as a string, or `null` if the key does not exist.

---

### removeItem()

> **removeItem**(`key`: `string`): `Promise`\<`void`\>

Removes the item associated with the specified key from storage.

#### Parameters

| Parameter | Type     | Description                                  |
| --------- | -------- | -------------------------------------------- |
| `key`     | `string` | The unique identifier of the item to remove. |

#### Returns

`Promise`\<`void`\>

---

### setItem()

> **setItem**(`key`: `string`, `value`: `string`): `Promise`\<`void`\>

Stores a key-value pair in the storage.

#### Parameters

| Parameter | Type     | Description                         |
| --------- | -------- | ----------------------------------- |
| `key`     | `string` | The unique identifier for the item. |
| `value`   | `string` | The string value to store.          |

#### Returns

`Promise`\<`void`\>
