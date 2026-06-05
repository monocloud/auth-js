---
rootSdk: @monocloud/auth-react
title: "MemoryStorage"
category: Classes
description: "In-memory implementation of IStorage. Useful for testing or for sessions that should not persist across page reloads."
---

# Class: MemoryStorage

In-memory implementation of [IStorage](/sdks/react/api-reference/types/istorage).

Useful for testing or for sessions that should not persist across page reloads.

## Implements

- [`IStorage`](/sdks/react/api-reference/types/istorage)

## Constructors

### Constructor

> **new MemoryStorage**(): `MemoryStorage`

#### Returns

`MemoryStorage`

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
