---
rootSdk: js-core
title: "SessionStorage"
category: Classes
---

# Class: SessionStorage

`window.sessionStorage`-backed implementation of [IStorage](/sdks/js-core/api-reference/types/istorage).

Data persists for the lifetime of the current browser tab.

## Implements

- [`IStorage`](/sdks/js-core/api-reference/types/istorage)

## Constructors

### Constructor

> **new SessionStorage**(): `SessionStorage`

#### Returns

`SessionStorage`

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

#### Implementation of

[`IStorage`](/sdks/js-core/api-reference/types/istorage).[`getItem`](/sdks/js-core/api-reference/types/istorage#getitem)

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

#### Implementation of

[`IStorage`](/sdks/js-core/api-reference/types/istorage).[`removeItem`](/sdks/js-core/api-reference/types/istorage#removeitem)

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

#### Implementation of

[`IStorage`](/sdks/js-core/api-reference/types/istorage).[`setItem`](/sdks/js-core/api-reference/types/istorage#setitem)
