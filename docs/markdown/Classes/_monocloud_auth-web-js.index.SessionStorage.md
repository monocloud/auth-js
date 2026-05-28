---
rootSdk: JavaScript
title: "SessionStorage"
category: Classes
description: "window.sessionStorage-backed implementation of IStorage. Data persists for the lifetime of the current browser tab."
---

# Class: SessionStorage

`window.sessionStorage`-backed implementation of [IStorage](/sdks/web-js/api-reference/types/istorage).

Data persists for the lifetime of the current browser tab.

## Implements

- [`IStorage`](/sdks/web-js/api-reference/types/istorage)

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
