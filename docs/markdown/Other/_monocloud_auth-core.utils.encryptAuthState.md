---
rootSdk: Node.js
title: "encryptAuthState"
category: Other
description: "Encrypts an AuthState object with a secret and optional time-to-live (TTL)."
---

# encryptAuthState

> **encryptAuthState**\<`T`\>(`authState`: `T`, `secret`: `string`, `ttl?`: `number`): `Promise`\<`string`\>

Encrypts an AuthState object with a secret and optional time-to-live (TTL).

## Type Parameters

| Type Parameter                                                                |
| ----------------------------------------------------------------------------- |
| `T` _extends_ [`AuthState`](/sdks/nodejs/api-reference/types/authstate) |

## Parameters

| Parameter   | Type     | Description                                                           |
| ----------- | -------- | --------------------------------------------------------------------- |
| `authState` | `T`      | A type that extends the AuthState interface.                          |
| `secret`    | `string` | The secret used for encryption.                                       |
| `ttl?`      | `number` | Optional time-to-live in seconds, after which the auth state expires. |

## Returns

`Promise`\<`string`\>

Encrypted auth state string.
