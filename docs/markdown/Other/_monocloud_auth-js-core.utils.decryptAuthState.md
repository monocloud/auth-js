---
rootSdk: js-core
title: "decryptAuthState"
category: Other
---

# decryptAuthState

> **decryptAuthState**\<`T`\>(`encryptedAuthState`: `string`, `secret`: `string`): `Promise`\<`T`\>

Decrypts an encrypted AuthState.

## Type Parameters

| Type Parameter                                                                   |
| -------------------------------------------------------------------------------- |
| `T` _extends_ [`AuthState`](/sdks/js-core/api-reference/types/authstate) |

## Parameters

| Parameter            | Type     | Description                                 |
| -------------------- | -------- | ------------------------------------------- |
| `encryptedAuthState` | `string` | The encrypted auth state string to decrypt. |
| `secret`             | `string` | The secret used for decryption.             |

## Returns

`Promise`\<`T`\>

State object on success.

## Throws

If decryption fails or the auth state has expired.
