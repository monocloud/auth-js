---
rootSdk: Node.js Core
title: "decrypt"
category: Other
description: "Decrypts an encrypted string using a secret with AES-GCM."
---

# decrypt

> **decrypt**(`encrypted`: `string`, `secret`: `string`): `Promise`\<`string` \| `undefined`\>

Decrypts an encrypted string using a secret with AES-GCM.

## Parameters

| Parameter   | Type     | Description                                   |
| ----------- | -------- | --------------------------------------------- |
| `encrypted` | `string` | The ciphertext to decrypt.                    |
| `secret`    | `string` | The secret used to derive the decryption key. |

## Returns

`Promise`\<`string` \| `undefined`\>

Decrypted plaintext string or undefined if decryption fails.
