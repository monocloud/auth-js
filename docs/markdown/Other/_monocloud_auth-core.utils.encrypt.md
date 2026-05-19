---
rootSdk: Node.js
title: "encrypt"
category: Other
description: "Encrypts a given string using a secret with AES-GCM."
---

# encrypt

> **encrypt**(`data`: `string`, `secret`: `string`): `Promise`\<`string`\>

Encrypts a given string using a secret with AES-GCM.

## Parameters

| Parameter | Type     | Description                                   |
| --------- | -------- | --------------------------------------------- |
| `data`    | `string` | The plaintext data to encrypt.                |
| `secret`  | `string` | The secret used to derive the encryption key. |

## Returns

`Promise`\<`string`\>

Base64-encoded ciphertext.
