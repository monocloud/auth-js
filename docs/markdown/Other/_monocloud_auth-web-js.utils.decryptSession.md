---
rootSdk: JavaScript
title: "decryptSession"
category: Other
description: "Decrypts an encrypted MonoCloud session."
---

# decryptSession

> **decryptSession**(`encryptedSession`: `string`, `secret`: `string`): `Promise`\<[`MonoCloudSession`](/sdks/web-js/api-reference/types/monocloudsession)\>

Decrypts an encrypted MonoCloud session.

## Parameters

| Parameter          | Type     | Description                              |
| ------------------ | -------- | ---------------------------------------- |
| `encryptedSession` | `string` | The encrypted session string to decrypt. |
| `secret`           | `string` | The secret used for decryption.          |

## Returns

`Promise`\<[`MonoCloudSession`](/sdks/web-js/api-reference/types/monocloudsession)\>

Session object on success.

## Throws

If decryption fails or the session has expired.
