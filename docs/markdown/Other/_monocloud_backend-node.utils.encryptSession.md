---
rootSdk: Node.js Backend
title: "encryptSession"
category: Other
---

# encryptSession

> **encryptSession**(`session`: [`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession), `secret`: `string`, `ttl?`: `number`): `Promise`\<`string`\>

Encrypts a MonoCloud session object with a secret and optional time-to-live (TTL).

## Parameters

| Parameter | Type                                                                          | Description                                                        |
| --------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `session` | [`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession) | The session object to encrypt.                                     |
| `secret`  | `string`                                                                      | The secret used for encryption.                                    |
| `ttl?`    | `number`                                                                      | Optional time-to-live in seconds, after which the session expires. |

## Returns

`Promise`\<`string`\>

Encrypted session string.
