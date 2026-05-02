---
rootSdk: Node.js Core
title: "OnError"
category: Handler Types
description: "Defines a callback invoked when an unexpected error occurs during execution of authentication endpoints such as sign-in, callback, sign-out, or userinfo."
---

# Handler Type: OnError

> **OnError** = (`error`: `Error`) => `Promise`\<`any`\> \| `any`

Defines a callback invoked when an unexpected error occurs during execution of authentication endpoints such as sign-in, callback, sign-out, or userinfo.

This handler allows applications to log, transform, or respond to errors before the SDK applies its default error handling behavior.

## Parameters

| Parameter | Type    | Description                                 |
| --------- | ------- | ------------------------------------------- |
| `error`   | `Error` | The error thrown during endpoint execution. |

## Returns

`Promise`\<`any`\> \| `any`
