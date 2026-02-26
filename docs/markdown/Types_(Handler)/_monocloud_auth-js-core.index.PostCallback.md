---
rootSdk: js-core
title: "PostCallback"
category: Handler Types
---

# Handler Type: PostCallback

> **PostCallback** = (`state`: [`PostCallbackParams`](/sdks/js-core/api-reference/types/postcallbackparams)) => `Promise`\<`void`\> \| `void`

Callback executed after sign-in or sign-out callback processing.

## Parameters

| Parameter | Type                                                                                 | Description                             |
| --------- | ------------------------------------------------------------------------------------ | --------------------------------------- |
| `state`   | [`PostCallbackParams`](/sdks/js-core/api-reference/types/postcallbackparams) | Metadata describing the completed flow. |

## Returns

`Promise`\<`void`\> \| `void`

Returns `void` or a `Promise<void>`.
