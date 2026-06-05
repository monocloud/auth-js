---
rootSdk: @monocloud/auth-react
title: "PostCallback"
category: Handler Types
description: "Callback executed after sign-in or sign-out callback processing."
---

# Handler Type: PostCallback

> **PostCallback** = (`state`: [`CallbackState`](/sdks/react/api-reference/types/callbackstate)) => `Promise`\<`void`\> \| `void`

Callback executed after sign-in or sign-out callback processing.

The default implementation removes query parameters from the current URL on `signIn` (no navigation) or performs a full page reload to `returnUrl`. Provide a custom implementation to integrate with a client-side router and avoid full page reloads.

## Parameters

| Parameter | Type                                                               | Description     |
| --------- | ------------------------------------------------------------------ | --------------- |
| `state`   | [`CallbackState`](/sdks/react/api-reference/types/callbackstate) | Callback state. |

## Returns

`Promise`\<`void`\> \| `void`

Returns a promise or void. Execution continues once the callback completes.
