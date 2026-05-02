---
rootSdk: Next.js
title: "OnBackChannelLogout"
category: Handler Types
description: "Callback invoked when a back-channel logout event is received from the authorization server."
---

# Handler Type: OnBackChannelLogout

> **OnBackChannelLogout** = (`sub?`: `string`, `sid?`: `string`) => `Promise`\<`void`\> \| `void`

Callback invoked when a back-channel logout event is received from the authorization server.

Back-channel logout allows MonoCloud to notify the application that a user session should be terminated without browser interaction.

## Parameters

| Parameter | Type     | Description                                                                       |
| --------- | -------- | --------------------------------------------------------------------------------- |
| `sub?`    | `string` | Optional subject identifier (`sub`) of the user associated with the logout event. |
| `sid?`    | `string` | Optional session identifier (`sid`) for the session being terminated.             |

## Returns

`Promise`\<`void`\> \| `void`

Returns a promise or void. Execution completes once logout handling finishes.
