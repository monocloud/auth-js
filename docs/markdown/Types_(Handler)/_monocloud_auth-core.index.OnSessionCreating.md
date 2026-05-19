---
rootSdk: Node.js
title: "OnSessionCreating"
category: Handler Types
description: "Callback invoked before a session is created or updated."
---

# Handler Type: OnSessionCreating

> **OnSessionCreating** = (`session`: [`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession), `idToken?`: `Partial`\<[`IdTokenClaims`](/sdks/nodejs/api-reference/types/idtokenclaims)\>, `userInfo?`: [`UserinfoResponse`](/sdks/nodejs/api-reference/types/userinforesponse)) => `Promise`\<`void`\> \| `void`

Callback invoked before a session is created or updated.

This hook allows you to inspect or modify the session during the authentication lifecycle — for example, to enrich the session with custom claims, normalize user data, or apply application-specific logic.

## Parameters

| Parameter   | Type                                                                                 | Description                                             |
| ----------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------- |
| `session`   | [`MonoCloudSession`](/sdks/nodejs/api-reference/types/monocloudsession)        | The session being created or updated.                   |
| `idToken?`  | `Partial`\<[`IdTokenClaims`](/sdks/nodejs/api-reference/types/idtokenclaims)\> | Optional. Claims extracted from the ID token.           |
| `userInfo?` | [`UserinfoResponse`](/sdks/nodejs/api-reference/types/userinforesponse)        | Optional. Claims returned from the `UserInfo` endpoint. |

## Returns

`Promise`\<`void`\> \| `void`

Returns a promise or void. Execution continues once the callback completes.
