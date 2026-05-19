---
rootSdk: Node.js Core
title: "OnSessionCreating"
category: Handler Types
description: "Callback invoked before a session is created or updated. Use this hook to modify or enrich the session before it is persisted."
---

# Handler Type: OnSessionCreating

> **OnSessionCreating** = (`session`: [`MonoCloudSession`](/sdks/nodejs-core/api-reference/types/monocloudsession), `idToken?`: `Partial`\<[`IdTokenClaims`](/sdks/nodejs-core/api-reference/types/idtokenclaims)\>, `userInfo?`: [`UserinfoResponse`](/sdks/nodejs-core/api-reference/types/userinforesponse), `state?`: [`ApplicationState`](/sdks/nodejs-core/api-reference/types/applicationstate)) => `Promise`\<`void`\> \| `void`

Callback invoked before a session is created or updated.

Use this hook to modify or enrich the session before it is persisted. The callback receives the resolved session along with optional claims obtained during authentication and any custom application state.

Common use cases include:

- Adding custom properties to the session
- Mapping or filtering claims
- Attaching tenant or application-specific metadata

## Parameters

| Parameter   | Type                                                                                      | Description                                                                      |
| ----------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `session`   | [`MonoCloudSession`](/sdks/nodejs-core/api-reference/types/monocloudsession)        | The session being created or updated. Changes made to this object are persisted. |
| `idToken?`  | `Partial`\<[`IdTokenClaims`](/sdks/nodejs-core/api-reference/types/idtokenclaims)\> | Optional claims extracted from the ID token.                                     |
| `userInfo?` | [`UserinfoResponse`](/sdks/nodejs-core/api-reference/types/userinforesponse)        | Optional claims returned from the `UserInfo` endpoint.                           |
| `state?`    | [`ApplicationState`](/sdks/nodejs-core/api-reference/types/applicationstate)        | Optional application state created during the authentication request.            |

## Returns

`Promise`\<`void`\> \| `void`

Returns a promise or void. Execution continues once the callback completes.
