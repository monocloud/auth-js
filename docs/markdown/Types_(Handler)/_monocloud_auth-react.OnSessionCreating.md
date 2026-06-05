---
rootSdk: @monocloud/auth-react
title: "OnSessionCreating"
category: Handler Types
description: "Callback invoked when a session is being created or updated."
---

# Handler Type: OnSessionCreating

> **OnSessionCreating** = (`session`: [`MonoCloudSession`](/sdks/react/api-reference/types/monocloudsession), `idToken?`: `Partial`\<[`IdTokenClaims`](/sdks/react/api-reference/types/idtokenclaims)\>, `userInfo?`: [`UserinfoResponse`](/sdks/react/api-reference/types/userinforesponse), `state?`: [`ApplicationState`](/sdks/react/api-reference/types/applicationstate)) => `Promise`\<`void`\> \| `void`

Callback invoked when a session is being created or updated.

Use this hook to modify or enrich the session before it is persisted - for example, to attach custom claims, normalize user data, or apply application-specific logic.

## Parameters

| Parameter   | Type                                                                            | Description                                                                      |
| ----------- | ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `session`   | [`MonoCloudSession`](/sdks/react/api-reference/types/monocloudsession)        | The session being created or updated. Changes made to this object are persisted. |
| `idToken?`  | `Partial`\<[`IdTokenClaims`](/sdks/react/api-reference/types/idtokenclaims)\> | Optional claims extracted from the ID token received during authentication.      |
| `userInfo?` | [`UserinfoResponse`](/sdks/react/api-reference/types/userinforesponse)        | Optional claims returned from the UserInfo endpoint.                             |
| `state?`    | [`ApplicationState`](/sdks/react/api-reference/types/applicationstate)        | Optional application state associated with the authentication request.           |

## Returns

`Promise`\<`void`\> \| `void`

Returns a promise or void. Execution continues once the callback completes.
