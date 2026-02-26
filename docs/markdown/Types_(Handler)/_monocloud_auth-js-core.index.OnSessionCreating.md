---
rootSdk: js-core
title: "OnSessionCreating"
category: Handler Types
---

# Handler Type: OnSessionCreating

> **OnSessionCreating** = (`session`: [`MonoCloudSession`](/sdks/js-core/api-reference/types/monocloudsession), `idToken?`: `Partial`\<[`IdTokenClaims`](/sdks/js-core/api-reference/types/idtokenclaims)\>, `userInfo?`: [`UserinfoResponse`](/sdks/js-core/api-reference/types/userinforesponse), `state?`: [`ApplicationState`](/sdks/js-core/api-reference/types/applicationstate)) => `Promise`\<`void`\> \| `void`

Callback invoked when a session is being created or updated.

## Parameters

| Parameter   | Type                                                                                    | Description                                                       |
| ----------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `session`   | [`MonoCloudSession`](/sdks/js-core/api-reference/types/monocloudsession)        | The session object being created.                                 |
| `idToken?`  | `Partial`\<[`IdTokenClaims`](/sdks/js-core/api-reference/types/idtokenclaims)\> | Optional claims from the ID token received during authentication. |
| `userInfo?` | [`UserinfoResponse`](/sdks/js-core/api-reference/types/userinforesponse)        | Optional claims from the UserInfo response.                       |
| `state?`    | [`ApplicationState`](/sdks/js-core/api-reference/types/applicationstate)        | Optional application state associated with the session.           |

## Returns

`Promise`\<`void`\> \| `void`

Returns `void` or a `Promise<void>`.
