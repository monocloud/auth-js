---
rootSdk: Node.js Core
title: "CallbackOptions"
category: Types
---

# Type: CallbackOptions

Options used to customize callback processing after authentication.

## Properties

| Property                                | Type                                                                         | Description                                                                                                                                         |
| --------------------------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `onError?`         | [`OnError`](/sdks/nodejs-core/api-reference/handler-types/onerror) | Callback invoked if an unexpected error occurs while processing the authentication callback.                                                        |
| `redirectUri?` | `string`                                                                     | Redirect URI sent to the token endpoint during the authorization code exchange. > This must match the redirect URI used during the sign-in request. |
| `userInfo?`       | `boolean`                                                                    | When `true`, fetches user profile data from the `UserInfo` endpoint after the authorization code exchange completes.                                |
