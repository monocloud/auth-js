---
rootSdk: Node.js Core
title: "UserInfoOptions"
category: Types
---

# Type: UserInfoOptions

Options used to customize the behavior of the userinfo handler.

## Properties

| Property                        | Type                                                                         | Description                                                                                                                  |
| ------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `onError?` | [`OnError`](/sdks/nodejs-core/api-reference/handler-types/onerror) | Callback invoked if an unexpected error occurs while retrieving user information.                                            |
| `refresh?` | `boolean`                                                                    | When `true`, forces user profile data to be re-fetched from the authentication service instead of using cached session data. |
