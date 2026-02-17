---
rootSdk: Node.js Core
title: "SignInOptions"
category: Types
---

# Type: SignInOptions

Options used to customize the sign-in flow.

## Properties

| Property                              | Type                                                                            | Description                                                                                                                         |
| ------------------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `authParams?` | [`AuthorizationParams`](/sdks/nodejs-core/api-reference/types/authorizationparams) | Additional authorization parameters merged into the authentication request.                                                         |
| `onError?`       | [`OnError`](/sdks/nodejs-core/api-reference/handler-types/onerror)    | Callback invoked if an unexpected error occurs during the sign-in flow.                                                             |
| `register?`     | `boolean`                                                                       | When `true`, initiates the user registration (sign-up) flow instead of a standard sign-in.                                          |
| `returnUrl?`   | `string`                                                                        | Relative URL to redirect the user to after successful authentication. If not provided, the application base URL (`appUrl`) is used. |
