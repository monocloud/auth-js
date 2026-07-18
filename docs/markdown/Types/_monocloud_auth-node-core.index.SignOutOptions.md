---
rootSdk: Node.js Core
title: "SignOutOptions"
category: Types
description: "Options used to customize the behavior of the sign-out handler."
---

# Type: SignOutOptions

Options used to customize the behavior of the sign-out handler.

## Extends

- [`EndSessionParameters`](/sdks/nodejs-core/api-reference/types/endsessionparameters)

## Properties

| Property                                                    | Type                                                                         | Description                                                                                                                                                                                                 |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `federatedSignOut?`           | `boolean`                                                                    | When `true`, also signs the user out of the MonoCloud session (Single Sign-Out) in addition to the local application session.                                                                               |
| `idTokenHint?`                     | `string`                                                                     | ID token hint identifying the session to terminate. Sent as the `id_token_hint` parameter. When provided, the authorization server can use this value to determine which user session should be signed out. |
| `onError?`                             | [`OnError`](/sdks/nodejs-core/api-reference/handler-types/onerror) | Callback invoked if an unexpected error occurs during the sign-out flow.                                                                                                                                    |
| `postLogoutRedirectUri?` | `string`                                                                     | The URL the authorization server should redirect the user to after a successful sign-out.                                                                                                                   |
| `state?`                                 | `string`                                                                     | Optional state value returned to the application after sign-out.                                                                                                                                            |
