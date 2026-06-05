---
rootSdk: @monocloud/auth-react
title: "SignOutOptions"
category: Types
description: "Options used to customize the sign-out flow."
---

# Type: SignOutOptions

Options used to customize the sign-out flow.

## Properties

| Property                                                    | Type                                                                             | Description                                                                                                                                                                                                                  |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `federatedSignOut?`           | `boolean`                                                                        | When `true`, signs the user out from both the application and MonoCloud (Single Sign-Out). Overrides the client-level `federatedSignOut` configuration for this specific call. If omitted, the client-level setting is used. |
| `mode?`                                   | [`InteractionMode`](/sdks/react/api-reference/enums/interactionmode) | Determines the interaction mode for the sign-out flow.                                                                                                                                                                       |
| `postLogoutRedirectUri?` | `string`                                                                         | URL to redirect the user to after sign-out completes. This URI must be registered in the application's sign-out URLs in MonoCloud.                                                                                           |
| `returnUrl?`                         | `string`                                                                         | Relative URL to navigate to after sign-out completes.                                                                                                                                                                        |
