---
rootSdk: js-core
title: "SignOutOptions"
category: Types
---

# Type: SignOutOptions

Options for `signOut()`.

## Properties

| Property                                                    | Type                                                                                     | Description                                                                                                                    |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `mode?`                                   | [`InteractionMode`](/sdks/js-core/api-reference/enums/interactionmode) | Determines the interaction mode for the sign-out process.                                                                      |
| `postLogoutRedirectUri?` | `string`                                                                                 | URI to redirect to after successful sign-out. This URI must be configured in the application's allowed sign-out callback URLs. |
| `returnUrl?`                         | `string`                                                                                 | Relative path to return to after sign-out.                                                                                     |
