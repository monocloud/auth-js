---
rootSdk: Next.js
title: "SignUpProps"
category: Types
---

# Type: SignUpProps

Props for the `<SignUp />` component.

## Extends

- `Omit`\<[`ExtraAuthParams`](/sdks/nextjs/api-reference/types/extraauthparams), `"authenticatorHint"` \| `"loginHint"` \| `"prompt"`\>

## Properties

| Property                            | Type                                                                                  | Description                                                                                                                     |
| ----------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `acrValues?` | `string`[]                                                                            | Authentication Context Class Reference (ACR) values requesting specific authentication assurance levels or methods.             |
| `display?`     | [`DisplayOptions`](/sdks/nextjs/api-reference/enums/displayoptions) | Preferred display mode for the authentication UI.                                                                               |
| `maxAge?`       | `number`                                                                              | Maximum acceptable time (in seconds) since the user last authenticated. If exceeded, the user may be required to sign in again. |
| `resource?`   | `string`                                                                              | Space-separated list of resource indicators that scope the issued access token.                                                 |
| `returnUrl?` | `string`                                                                              | URL to redirect to after successful sign-up.                                                                                    |
| `scopes?`       | `string`                                                                              | Space-separated list of scopes requested during authentication.                                                                 |
| `uiLocales?` | `string`                                                                              | Preferred UI language.                                                                                                          |
