---
rootSdk: Next.js
title: "RedirectToSignInOptions"
category: Types
---

# Type: RedirectToSignInOptions

Options for `redirectToSignIn()`

## Properties

| Property                                            | Type                                                                                  | Description                                                                                                         |
| --------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `acrValues?`                 | `string`[]                                                                            | Authentication Context Class Reference (ACR) values requesting specific authentication methods or assurance levels. |
| `authenticatorHint?` | [`Authenticators`](/sdks/nextjs/api-reference/enums/authenticators) | Hint to the authorization server indicating which authenticator should be used during sign-in.                      |
| `display?`                     | [`DisplayOptions`](/sdks/nextjs/api-reference/enums/displayoptions) | Preferred display mode for the authentication UI.                                                                   |
| `loginHint?`                 | `string`                                                                              | Hint about the user's identifier (for example, email or username).                                                  |
| `maxAge?`                       | `number`                                                                              | Maximum allowed time (in seconds) since the user's last authentication.                                             |
| `prompt?`                       | [`Prompt`](/sdks/nextjs/api-reference/enums/prompt)                 | Controls whether the authorization server should force specific user interactions during authentication             |
| `resource?`                   | `string`[]                                                                            | Resource indicators the access token should be issued for.                                                          |
| `returnUrl?`                 | `string`                                                                              | URL to return the user to after successful authentication. Must be a relative application URL.                      |
| `scopes?`                       | `string`[]                                                                            | Scopes to request during authentication.                                                                            |
| `uiLocales?`                 | `string`                                                                              | Preferred UI language(s) for the authentication experience.                                                         |
