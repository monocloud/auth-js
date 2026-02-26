---
rootSdk: js-core
title: "SignInOptions"
category: Types
---

# Type: SignInOptions

Options for `signIn()`.

## Properties

| Property                                            | Type                                                                                     | Description                                                                                                                                  |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `acrValues?`                 | `string`[]                                                                               | An array of authentication context class references (ACRs).                                                                                  |
| `appState?`                   | [`ApplicationState`](/sdks/js-core/api-reference/types/applicationstate)                  | Additional custom application-specific state information.                                                                                    |
| `authenticatorHint?` | [`Authenticators`](/sdks/js-core/api-reference/enums/authenticators)   | Specifies the preferred authenticator for sign-in.                                                                                           |
| `display?`                     | [`DisplayOptions`](/sdks/js-core/api-reference/enums/displayoptions)   | The desired user interface mode.                                                                                                             |
| `loginHint?`                 | `string`                                                                                 | Provides a hint about the user's login identifier. Used to pre-fill or suggest a username. **Example** `"user@example.com"`                  |
| `maxAge?`                       | `number`                                                                                 | Maximum allowed time (in seconds) since the user's last authentication. Used to force re-authentication if the last login exceeds this time. |
| `mode?`                           | [`InteractionMode`](/sdks/js-core/api-reference/enums/interactionmode) | Determines the interaction mode for sign-in.                                                                                                 |
| `prompt?`                       | [`Prompt`](/sdks/js-core/api-reference/enums/prompt)                   | The desired authentication behavior.                                                                                                         |
| `resource?`                   | `string`                                                                                 | Space-separated resources the access token should be scoped to.                                                                              |
| `returnUrl?`                 | `string`                                                                                 | Relative path to return to after sign-in.                                                                                                    |
| `scopes?`                       | `string`                                                                                 | Space-separated scopes requested from the authorization server.                                                                              |
| `signUp?`                       | `boolean`                                                                                | When `true`, starts the sign-up flow.                                                                                                        |
| `uiLocales?`                 | `string`                                                                                 | Specifies preferred locales for the sign-in page. **Example** `"en-US"`                                                                      |
