---
rootSdk: React
title: "SignInOptions"
category: Types
description: "Options used to customize the sign-in flow."
---

# Type: SignInOptions

Options used to customize the sign-in flow.

## Properties

| Property                                            | Type                                                                             | Description                                                                                                                                                                                                                      |
| --------------------------------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `acrValues?`                 | `string`[]                                                                       | Authentication Context Class Reference (ACR) values requesting specific authentication assurance levels or methods.                                                                                                              |
| `appState?`                   | [`ApplicationState`](/sdks/react/api-reference/types/applicationstate)                  | Custom application state preserved across the authentication round-trip. The value is provided to the [OnSessionCreating](/sdks/react/api-reference/handler-types/onsessioncreating) hook when the session is constructed. |
| `authenticatorHint?` | [`Authenticators`](/sdks/react/api-reference/enums/authenticators)   | Specifies the preferred authenticator or identity provider to use for sign-in.                                                                                                                                                   |
| `display?`                     | [`DisplayOptions`](/sdks/react/api-reference/enums/displayoptions)   | Preferred display mode for the authentication UI.                                                                                                                                                                                |
| `loginHint?`                 | `string`                                                                         | Hint identifying the user (for example, an email or username). Used to pre-fill or optimize the sign-in experience. **Example** `"user@example.com"`                                                                             |
| `maxAge?`                       | `number`                                                                         | Maximum allowed time (in seconds) since the user's last authentication. Used to force re-authentication if the time since the last sign-in exceeds this value.                                                                   |
| `mode?`                           | [`InteractionMode`](/sdks/react/api-reference/enums/interactionmode) | Determines the interaction mode for the sign-in flow.                                                                                                                                                                            |
| `prompt?`                       | [`Prompt`](/sdks/react/api-reference/enums/prompt)                   | Specifies the desired authentication interaction behavior.                                                                                                                                                                       |
| `resource?`                   | `string`                                                                         | Space-separated resources the access token should be scoped to for this specific sign-in. Merged with `defaultAuthParams.resource` and any indicator resources configured on the client.                                         |
| `returnUrl?`                 | `string`                                                                         | Relative URL to navigate to after sign-in completes.                                                                                                                                                                             |
| `scopes?`                       | `string`                                                                         | Space-separated scopes requested from the authorization server for this specific sign-in. Merged with `defaultAuthParams.scopes` and any indicator scopes configured on the client.                                              |
| `signUp?`                       | `boolean`                                                                        | When `true`, starts the sign-up (user registration) flow instead of a standard sign-in. Equivalent to setting `prompt: 'create'`. If both are provided, `signUp: true` wins.                                                     |
| `uiLocales?`                 | `string`                                                                         | Preferred locale(s) for the sign-in UI. **Example** `"en-US"`                                                                                                                                                                    |
