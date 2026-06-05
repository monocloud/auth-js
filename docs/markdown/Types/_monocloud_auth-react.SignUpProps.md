---
rootSdk: @monocloud/auth-react
title: "SignUpProps"
category: Types
description: "Props for the <SignUp /> component."
---

# Type: SignUpProps

Props for the `<SignUp />` component.

## Extends

- `Omit`\<[`SignInOptions`](/sdks/react/api-reference/types/signinoptions), `"signUp"` \| `"authenticatorHint"` \| `"loginHint"` \| `"prompt"`\>.`ButtonHTMLAttributes`\<`HTMLButtonElement`\>

## Properties

| Property                            | Type                                                                             | Description                                                                                                                                                                                                                      |
| ----------------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `acrValues?` | `string`[]                                                                       | Authentication Context Class Reference (ACR) values requesting specific authentication assurance levels or methods.                                                                                                              |
| `appState?`   | [`ApplicationState`](/sdks/react/api-reference/types/applicationstate)                  | Custom application state preserved across the authentication round-trip. The value is provided to the [OnSessionCreating](/sdks/react/api-reference/handler-types/onsessioncreating) hook when the session is constructed. |
| `children`    | `ReactNode`                                                                      | Content rendered inside the button.                                                                                                                                                                                              |
| `display?`     | [`DisplayOptions`](/sdks/react/api-reference/enums/displayoptions)   | Preferred display mode for the authentication UI.                                                                                                                                                                                |
| `maxAge?`       | `number`                                                                         | Maximum allowed time (in seconds) since the user's last authentication. Used to force re-authentication if the time since the last sign-in exceeds this value.                                                                   |
| `mode?`           | [`InteractionMode`](/sdks/react/api-reference/enums/interactionmode) | Determines the interaction mode for the sign-in flow.                                                                                                                                                                            |
| `resource?`   | `string`                                                                         | Space-separated resources the access token should be scoped to for this specific sign-in. Merged with `defaultAuthParams.resource` and any indicator resources configured on the client.                                         |
| `returnUrl?` | `string`                                                                         | Relative URL to navigate to after sign-in completes.                                                                                                                                                                             |
| `scopes?`       | `string`                                                                         | Space-separated scopes requested from the authorization server for this specific sign-in. Merged with `defaultAuthParams.scopes` and any indicator scopes configured on the client.                                              |
| `uiLocales?` | `string`                                                                         | Preferred locale(s) for the sign-in UI. **Example** `"en-US"`                                                                                                                                                                    |
