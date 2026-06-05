---
rootSdk: @monocloud/auth-react
title: "SignInSilentOptions"
category: Types
description: "Options used to customize the silent sign-in flow."
---

# Type: SignInSilentOptions

Options used to customize the silent sign-in flow.

## Properties

| Property                            | Type                                                            | Description                                                                                                                                                                                                                                       |
| ----------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `acrValues?` | `string`[]                                                      | Authentication Context Class Reference (ACR) values requesting specific authentication assurance levels or methods. If the existing session does not satisfy the requested ACR, the authorization server will reject with `interaction_required`. |
| `appState?`   | [`ApplicationState`](/sdks/react/api-reference/types/applicationstate) | Custom application state preserved across the silent authentication round-trip. The value is provided to the [OnSessionCreating](/sdks/react/api-reference/handler-types/onsessioncreating) hook when the session is constructed.           |
| `loginHint?` | `string`                                                        | Hint identifying the user (for example, an email or username). Helps the authorization server disambiguate when multiple sessions are present. **Example** `"user@example.com"`                                                                   |
| `maxAge?`       | `number`                                                        | Maximum allowed time (in seconds) since the user's last authentication. If the existing session is older than this value, the authorization server cannot satisfy the silent request and will reject with `login_required`.                       |
| `resource?`   | `string`                                                        | Space-separated resources the access token should be scoped to for this specific silent sign-in. Merged with `defaultAuthParams.resource` and any indicator resources configured on the client.                                                   |
| `scopes?`       | `string`                                                        | Space-separated scopes requested from the authorization server for this specific silent sign-in. Merged with `defaultAuthParams.scopes` and any indicator scopes configured on the client.                                                        |
