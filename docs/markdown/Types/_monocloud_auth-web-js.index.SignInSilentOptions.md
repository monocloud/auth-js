---
rootSdk: JavaScript
title: "SignInSilentOptions"
category: Types
description: "Options used to customize the silent sign-in flow."
---

# Type: SignInSilentOptions

Options used to customize the silent sign-in flow.

## Properties

| Property                          | Type                                                                   | Description                                                                                                                                                                                                                                    |
| --------------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `appState?` | [`ApplicationState`](/sdks/web-js/api-reference/types/applicationstate) | Custom application state preserved across the silent authentication round-trip. The value is provided to the [OnSessionCreating](/sdks/web-js/api-reference/handler-types/onsessioncreating) hook when the session is constructed. |
| `resource?` | `string`                                                               | Space-separated resources the access token should be scoped to for this specific silent sign-in. Merged with `defaultAuthParams.resource` and any indicator resources configured on the client.                                                |
| `scopes?`     | `string`                                                               | Space-separated scopes requested from the authorization server for this specific silent sign-in. Merged with `defaultAuthParams.scopes` and any indicator scopes configured on the client.                                                     |
