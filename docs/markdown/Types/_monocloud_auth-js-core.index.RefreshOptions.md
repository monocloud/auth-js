---
rootSdk: js-core
title: "RefreshOptions"
category: Types
---

# Type: RefreshOptions

Options for `refreshSession()`.

## Properties

| Property                                                | Type                                                                             | Description                                                                                                                                                     |
| ------------------------------------------------------- | -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `appState?`                       | [`ApplicationState`](/sdks/js-core/api-reference/types/applicationstate)          | Additional custom application-specific state information.                                                                                                       |
| `mode?`                               | [`RefreshMode`](/sdks/js-core/api-reference/enums/refreshmode) | Determines the interaction mode for the session refresh process. Using `popup` or `silent` starts a new authorization request and replaces the current session. |
| `refreshGrantOptions?` | [`RefreshGrantOptions`](/sdks/js-core/api-reference/types/refreshgrantoptions)    | Configuration specific to the Refresh Token Grant flow.                                                                                                         |
