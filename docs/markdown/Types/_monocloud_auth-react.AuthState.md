---
rootSdk: React
title: "AuthState"
category: Types
description: "The current authentication state."
---

# Type: AuthState

The current authentication state.

## Properties

| Property                                       | Type                                                            | Description                                                       |
| ---------------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------------- |
| `error?`                    | `Error`                                                         | Error encountered during authentication, if any.                  |
| `isAuthenticated` | `boolean`                                                       | Flag indicating if the user is authenticated.                     |
| `isLoading`             | `boolean`                                                       | Flag indicating if the authentication state is still loading.     |
| `session?`                | [`MonoCloudSession`](/sdks/react/api-reference/types/monocloudsession) | The current session, including tokens and the user, if available. |
| `user?`                      | [`MonoCloudUser`](/sdks/react/api-reference/types/monoclouduser)       | The authenticated user's information, if available.               |
