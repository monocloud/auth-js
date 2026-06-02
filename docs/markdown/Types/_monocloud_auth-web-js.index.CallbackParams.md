---
rootSdk: JavaScript
title: "CallbackParams"
category: Types
description: "Parameters returned to the application after the authorization server redirects the user back to the callback URL."
---

# Type: CallbackParams

Parameters returned to the application after the authorization server redirects the user back to the callback URL.

## Properties

| Property                                          | Type     | Description                                                                                                                |
| ------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------- |
| `accessToken?`           | `string` | Access token returned directly by implicit or hybrid flows.                                                                |
| `code?`                         | `string` | Authorization code returned when using the Authorization Code Flow.                                                        |
| `error?`                       | `string` | Error code returned when authorization fails.                                                                              |
| `errorDescription?` | `string` | Human-readable description providing additional information about the authorization error.                                 |
| `expiresIn?`               | `number` | Lifetime of the access token in seconds.                                                                                   |
| `idToken?`                   | `string` | ID token issued by the authorization server.                                                                               |
| `refreshToken?`         | `string` | Refresh token issued during authorization (if enabled).                                                                    |
| `scope?`                       | `string` | Access token scopes (Implicit Flow)                                                                                        |
| `sessionState?`         | `string` | OIDC session state value used for session monitoring and front-channel session management.                                 |
| `state?`                       | `string` | The state value originally sent in the authorization request. Used to validate request integrity and prevent CSRF attacks. |
