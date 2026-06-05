---
rootSdk: @monocloud/auth-react
title: "MonoCloudTokens"
category: Types
description: "Tokens available in the current session."
---

# Type: MonoCloudTokens

Tokens available in the current session.

Extends [AccessToken](/sdks/react/api-reference/types/accesstoken) with the ID token, refresh token, and a convenience flag indicating whether the access token has expired.

## Extends

- [`AccessToken`](/sdks/react/api-reference/types/accesstoken)

## Properties

| Property                                                   | Type      | Description                                                                                                                                 |
| ---------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `accessToken`                     | `string`  | The issued access token.                                                                                                                    |
| `accessTokenExpiration` | `number`  | The expiration time of the access token (Unix epoch, in seconds).                                                                           |
| `idToken?`                            | `string`  | ID token issued during authentication.                                                                                                      |
| `isExpired`                         | `boolean` | Indicates whether the access token is expired at the time of evaluation.                                                                    |
| `refreshToken?`                  | `string`  | Refresh token issued during authentication, if any.                                                                                         |
| `requestedScopes?`            | `string`  | Optional space-separated list of scopes originally requested during token acquisition.                                                      |
| `resource?`                          | `string`  | Optional resource (audience) that the access token is scoped for.                                                                           |
| `scopes`                               | `string`  | Space-separated list of scopes granted to the access token. These represent the effective permissions approved by the authorization server. |
