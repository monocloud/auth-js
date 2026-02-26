---
rootSdk: js-core
title: "MonoCloudTokens"
category: Types
---

# Type: MonoCloudTokens

Tokens available in the current session.

## Extends

- [`AccessToken`](/sdks/js-core/api-reference/types/accesstoken)

## Properties

| Property                                                   | Type      | Description                                                                                                                                 |
| ---------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `accessToken`                     | `string`  | The issued access token.                                                                                                                    |
| `accessTokenExpiration` | `number`  | The expiration time of the access token (Unix epoch, in seconds).                                                                           |
| `idToken?`                            | `string`  | The ID token obtained during authentication.                                                                                                |
| `isExpired`                         | `boolean` | Specifies if the access token has expired.                                                                                                  |
| `refreshToken?`                  | `string`  | The refresh token obtained during authentication.                                                                                           |
| `requestedScopes?`            | `string`  | Optional space-separated list of scopes originally requested during token acquisition.                                                      |
| `resource?`                          | `string`  | Optional resource (audience) that the access token is scoped for.                                                                           |
| `scopes`                               | `string`  | Space-separated list of scopes granted to the access token. These represent the effective permissions approved by the authorization server. |
