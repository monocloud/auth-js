---
rootSdk: Node.js Core
title: "MonoCloudTokens"
category: Types
---

# Type: MonoCloudTokens

Represents the token set associated with the currently authenticated user.

This object extends [AccessToken](/sdks/nodejs-core/api-reference/types/accesstoken) and includes additional tokens issued during authentication, along with convenience metadata used by the SDK to indicate token validity.

## Extends

- [`AccessToken`](/sdks/nodejs-core/api-reference/types/accesstoken)

## Properties

| Property                                                   | Type      | Description                                                                                                                                 |
| ---------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `accessToken`                     | `string`  | The issued access token.                                                                                                                    |
| `accessTokenExpiration` | `number`  | The expiration time of the access token (Unix epoch, in seconds).                                                                           |
| `idToken?`                            | `string`  | The ID token issued during authentication. Contains identity claims about the authenticated user.                                           |
| `isExpired`                         | `boolean` | Indicates whether the current access token is expired at the time of evaluation.                                                            |
| `refreshToken?`                  | `string`  | The refresh token used to obtain new access tokens without requiring the user to re-authenticate.                                           |
| `requestedScopes?`            | `string`  | Optional space-separated list of scopes originally requested during token acquisition.                                                      |
| `resource?`                          | `string`  | Optional resource (audience) that the access token is scoped for.                                                                           |
| `scopes`                               | `string`  | Space-separated list of scopes granted to the access token. These represent the effective permissions approved by the authorization server. |
