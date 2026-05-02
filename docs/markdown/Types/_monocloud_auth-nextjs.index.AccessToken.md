---
rootSdk: Next.js
title: "AccessToken"
category: Types
description: "Represents an OAuth 2.0 access token and its associated metadata."
---

# Type: AccessToken

Represents an OAuth 2.0 access token and its associated metadata.

## Properties

| Property                                                   | Type     | Description                                                                                                                                 |
| ---------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `accessToken`                     | `string` | The issued access token.                                                                                                                    |
| `accessTokenExpiration` | `number` | The expiration time of the access token (Unix epoch, in seconds).                                                                           |
| `requestedScopes?`            | `string` | Optional space-separated list of scopes originally requested during token acquisition.                                                      |
| `resource?`                          | `string` | Optional resource (audience) that the access token is scoped for.                                                                           |
| `scopes`                               | `string` | Space-separated list of scopes granted to the access token. These represent the effective permissions approved by the authorization server. |
