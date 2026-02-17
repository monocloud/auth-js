---
rootSdk: Node.js
title: "AuthState"
category: Types
---

# Type: AuthState

Represents the authentication transaction state stored between the authorization request and the callback.

## Properties

| Property                                  | Type     | Description                                                                                                               |
| ----------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------- |
| `codeVerifier?` | `string` | Optional. PKCE code verifier used to validate the authorization code exchange.                                            |
| `maxAge?`             | `number` | Optional. Maximum allowed time (in seconds) since the user's last authentication.                                         |
| `nonce`                | `string` | A cryptographic value used to associate the ID token with the original authentication request and prevent replay attacks. |
| `resource?`         | `string` | Optional. Space-separated list of resource indicators requested for the access token.                                     |
| `scopes`              | `string` | Space-separated list of scopes requested during authorization.                                                            |
| `state`                | `string` | A unique value used to correlate the authorization request with the callback and protect against CSRF attacks.            |
