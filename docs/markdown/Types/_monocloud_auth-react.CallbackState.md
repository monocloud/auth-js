---
rootSdk: @monocloud/auth-react
title: "CallbackState"
category: Types
description: "Internal state persisted between an authorization request and its callback."
---

# Type: CallbackState

Internal state persisted between an authorization request and its callback.

## Extends

- `Partial`\<[`AuthState`](/sdks/nodejs/api-reference/types/authstate)\>

## Properties

| Property                                  | Type                                                                         | Description                                                                                                               |
| ----------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `appState?`         | [`ApplicationState`](/sdks/react/api-reference/types/applicationstate)              | Custom application state associated with the request.                                                                     |
| `codeVerifier?` | `string`                                                                     | Optional. PKCE code verifier used to validate the authorization code exchange.                                            |
| `maxAge?`             | `number`                                                                     | Optional. Maximum allowed time (in seconds) since the user's last authentication.                                         |
| `mode`                  | `"popup"` \| `"redirect"` \| `"silent"`                                      | Interaction mode used to initiate the original authorization request.                                                     |
| `nonce?`               | `string`                                                                     | A cryptographic value used to associate the ID token with the original authentication request and prevent replay attacks. |
| `resource?`         | `string`                                                                     | Optional. Space-separated list of resource indicators requested for the access token.                                     |
| `responseType?` | [`ResponseTypes`](/sdks/react/api-reference/enums/responsetypes) | Response type requested during authorization.                                                                             |
| `returnUrl?`       | `string`                                                                     | URL to navigate to after the callback has been processed.                                                                 |
| `scopes?`             | `string`                                                                     | Space-separated list of scopes requested during authorization.                                                            |
| `signOut?`           | `boolean`                                                                    | Indicates whether the callback represents a sign-out flow.                                                                |
| `state?`               | `string`                                                                     | A unique value used to correlate the authorization request with the callback and protect against CSRF attacks.            |
