---
rootSdk: js-core
title: "CallbackState"
category: Types
---

# Type: CallbackState

Internal state persisted between authorization start and callback processing.

## Extends

- `Partial`\<[`AuthState`](/sdks/js-core/api-reference/types/authstate)\>

## Properties

| Property                                  | Type                                                                                 | Description                                                                                                               |
| ----------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `appState?`         | [`ApplicationState`](/sdks/js-core/api-reference/types/applicationstate)              | -                                                                                                                         |
| `codeVerifier?` | `string`                                                                             | Optional. PKCE code verifier used to validate the authorization code exchange.                                            |
| `maxAge?`             | `number`                                                                             | Optional. Maximum allowed time (in seconds) since the user's last authentication.                                         |
| `mode`                  | `"popup"` \| `"redirect"` \| `"silent"`                                              | -                                                                                                                         |
| `nonce?`               | `string`                                                                             | A cryptographic value used to associate the ID token with the original authentication request and prevent replay attacks. |
| `resource?`         | `string`                                                                             | Optional. Space-separated list of resource indicators requested for the access token.                                     |
| `responseType?` | [`ResponseTypes`](/sdks/js-core/api-reference/enums/responsetypes) | -                                                                                                                         |
| `returnUrl?`       | `string`                                                                             | -                                                                                                                         |
| `scopes?`             | `string`                                                                             | Space-separated list of scopes requested during authorization.                                                            |
| `signOut?`           | `boolean`                                                                            | -                                                                                                                         |
| `state?`               | `string`                                                                             | A unique value used to correlate the authorization request with the callback and protect against CSRF attacks.            |
