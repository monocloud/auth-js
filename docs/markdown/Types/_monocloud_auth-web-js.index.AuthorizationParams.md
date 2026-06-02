---
rootSdk: JavaScript
title: "AuthorizationParams"
category: Types
description: "Parameters used to construct an OAuth 2.0 / OpenID Connect authorization request."
---

# Type: AuthorizationParams

Parameters used to construct an OAuth 2.0 / OpenID Connect authorization request.

## Properties

| Property                                                | Type                                                                                            | Description                                                                                                                                                              |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `acrValues?`                     | `string`[]                                                                                      | Authentication Context Class Reference (ACR) values requesting specific authentication assurance levels or methods.                                                      |
| `authenticatorHint?`     | [`Authenticators`](/sdks/web-js/api-reference/enums/authenticators)           | Hint to the authorization server indicating which authenticator or connection should be used.                                                                            |
| `codeChallenge?`             | `string`                                                                                        | PKCE code challenge derived from the code verifier. Used to secure authorization code exchanges.                                                                         |
| `codeChallengeMethod?` | [`CodeChallengeMethod`](/sdks/web-js/api-reference/enums/codechallengemethod) | Method used to generate the PKCE code challenge.                                                                                                                         |
| `display?`                         | [`DisplayOptions`](/sdks/web-js/api-reference/enums/displayoptions)           | Preferred display mode for the authentication UI.                                                                                                                        |
| `loginHint?`                     | `string`                                                                                        | Hint identifying the user (for example, email or username). Used to prefill or optimize the sign-in experience.                                                          |
| `maxAge?`                           | `number`                                                                                        | Maximum acceptable time (in seconds) since the user last authenticated. If exceeded, the user may be required to sign in again.                                          |
| `nonce?`                             | `string`                                                                                        | A cryptographically random value included in the ID token to prevent replay attacks.                                                                                     |
| `prompt?`                           | [`Prompt`](/sdks/web-js/api-reference/enums/prompt)                           | Controls authentication interaction behavior. For example, forcing login or consent.                                                                                     |
| `redirectUri?`                 | `string`                                                                                        | The redirect URI where the authorization server sends the user after authentication completes.                                                                           |
| `request?`                         | `string`                                                                                        | A signed JWT containing authorization request parameters.                                                                                                                |
| `requestUri?`                   | `string`                                                                                        | URI referencing a previously created authorization request (typically via Pushed Authorization Requests — PAR). When set, other authorization parameters may be ignored. |
| `resource?`                       | `string`                                                                                        | Space-separated list of resource indicators that scope the issued access token.                                                                                          |
| `responseMode?`               | [`ResponseModes`](/sdks/web-js/api-reference/enums/responsemodes)             | Specifies how the authorization response is returned to the client.                                                                                                      |
| `responseType?`               | [`ResponseTypes`](/sdks/web-js/api-reference/enums/responsetypes)             | Determines which artifacts are returned from the authorization endpoint.                                                                                                 |
| `scopes?`                           | `string`                                                                                        | Space-separated list of scopes requested during authentication.                                                                                                          |
| `state?`                             | `string`                                                                                        | A cryptographically random value used to maintain request state and protect against CSRF attacks.                                                                        |
| `uiLocales?`                     | `string`                                                                                        | Preferred UI language.                                                                                                                                                   |
