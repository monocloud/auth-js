---
rootSdk: Node.js
title: "AuthenticateOptions"
category: Types
description: "Options used when authenticating a user via the Authorization Code flow."
---

# Type: AuthenticateOptions

Options used when authenticating a user via the Authorization Code flow.

## Properties

| Property                                                    | Type                                                                                        | Description                                                                                                                                                       |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `codeVerifier?`                   | `string`                                                                                    | PKCE code verifier associated with the authorization request.                                                                                                     |
| `fetchUserInfo?`                 | `boolean`                                                                                   | When enabled, user profile data is fetched from the UserInfo endpoint and merged into the session user object.                                                    |
| `filteredIdTokenClaims?` | `string`[]                                                                                  | List of ID token claims to remove before storing the session.                                                                                                     |
| `idTokenClockSkew?`           | `number`                                                                                    | Clock skew adjustment (in seconds) applied when validating ID token timestamps against the authorization server.                                                  |
| `idTokenClockTolerance?` | `number`                                                                                    | Additional allowed clock tolerance (in seconds) when validating time-based ID token claims such as `exp`, `iat`, and `nbf`.                                       |
| `idTokenMaxAge?`                 | `number`                                                                                    | Maximum allowed authentication age (in seconds) for the ID token.                                                                                                 |
| `idTokenNonce?`                   | `string`                                                                                    | Nonce value expected in the ID token. Used to prevent replay attacks.                                                                                             |
| `jwks?`                                   | [`Jwks`](/sdks/nodejs/api-reference/types/jwks)                                                | JSON Web Key Set used to validate the ID token signature. If not provided, the JWKS is automatically fetched from the authorization server metadata.              |
| `onSessionCreating?`         | [`OnSessionCreating`](/sdks/nodejs/api-reference/handler-types/onsessioncreating) | Callback invoked before a session is created or updated. Allows customization or enrichment of the session.                                                       |
| `validateIdToken?`             | `boolean`                                                                                   | Determines whether the ID token signature and claims should be validated. Disabling validation is not recommended except for advanced or controlled environments. |
