---
rootSdk: Node.js
title: "RefreshSessionOptions"
category: Types
description: "Options used when refreshing an existing MonoCloud session."
---

# Type: RefreshSessionOptions

Options used when refreshing an existing MonoCloud session.

## Properties

| Property                                                    | Type                                                                                        | Description                                                                                                                                                       |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fetchUserInfo?`                 | `boolean`                                                                                   | When enabled, user profile data is fetched from the UserInfo endpoint and merged into the session user object.                                                    |
| `filteredIdTokenClaims?` | `string`[]                                                                                  | List of ID token claims to remove before storing the session.                                                                                                     |
| `idTokenClockSkew?`           | `number`                                                                                    | Clock skew adjustment (in seconds) applied when validating ID token timestamps against the authorization server.                                                  |
| `idTokenClockTolerance?` | `number`                                                                                    | Additional allowed clock tolerance (in seconds) when validating time-based ID token claims such as `exp`, `iat`, and `nbf`.                                       |
| `jwks?`                                   | [`Jwks`](/sdks/nodejs/api-reference/types/jwks)                                                | JSON Web Key Set used to validate the ID token signature. If not provided, the JWKS is automatically fetched from the authorization server metadata.              |
| `onSessionCreating?`         | [`OnSessionCreating`](/sdks/nodejs/api-reference/handler-types/onsessioncreating) | Callback invoked before a session is created or updated. Allows customization or enrichment of the session.                                                       |
| `refreshGrantOptions?`     | [`RefreshGrantOptions`](/sdks/nodejs/api-reference/types/refreshgrantoptions)                  | Options applied to the refresh token grant request, such as requesting tokens for specific resources or scopes.                                                   |
| `strictProfileSync?`         | `boolean`                                                                                   | When enabled, replaces the existing session user profile with a freshly constructed profile derived from the latest ID token and/or UserInfo response.            |
| `validateIdToken?`             | `boolean`                                                                                   | Determines whether the ID token signature and claims should be validated. Disabling validation is not recommended except for advanced or controlled environments. |
