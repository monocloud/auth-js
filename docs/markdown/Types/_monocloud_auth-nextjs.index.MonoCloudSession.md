---
rootSdk: Next.js
title: "MonoCloudSession"
category: Types
---

# Type: MonoCloudSession

Represents an authenticated session, containing the authenticated user profile along with the tokens and metadata issued during authentication.

## Indexable

\[`key`: `string`\]: `unknown`

Additional custom properties attached to the session.

These may be added via hooks such as `onSessionCreating`.

## Properties

| Property                                          | Type                                                             | Description                                                                                                                               |
| ------------------------------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `accessTokens?`         | [`AccessToken`](/sdks/nextjs/api-reference/types/accesstoken)[]   | Access tokens associated with the session. Multiple tokens may exist when access tokens are issued for different resources or scope sets. |
| `authorizedScopes?` | `string`                                                         | Space-separated list of scopes authorized for the session.                                                                                |
| `idToken?`                   | `string`                                                         | Optional ID token issued during authentication.                                                                                           |
| `refreshToken?`         | `string`                                                         | Optional refresh token used to obtain new access tokens without requiring the user to re-authenticate.                                    |
| `user`                          | [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser) | The authenticated user profile, typically derived from ID token claims and/or the `UserInfo` endpoint.                                    |
