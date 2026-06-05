---
rootSdk: @monocloud/auth-react
title: "MonoCloudAuth"
category: Types
description: "The current authentication state and the authentication actions."
---

# Type: MonoCloudAuth

The current authentication state and the authentication actions.

## Extends

- [`AuthState`](/sdks/react/api-reference/types/authstate)

## Properties

| Property                                       | Type                                                                                                                                                                            | Description                                                                      |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `error?`                    | `Error`                                                                                                                                                                         | Error encountered during authentication, if any.                                 |
| `getTokens`             | (`options?`: [`GetTokensOptions`](/sdks/react/api-reference/types/gettokensoptions)) => `Promise`\<[`MonoCloudTokens`](/sdks/react/api-reference/types/monocloudtokens)\>                     | Retrieves the active tokens, refreshing them if they have expired.               |
| `isAuthenticated` | `boolean`                                                                                                                                                                       | Flag indicating if the user is authenticated.                                    |
| `isLoading`             | `boolean`                                                                                                                                                                       | Flag indicating if the authentication state is still loading.                    |
| `refetchUserInfo` | () => `Promise`\<`void`\>                                                                                                                                                       | Refetches the user's profile from the UserInfo endpoint and updates the session. |
| `refreshSession`   | (`refreshOptions?`: [`RefreshOptions`](/sdks/react/api-reference/types/refreshoptions)) => `Promise`\<`void`\>                                                                         | Refreshes the current session using the Refresh Token Grant.                     |
| `session?`                | [`MonoCloudSession`](/sdks/react/api-reference/types/monocloudsession)                                                                                                                 | The current session, including tokens and the user, if available.                |
| `signIn`                   | (`signInOptions?`: [`SignInOptions`](/sdks/react/api-reference/types/signinoptions)) => `Promise`\<`void`\>                                                                            | Initiates the sign-in flow.                                                      |
| `signInSilent`       | (`signInSilentOptions?`: [`SignInSilentOptions`](/sdks/react/api-reference/types/signinsilentoptions)) => `Promise`\<[`MonoCloudSession`](/sdks/react/api-reference/types/monocloudsession)\> | Attempts to silently restore the session via a hidden iframe (`prompt=none`).    |
| `signOut`                 | (`signOutOptions?`: [`SignOutOptions`](/sdks/react/api-reference/types/signoutoptions)) => `Promise`\<`void`\>                                                                         | Initiates the sign-out flow.                                                     |
| `user?`                      | [`MonoCloudUser`](/sdks/react/api-reference/types/monoclouduser)                                                                                                                       | The authenticated user's information, if available.                              |
