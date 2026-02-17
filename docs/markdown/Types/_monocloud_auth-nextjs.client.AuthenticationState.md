---
rootSdk: Next.js
title: "AuthenticationState"
category: Types
---

# Type: AuthenticationState

Authentication State returned by `useAuth` hook.

## Properties

| Property                                       | Type                                                             | Description                                                   |
| ---------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------- |
| `error?`                    | `Error`                                                          | Error encountered during authentication, if any.              |
| `isAuthenticated` | `boolean`                                                        | Flag indicating if the user is authenticated.                 |
| `isLoading`             | `boolean`                                                        | Flag indicating if the authentication state is still loading. |
| `refetch`                 | (`refresh?`: `boolean`) => `void`                                | Function to refetch the authentication state.                 |
| `user?`                      | [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser) | The authenticated user's information, if available.           |
