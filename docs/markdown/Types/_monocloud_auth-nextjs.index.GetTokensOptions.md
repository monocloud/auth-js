---
rootSdk: Next.js
title: "GetTokensOptions"
category: Types
---

# Type: GetTokensOptions

Options used to control token retrieval and refresh behavior when calling `getTokens()`.

## Extends

- [`RefreshGrantOptions`](/sdks/nodejs/api-reference/types/refreshgrantoptions)

## Properties

| Property                                        | Type      | Description                                                                                                                                                                                   |
| ----------------------------------------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `forceRefresh?`       | `boolean` | When `true`, forces a refresh of the access token even if the current token has not expired.                                                                                                  |
| `refetchUserInfo?` | `boolean` | When enabled, refetches user information from the `UserInfo` endpoint after tokens are refreshed.                                                                                             |
| `resource?`               | `string`  | Space-separated list of resource indicators that the new access token should be issued for. The requested resources must have been previously granted during the original authorization flow. |
| `scopes?`                   | `string`  | Space-separated list of scopes to request for the refreshed access token. The requested scopes must have been granted during the original authorization flow.                                 |
