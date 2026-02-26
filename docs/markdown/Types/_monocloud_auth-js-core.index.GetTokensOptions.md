---
rootSdk: js-core
title: "GetTokensOptions"
category: Types
---

# Type: GetTokensOptions

Options for `getTokens()`.

## Extends

- [`RefreshGrantOptions`](/sdks/js-core/api-reference/types/refreshgrantoptions)

## Properties

| Property                                        | Type      | Description                                                                                                                                                                                   |
| ----------------------------------------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `forceRefresh?`       | `boolean` | Specifies whether to force the refresh of the access token.                                                                                                                                   |
| `refetchUserInfo?` | `boolean` | Determines whether to refetch the user information.                                                                                                                                           |
| `resource?`               | `string`  | Space-separated list of resource indicators that the new access token should be issued for. The requested resources must have been previously granted during the original authorization flow. |
| `scopes?`                   | `string`  | Space-separated list of scopes to request for the refreshed access token. The requested scopes must have been granted during the original authorization flow.                                 |
