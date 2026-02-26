---
rootSdk: js-core
title: "RefreshGrantOptions"
category: Types
---

# Type: RefreshGrantOptions

Options used when exchanging a refresh token for a new access token.

These parameters allow requesting an access token scoped to specific resources or scopes that were previously authorized by the user.

## Extended by

- [`GetTokensOptions`](/sdks/js-core/api-reference/types/gettokensoptions)

## Properties

| Property                          | Type     | Description                                                                                                                                                                                   |
| --------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `resource?` | `string` | Space-separated list of resource indicators that the new access token should be issued for. The requested resources must have been previously granted during the original authorization flow. |
| `scopes?`     | `string` | Space-separated list of scopes to request for the refreshed access token. The requested scopes must have been granted during the original authorization flow.                                 |
