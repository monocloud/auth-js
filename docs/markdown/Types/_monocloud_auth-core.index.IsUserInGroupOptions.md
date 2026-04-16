---
rootSdk: Node.js
title: "IsUserInGroupOptions"
category: Types
---

# Type: IsUserInGroupOptions

Options for configuring group membership validation on access tokens.

## Properties

| Property                                | Type      | Description                                                                                                                   |
| --------------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `groupsClaim?` | `string`  | The claim name in the token that contains group memberships.                                                                  |
| `matchAll?`       | `boolean` | When `true`, requires the token to contain all specified groups. When `false`, requires at least one of the specified groups. |
