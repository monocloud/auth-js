---
rootSdk: Next.js
title: "IsUserInGroupOptions"
category: Types
---

# Type: IsUserInGroupOptions

Configuration options for evaluating user group membership.

## Extended by

- [`GroupOptions`](/sdks/nextjs/api-reference/types/groupoptions)

## Properties

| Property                                | Type      | Description                                                                                                                                                                                     |
| --------------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `groupsClaim?` | `string`  | The name of the claim in the user profile that contains group information. This value is read from the authenticated user's session.                                                            |
| `matchAll?`       | `boolean` | Determines how multiple groups are evaluated. When `true`, the user must belong to **all** specified groups for authorization to succeed. Otherwise, membership in any one group is sufficient. |
