---
rootSdk: Next.js
title: "GroupOptions"
category: Types
---

# Type: GroupOptions

Configuration options that require the user to belong to specific groups.

## Extends

- [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions)

## Extended by

- [`ProtectOptions`](/sdks/nextjs/api-reference/types/protectoptions)
- [`ProtectApiAppOptions`](/sdks/nextjs/api-reference/types/protectapiappoptions)
- [`ProtectApiPageOptions`](/sdks/nextjs/api-reference/types/protectapipageoptions)
- [`ProtectAppPageOptions`](/sdks/nextjs/api-reference/types/protectapppageoptions)
- [`ProtectPagePageOptions`](/sdks/nextjs/api-reference/types/protectpagepageoptions)
- [`ProtectClientPageOptions`](/sdks/nextjs/api-reference/types/protectclientpageoptions)

## Properties

| Property                                | Type       | Description                                                                                                                                                                                     |
| --------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `groups?`           | `string`[] | A list of group IDs or group names the authenticated user must belong to. Group membership is evaluated using the configured `groupsClaim` from the user session.                               |
| `groupsClaim?` | `string`   | The name of the claim in the user profile that contains group information. This value is read from the authenticated user's session.                                                            |
| `matchAll?`       | `boolean`  | Determines how multiple groups are evaluated. When `true`, the user must belong to **all** specified groups for authorization to succeed. Otherwise, membership in any one group is sufficient. |
