---
rootSdk: Next.js
title: "ProtectApiAppOptions"
category: Types
---

# Type: ProtectApiAppOptions

Options for configuring [protectApi()](/sdks/nextjs/api-reference/functions/protectapi) in the App Router.

## Extends

- [`GroupOptions`](/sdks/nextjs/api-reference/types/groupoptions)

## Properties

| Property                                                | Type                                                                                                                                    | Description                                                                                                                                                                                     |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `groups?`                           | `string`[]                                                                                                                              | A list of group IDs or group names the authenticated user must belong to. Group membership is evaluated using the configured `groupsClaim` from the user session.                               |
| `groupsClaim?`                 | `string`                                                                                                                                | The name of the claim in the user profile that contains group information. This value is read from the authenticated user's session.                                                            |
| `matchAll?`                       | `boolean`                                                                                                                               | Determines how multiple groups are evaluated. When `true`, the user must belong to **all** specified groups for authorization to succeed. Otherwise, membership in any one group is sufficient. |
| `onAccessDenied?`           | [`AppRouterApiOnAccessDeniedHandler`](/sdks/nextjs/api-reference/handler-types/approuterapionaccessdeniedhandler)           | Alternate API route handler invoked when the request is not authenticated.                                                                                                                      |
| `onGroupAccessDenied?` | [`AppRouterApiOnGroupAccessDeniedHandler`](/sdks/nextjs/api-reference/handler-types/approuterapiongroupaccessdeniedhandler) | Alternate API route handler invoked when the request is authenticated but the user does not satisfy the required group restrictions.                                                            |
