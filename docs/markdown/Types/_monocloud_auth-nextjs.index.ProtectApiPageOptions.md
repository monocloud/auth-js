---
rootSdk: Next.js
title: "ProtectApiPageOptions"
category: Types
---

# Type: ProtectApiPageOptions

Options for configuring `protectApi()` in the Pages Router.

## Extends

- [`GroupOptions`](/sdks/nextjs/api-reference/types/groupoptions)

## Properties

| Property                                                | Type                                                                                                                                      | Description                                                                                                                                                                                     |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `groups?`                           | `string`[]                                                                                                                                | A list of group IDs or group names the authenticated user must belong to. Group membership is evaluated using the configured `groupsClaim` from the user session.                               |
| `groupsClaim?`                 | `string`                                                                                                                                  | The name of the claim in the user profile that contains group information. This value is read from the authenticated user's session.                                                            |
| `matchAll?`                       | `boolean`                                                                                                                                 | Determines how multiple groups are evaluated. When `true`, the user must belong to **all** specified groups for authorization to succeed. Otherwise, membership in any one group is sufficient. |
| `onAccessDenied?`           | [`PageRouterApiOnAccessDeniedHandler`](/sdks/nextjs/api-reference/handler-types/pagerouterapionaccessdeniedhandler)           | Alternate API handler invoked when the request is unauthenticated.                                                                                                                              |
| `onGroupAccessDenied?` | [`PageRouterApiOnGroupAccessDeniedHandler`](/sdks/nextjs/api-reference/handler-types/pagerouterapiongroupaccessdeniedhandler) | Alternate API handler invoked when the user is authenticated but does not satisfy the configured group authorization rules.                                                                     |
