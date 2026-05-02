---
rootSdk: Next.js
title: "ProtectOptions"
category: Types
description: "Options for configuring protect()."
---

# Type: ProtectOptions

Options for configuring [protect()](/sdks/nextjs/api-reference/functions/protect).

## Extends

- [`GroupOptions`](/sdks/nextjs/api-reference/types/groupoptions)

## Properties

| Property                                | Type                                                                 | Description                                                                                                                                                                                     |
| --------------------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `authParams?`   | [`ExtraAuthParams`](/sdks/nextjs/api-reference/types/extraauthparams) | Additional authorization parameters to include when redirecting the user to the sign-in flow.                                                                                                   |
| `groups?`           | `string`[]                                                           | A list of group IDs or group names the authenticated user must belong to. Group membership is evaluated using the configured `groupsClaim` from the user session.                               |
| `groupsClaim?` | `string`                                                             | The name of the claim in the user profile that contains group information. This value is read from the authenticated user's session.                                                            |
| `matchAll?`       | `boolean`                                                            | Determines how multiple groups are evaluated. When `true`, the user must belong to **all** specified groups for authorization to succeed. Otherwise, membership in any one group is sufficient. |
| `returnUrl?`     | `string`                                                             | The URL to return to after successful authentication. If not provided, the current request URL is used.                                                                                         |
