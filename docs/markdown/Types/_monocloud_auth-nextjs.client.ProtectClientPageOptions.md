---
rootSdk: Next.js
title: "ProtectClientPageOptions"
category: Types
description: "Options for configuring page protection."
---

# Type: ProtectClientPageOptions

Options for configuring page protection.

## Extends

- [`GroupOptions`](/sdks/nextjs/api-reference/types/groupoptions)

## Properties

| Property                                                | Type                                                                                      | Description                                                                                                                                                                                     |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `authParams?`                   | [`ExtraAuthParams`](/sdks/nextjs/api-reference/types/extraauthparams)                      | Authorization parameters to be used during authentication.                                                                                                                                      |
| `groups?`                           | `string`[]                                                                                | A list of group IDs or group names the authenticated user must belong to. Group membership is evaluated using the configured `groupsClaim` from the user session.                               |
| `groupsClaim?`                 | `string`                                                                                  | The name of the claim in the user profile that contains group information. This value is read from the authenticated user's session.                                                            |
| `matchAll?`                       | `boolean`                                                                                 | Determines how multiple groups are evaluated. When `true`, the user must belong to **all** specified groups for authorization to succeed. Otherwise, membership in any one group is sufficient. |
| `onAccessDenied?`           | () => `ReactNode`                                                                         | A custom react element to render when the user is not authenticated.                                                                                                                            |
| `onError?`                         | (`error`: `Error`) => `ReactNode`                                                         | Callback function to handle errors. If not provided, errors will be thrown.                                                                                                                     |
| `onGroupAccessDenied?` | (`user`: [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser)) => `ReactNode` | A custom react element to render when the user is authenticated but does not belong to the required groups.                                                                                     |
| `returnUrl?`                     | `string`                                                                                  | The URL where the user will be redirected to after sign in.                                                                                                                                     |
