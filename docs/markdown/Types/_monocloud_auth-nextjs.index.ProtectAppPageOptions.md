---
rootSdk: Next.js
title: "ProtectAppPageOptions"
category: Types
---

# Type: ProtectAppPageOptions

Options for configuring `protectPage()` in the App Router.

## Extends

- [`GroupOptions`](/sdks/nextjs/api-reference/types/groupoptions)

## Properties

| Property                                                | Type                                                                                                                                                                                                                                                                     | Description                                                                                                                                                                                     |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `authParams?`                   | [`ExtraAuthParams`](/sdks/nextjs/api-reference/types/extraauthparams)                                                                                                                                                                                                     | Additional authorization parameters applied when redirecting the user to authenticate.                                                                                                          |
| `groups?`                           | `string`[]                                                                                                                                                                                                                                                               | A list of group IDs or group names the authenticated user must belong to. Group membership is evaluated using the configured `groupsClaim` from the user session.                               |
| `groupsClaim?`                 | `string`                                                                                                                                                                                                                                                                 | The name of the claim in the user profile that contains group information. This value is read from the authenticated user's session.                                                            |
| `matchAll?`                       | `boolean`                                                                                                                                                                                                                                                                | Determines how multiple groups are evaluated. When `true`, the user must belong to **all** specified groups for authorization to succeed. Otherwise, membership in any one group is sufficient. |
| `onAccessDenied?`           | (`props`: \{ `params?`: `Record`\<`string`, `string` \| `string`[]\>; `searchParams?`: `Record`\<`string`, `string` \| `string`[] \| `undefined`\>; \}) => `Element` \| `Promise`\<`Element`\>                                                                           | Alternate Server Component rendered when the user is **not authenticated**. If not provided, the default behavior redirects the user to the sign-in flow.                                       |
| `onGroupAccessDenied?` | (`props`: \{ `params?`: `Record`\<`string`, `string` \| `string`[]\>; `searchParams?`: `Record`\<`string`, `string` \| `string`[] \| `undefined`\>; `user`: [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser); \}) => `Element` \| `Promise`\<`Element`\> | Alternate Server Component rendered when the user is authenticated but does **not** belong to the required groups. Receives the resolved authenticated user.                                    |
| `returnUrl?`                     | `string`                                                                                                                                                                                                                                                                 | The URL the user should be returned to after successful authentication. Defaults to the current request URL.                                                                                    |
