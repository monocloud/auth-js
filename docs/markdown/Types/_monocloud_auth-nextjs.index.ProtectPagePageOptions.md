---
rootSdk: Next.js
title: "ProtectPagePageOptions"
category: Types
---

# Type: ProtectPagePageOptions

Options for configuring [protectPage()](/sdks/nextjs/api-reference/functions/protectpage) in the Pages Router.

## Extends

- [`GroupOptions`](/sdks/nextjs/api-reference/types/groupoptions)

## Type Parameters

| Type Parameter                            | Description                               |
| ----------------------------------------- | ----------------------------------------- |
| `P` _extends_ `Record`\<`string`, `any`\> | Props returned from `getServerSideProps`. |
| `Q` _extends_ `ParsedUrlQuery`            | Query parameters parsed from the URL.     |

## Properties

| Property                                                | Type                                                                                                                                                | Description                                                                                                                                                                                                                                           |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `authParams?`                   | [`ExtraAuthParams`](/sdks/nextjs/api-reference/types/extraauthparams)                                                                                | Additional authorization parameters applied when redirecting the user to authenticate.                                                                                                                                                                |
| `getServerSideProps?`   | `GetServerSideProps`\<`P`, `Q`\>                                                                                                                    | An optional `getServerSideProps` implementation that runs after authentication (and group checks, if configured). Use this to compute additional props for the page.                                                                                  |
| `groups?`                           | `string`[]                                                                                                                                          | A list of group IDs or group names the authenticated user must belong to. Group membership is evaluated using the configured `groupsClaim` from the user session.                                                                                     |
| `groupsClaim?`                 | `string`                                                                                                                                            | The name of the claim in the user profile that contains group information. This value is read from the authenticated user's session.                                                                                                                  |
| `matchAll?`                       | `boolean`                                                                                                                                           | Determines how multiple groups are evaluated. When `true`, the user must belong to **all** specified groups for authorization to succeed. Otherwise, membership in any one group is sufficient.                                                       |
| `onAccessDenied?`           | [`ProtectPagePageOnAccessDeniedType`](/sdks/nextjs/api-reference/handler-types/protectpagepageonaccessdeniedtype)\<`P`, `Q`\>           | Called when no valid session exists. If not provided, the default behavior redirects the user to the sign-in flow.                                                                                                                                    |
| `onGroupAccessDenied?` | [`ProtectPagePageOnGroupAccessDeniedType`](/sdks/nextjs/api-reference/handler-types/protectpagepageongroupaccessdeniedtype)\<`P`, `Q`\> | Called when the user is authenticated but does not satisfy the group requirements. If not provided, the default behavior continues rendering and sets `groupAccessDenied` in the returned props, or applies the SDK’s default access-denied behavior. |
| `returnUrl?`                     | `string`                                                                                                                                            | The URL the user should be returned to after successful authentication. Defaults to the current request URL.                                                                                                                                          |
