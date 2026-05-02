---
rootSdk: Next.js
title: "ProtectPagePageOnGroupAccessDeniedType"
category: Handler Types
description: "Handler invoked when an authenticated user does not satisfy the required group restrictions while running a Pages Router getServerSideProps protected by protectPage()."
---

# Handler Type: ProtectPagePageOnGroupAccessDeniedType

> **ProtectPagePageOnGroupAccessDeniedType**\<`P`, `Q`\> = (`context`: [`ProtectPageGetServerSidePropsContext`](/sdks/nextjs/api-reference/handler-types/protectpagegetserversidepropscontext)\<`Q`\>) => `Promise`\<`GetServerSidePropsResult`\<`P`\>\> \| `GetServerSidePropsResult`\<`P`\>

Handler invoked when an authenticated user does not satisfy the required group restrictions while running a Pages Router `getServerSideProps` protected by [protectPage()](/sdks/nextjs/api-reference/functions/protectpage).

## Type Parameters

| Type Parameter                 | Description                               |
| ------------------------------ | ----------------------------------------- |
| `P`                            | Props returned from `getServerSideProps`. |
| `Q` _extends_ `ParsedUrlQuery` | Query parameters parsed from the URL.     |

## Parameters

| Parameter | Type                                                                                                                  | Description                               |
| --------- | --------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| `context` | [`ProtectPageGetServerSidePropsContext`](/sdks/nextjs/api-reference/handler-types/protectpagegetserversidepropscontext)\<`Q`\> | The Next.js `getServerSideProps` context. |

## Returns

`Promise`\<`GetServerSidePropsResult`\<`P`\>\> \| `GetServerSidePropsResult`\<`P`\>

A `getServerSideProps` result.
