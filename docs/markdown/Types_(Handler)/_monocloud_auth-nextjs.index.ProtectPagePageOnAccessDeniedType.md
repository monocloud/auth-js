---
rootSdk: Next.js
title: "ProtectPagePageOnAccessDeniedType"
category: Handler Types
description: "Handler invoked when no valid session exists while running a Pages Router getServerSideProps protected by protectPage()."
---

# Handler Type: ProtectPagePageOnAccessDeniedType

> **ProtectPagePageOnAccessDeniedType**\<`P`, `Q`\> = (`context`: `GetServerSidePropsContext`\<`Q`\>) => `Promise`\<`GetServerSidePropsResult`\<`P`\>\> \| `GetServerSidePropsResult`\<`P`\>

Handler invoked when no valid session exists while running a Pages Router `getServerSideProps` protected by [protectPage()](/sdks/nextjs/api-reference/functions/protectpage).

## Type Parameters

| Type Parameter                 | Description                               |
| ------------------------------ | ----------------------------------------- |
| `P`                            | Props returned from `getServerSideProps`. |
| `Q` _extends_ `ParsedUrlQuery` | Query parameters parsed from the URL.     |

## Parameters

| Parameter | Type                               | Description                               |
| --------- | ---------------------------------- | ----------------------------------------- |
| `context` | `GetServerSidePropsContext`\<`Q`\> | The Next.js `getServerSideProps` context. |

## Returns

`Promise`\<`GetServerSidePropsResult`\<`P`\>\> \| `GetServerSidePropsResult`\<`P`\>

A `getServerSideProps` result.
