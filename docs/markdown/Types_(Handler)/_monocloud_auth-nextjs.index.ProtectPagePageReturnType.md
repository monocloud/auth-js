---
rootSdk: Next.js
title: "ProtectPagePageReturnType"
category: Handler Types
---

# Handler Type: ProtectPagePageReturnType

> **ProtectPagePageReturnType**\<`P`, `Q`\> = (`context`: `GetServerSidePropsContext`\<`Q`\>) => `Promise`\<`GetServerSidePropsResult`\<`P` & \{ `accessDenied?`: `boolean`; `user`: [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser); \}\>\>

Return type produced by the [protectPage()](/sdks/nextjs/api-reference/functions/protectpage) wrapper for the Pages Router.

Represents a `getServerSideProps` compatible function that resolves authentication before executing page logic and injects the authenticated `user` into the returned props.

## Type Parameters

| Type Parameter                 | Description                               |
| ------------------------------ | ----------------------------------------- |
| `P`                            | Props returned from `getServerSideProps`. |
| `Q` _extends_ `ParsedUrlQuery` | Query parameters parsed from the URL.     |

## Parameters

| Parameter | Type                               |
| --------- | ---------------------------------- |
| `context` | `GetServerSidePropsContext`\<`Q`\> |

## Returns

`Promise`\<`GetServerSidePropsResult`\<`P` & \{ `accessDenied?`: `boolean`; `user`: [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser); \}\>\>
