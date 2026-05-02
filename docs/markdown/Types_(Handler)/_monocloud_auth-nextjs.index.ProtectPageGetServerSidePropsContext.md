---
rootSdk: Next.js
title: "ProtectPageGetServerSidePropsContext"
category: Handler Types
description: "Next.js getServerSideProps context extended with the authenticated user when using protectPage()."
---

# Handler Type: ProtectPageGetServerSidePropsContext

Next.js `getServerSideProps` context extended with the authenticated user when using [protectPage()](/sdks/nextjs/api-reference/functions/protectpage).

## Extends

- `GetServerSidePropsContext`\<`Q`\>

## Type Parameters

| Type Parameter                 |
| ------------------------------ |
| `Q` _extends_ `ParsedUrlQuery` |

## Properties

| Property                 | Type                                                                      | Description                                               |
| ------------------------ | ------------------------------------------------------------------------- | --------------------------------------------------------- |
| `user` | [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser) | The authenticated user resolved from the current session. |
