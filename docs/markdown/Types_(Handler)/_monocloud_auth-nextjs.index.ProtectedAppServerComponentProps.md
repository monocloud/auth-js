---
rootSdk: Next.js
title: "ProtectedAppServerComponentProps"
category: Handler Types
description: "Props injected into an App Router Server Component wrapped by protectPage()."
---

# Handler Type: ProtectedAppServerComponentProps

Props injected into an App Router Server Component wrapped by [protectPage()](/sdks/nextjs/api-reference/functions/protectpage).

Includes the authenticated `user` and optional route/search parameters provided by Next.js.

## Properties

| Property                                  | Type                                                                      | Description                                               |
| ----------------------------------------- | ------------------------------------------------------------------------- | --------------------------------------------------------- |
| `params?`             | `Record`\<`string`, `string` \| `string`[]\>                              | Dynamic route parameters provided by the App Router.      |
| `searchParams?` | `Record`\<`string`, `string` \| `string`[] \| `undefined`\>               | URL search parameters provided by the App Router.         |
| `user`                  | [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser) | The authenticated user resolved from the current session. |
