---
rootSdk: Next.js
title: "ProtectedAppServerComponent"
category: Handler Types
---

# Handler Type: ProtectedAppServerComponent

> **ProtectedAppServerComponent** = (`props`: \{ `params?`: `Record`\<`string`, `string` \| `string`[]\>; `searchParams?`: `Record`\<`string`, `string` \| `string`[] \| `undefined`\>; `user`: [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser); \}) => `Promise`\<`JSX.Element`\> \| `JSX.Element`

App Router Server Component wrapped by `protectPage()`.

This component is only executed after authentication (and optional authorization) succeeds. The authenticated `user` is injected into the component props automatically.

## Parameters

| Parameter             | Type                                                                                                                                                                                                                            | Description                                               |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `props`               | \{ `params?`: `Record`\<`string`, `string` \| `string`[]\>; `searchParams?`: `Record`\<`string`, `string` \| `string`[] \| `undefined`\>; `user`: [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser); \} | -                                                         |
| `props.params?`       | `Record`\<`string`, `string` \| `string`[]\>                                                                                                                                                                                    | Dynamic route parameters provided by the App Router.      |
| `props.searchParams?` | `Record`\<`string`, `string` \| `string`[] \| `undefined`\>                                                                                                                                                                     | URL search parameters provided by the App Router.         |
| `props.user`          | [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser)                                                                                                                                                       | The authenticated user resolved from the current session. |

## Returns

`Promise`\<`JSX.Element`\> \| `JSX.Element`
