---
rootSdk: Next.js
title: "ProtectedAppServerComponent"
category: Handler Types
---

# Handler Type: ProtectedAppServerComponent

> **ProtectedAppServerComponent** = (`props`: [`ProtectedAppServerComponentProps`](/sdks/nextjs/api-reference/handler-types/protectedappservercomponentprops)) => `Promise`\<`JSX.Element`\> \| `JSX.Element`

App Router Server Component wrapped by [protectPage()](/sdks/nextjs/api-reference/functions/protectpage).

This component is only executed after authentication (and optional authorization) succeeds. The authenticated `user` is injected into the component props automatically.

## Props

| Property                                  | Type                                                                      | Description                                               |
| ----------------------------------------- | ------------------------------------------------------------------------- | --------------------------------------------------------- |
| `params?`             | `Record`\<`string`, `string` \| `string`[]\>                              | Dynamic route parameters provided by the App Router.      |
| `searchParams?` | `Record`\<`string`, `string` \| `string`[] \| `undefined`\>               | URL search parameters provided by the App Router.         |
| `user`                  | [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser) | The authenticated user resolved from the current session. |


## Returns

`Promise`\<`JSX.Element`\> \| `JSX.Element`
