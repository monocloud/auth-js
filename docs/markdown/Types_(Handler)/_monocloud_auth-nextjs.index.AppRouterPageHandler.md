---
rootSdk: Next.js
title: "AppRouterPageHandler"
category: Handler Types
---

# Handler Type: AppRouterPageHandler

> **AppRouterPageHandler** = (`props`: \{ `params?`: `Record`\<`string`, `string` \| `string`[]\>; `searchParams?`: `Record`\<`string`, `string` \| `string`[] \| `undefined`\>; \}) => `Promise`\<`JSX.Element`\> \| `JSX.Element`

Represents a Next.js App Router page component (Server Component).

## Parameters

| Parameter             | Type                                                                                                                                         | Description                                                                                   |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `props`               | \{ `params?`: `Record`\<`string`, `string` \| `string`[]\>; `searchParams?`: `Record`\<`string`, `string` \| `string`[] \| `undefined`\>; \} | Page props provided by Next.js, including dynamic route parameters and URL search parameters. |
| `props.params?`       | `Record`\<`string`, `string` \| `string`[]\>                                                                                                 | Dynamic route parameters extracted from the URL.                                              |
| `props.searchParams?` | `Record`\<`string`, `string` \| `string`[] \| `undefined`\>                                                                                  | URL search parameters (`?key=value`) parsed by Next.js.                                       |

## Returns

`Promise`\<`JSX.Element`\> \| `JSX.Element`

A JSX element, or a Promise resolving to one.
