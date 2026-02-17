---
rootSdk: Next.js
title: "AppRouterContext"
category: Types
---

# Type: AppRouterContext

Context object provided to App Router route handlers.

Contains dynamic route parameters resolved from the matched route segment (for example, `[id]` or `[...slug]`).

In streaming or async environments, `params` may be provided as a Promise.

## Properties

| Property                     | Type                                                                                                      | Description                                              |
| ---------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `params` | `Record`\<`string`, `string` \| `string`[]\> \| `Promise`\<`Record`\<`string`, `string` \| `string`[]\>\> | Dynamic route parameters extracted from the request URL. |
