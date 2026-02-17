---
rootSdk: Next.js
title: "AppRouterApiHandlerFn"
category: Handler Types
---

# Handler Type: AppRouterApiHandlerFn

> **AppRouterApiHandlerFn** = (`req`: `NextRequest` \| `Request`, `ctx`: [`AppRouterContext`](/sdks/nextjs/api-reference/types/approutercontext)) => `Promise`\<`Response` \| `NextResponse`\> \| `Response` \| `NextResponse`

Represents a Next.js App Router Route Handler function.

## Parameters

| Parameter | Type                                                                            | Description                                        |
| --------- | ------------------------------------------------------------------------------- | -------------------------------------------------- |
| `req`     | `NextRequest` \| `Request`                                                      | The incoming request object.                       |
| `ctx`     | [`AppRouterContext`](/sdks/nextjs/api-reference/types/approutercontext) | Route context containing dynamic route parameters. |

## Returns

`Promise`\<`Response` \| `NextResponse`\> \| `Response` \| `NextResponse`

A `Response` or `NextResponse`, or a Promise resolving to one.
