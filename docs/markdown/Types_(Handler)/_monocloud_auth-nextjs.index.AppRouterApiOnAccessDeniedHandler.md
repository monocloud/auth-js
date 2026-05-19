---
rootSdk: Next.js
title: "AppRouterApiOnAccessDeniedHandler"
category: Handler Types
description: "Handler invoked when a request is denied because the user is not authenticated in an App Router API route."
---

# Handler Type: AppRouterApiOnAccessDeniedHandler

> **AppRouterApiOnAccessDeniedHandler** = (`req`: `NextRequest`, `ctx`: [`AppRouterContext`](/sdks/nextjs/api-reference/types/approutercontext)) => `Promise`\<`Response`\> \| `Response`

Handler invoked when a request is denied because the user is not authenticated in an App Router API route.

## Parameters

| Parameter | Type                                                                            | Description                                                 |
| --------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `req`     | `NextRequest`                                                                   | The incoming Next.js request.                               |
| `ctx`     | [`AppRouterContext`](/sdks/nextjs/api-reference/types/approutercontext) | The App Router context containing dynamic route parameters. |

## Returns

`Promise`\<`Response`\> \| `Response`

Returns a `Response` (or `NextResponse`) or a Promise resolving to one.
