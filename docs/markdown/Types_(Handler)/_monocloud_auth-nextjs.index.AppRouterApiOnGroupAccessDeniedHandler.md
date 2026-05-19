---
rootSdk: Next.js
title: "AppRouterApiOnGroupAccessDeniedHandler"
category: Handler Types
description: "Handler invoked when a request is denied because the authenticated user does not satisfy the required group restrictions in an App Router API route."
---

# Handler Type: AppRouterApiOnGroupAccessDeniedHandler

> **AppRouterApiOnGroupAccessDeniedHandler** = (`req`: `NextRequest`, `ctx`: [`AppRouterContext`](/sdks/nextjs/api-reference/types/approutercontext), `user`: [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser)) => `Promise`\<`Response`\> \| `Response`

Handler invoked when a request is denied because the authenticated user does not satisfy the required group restrictions in an App Router API route.

## Parameters

| Parameter | Type                                                                            | Description                                                 |
| --------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `req`     | `NextRequest`                                                                   | The incoming Next.js request.                               |
| `ctx`     | [`AppRouterContext`](/sdks/nextjs/api-reference/types/approutercontext) | The App Router context containing dynamic route parameters. |
| `user`    | [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser)       | The authenticated user associated with the request.         |

## Returns

`Promise`\<`Response`\> \| `Response`

Returns a `Response` (or `NextResponse`) or a Promise resolving to one.
