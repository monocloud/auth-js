---
rootSdk: Next.js
title: "MonoCloudAuthHandler"
category: Handler Types
description: "Handler function returned by monoCloudAuth()."
---

# Handler Type: MonoCloudAuthHandler

> **MonoCloudAuthHandler** = (`req`: `Request` \| `NextRequest` \| `NextApiRequest`, `resOrCtx?`: `Response` \| `NextResponse`\<`any`\> \| `NextApiResponse`\<`any`\> \| [`AppRouterContext`](/sdks/nextjs/api-reference/types/approutercontext)) => `Promise`\<`Response` \| `NextResponse` \| `void` \| `any`\>

Handler function returned by [monoCloudAuth()](/sdks/nextjs/api-reference/functions/monocloudauth).

This handler processes authentication routes such as sign-in, callback, sign-out, userinfo, and back-channel logout across supported Next.js runtimes (App Router, Pages Router, and API routes).

## Parameters

| Parameter   | Type                                                                                                                                                   |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `req`       | `Request` \| `NextRequest` \| `NextApiRequest`                                                                                                         |
| `resOrCtx?` | `Response` \| `NextResponse`\<`any`\> \| `NextApiResponse`\<`any`\> \| [`AppRouterContext`](/sdks/nextjs/api-reference/types/approutercontext) |

## Returns

`Promise`\<`Response` \| `NextResponse` \| `void` \| `any`\>
