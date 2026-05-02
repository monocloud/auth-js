---
rootSdk: Next.js
title: "PageRouterApiOnAccessDeniedHandler"
category: Handler Types
description: "Handler function invoked when a request is not authenticated in a Pages Router API route."
---

# Handler Type: PageRouterApiOnAccessDeniedHandler

> **PageRouterApiOnAccessDeniedHandler** = (`req`: `NextApiRequest`, `res`: `NextApiResponse`\<`any`\>) => `Promise`\<`unknown`\> \| `unknown`

Handler function invoked when a request is not authenticated in a Pages Router API route.

## Parameters

| Parameter | Type                       | Description                                                       |
| --------- | -------------------------- | ----------------------------------------------------------------- |
| `req`     | `NextApiRequest`           | The incoming Next.js API request.                                 |
| `res`     | `NextApiResponse`\<`any`\> | The Next.js API response object used to send the custom response. |

## Returns

`Promise`\<`unknown`\> \| `unknown`

The handler should send a response using `res` (for example, `res.status(...).json(...)`). Returning a value does not automatically end the request.
