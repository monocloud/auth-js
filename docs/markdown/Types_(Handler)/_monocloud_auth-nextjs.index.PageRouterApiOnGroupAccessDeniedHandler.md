---
rootSdk: Next.js
title: "PageRouterApiOnGroupAccessDeniedHandler"
category: Handler Types
description: "Handler function invoked when an authenticated user is denied access in a Pages Router API route due to group authorization restrictions."
---

# Handler Type: PageRouterApiOnGroupAccessDeniedHandler

> **PageRouterApiOnGroupAccessDeniedHandler** = (`req`: `NextApiRequest`, `res`: `NextApiResponse`\<`any`\>, `user`: [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser)) => `Promise`\<`unknown`\> \| `unknown`

Handler function invoked when an authenticated user is denied access in a Pages Router API route due to group authorization restrictions.

## Parameters

| Parameter | Type                                                                      | Description                                                       |
| --------- | ------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `req`     | `NextApiRequest`                                                          | The incoming Next.js API request.                                 |
| `res`     | `NextApiResponse`\<`any`\>                                                | The Next.js API response object used to send the custom response. |
| `user`    | [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser) | -                                                                 |

## Returns

`Promise`\<`unknown`\> \| `unknown`

The handler should send a response using `res` (for example, `res.status(...).json(...)`). Returning a value does not automatically end the request.
