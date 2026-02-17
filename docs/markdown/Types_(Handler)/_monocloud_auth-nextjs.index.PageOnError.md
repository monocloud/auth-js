---
rootSdk: Next.js
title: "PageOnError"
category: Handler Types
---

# Handler Type: PageOnError

> **PageOnError** = (`req`: `NextApiRequest`, `res`: `NextApiResponse`, `error`: `Error`) => `Promise`\<`void`\> \| `void`

Handler invoked when an error occurs during execution of a Pages Router API endpoint.

Allows custom error handling such as logging, modifying the response, or sending a custom error payload.

## Parameters

| Parameter | Type              | Description                                 |
| --------- | ----------------- | ------------------------------------------- |
| `req`     | `NextApiRequest`  | The incoming Next.js API request.           |
| `res`     | `NextApiResponse` | The outgoing Next.js API response.          |
| `error`   | `Error`           | The error thrown during endpoint execution. |

## Returns

`Promise`\<`void`\> \| `void`

Returns `void` or a Promise that resolves when error handling is complete.
