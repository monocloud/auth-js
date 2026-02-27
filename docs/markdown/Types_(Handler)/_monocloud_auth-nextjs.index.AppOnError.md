---
rootSdk: Next.js
title: "AppOnError"
category: Handler Types
---

# Handler Type: AppOnError

> **AppOnError**\<`T`\> = (`req`: `NextRequest`, `ctx`: `T`, `error`: `Error`) => `Promise`\<`NextResponse` \| `void`\> \| `NextResponse` \| `void`

Handler invoked when an error occurs during execution of an App Router endpoint.

Allows custom error handling such as logging, transforming the response, or returning a custom `NextResponse`

## Type Parameters

| Type Parameter | Description                                               |
| -------------- | --------------------------------------------------------- |
| `T`            | The type of the App Router context passed to the handler. |

## Parameters

| Parameter | Type          | Description                                                 |
| --------- | ------------- | ----------------------------------------------------------- |
| `req`     | `NextRequest` | The incoming Next.js request.                               |
| `ctx`     | `T`           | The App Router context containing dynamic route parameters. |
| `error`   | `Error`       | The error thrown during endpoint execution.                 |

## Returns

`Promise`\<`NextResponse` \| `void`\> \| `NextResponse` \| `void`

Returns a `NextResponse` or `void`.
