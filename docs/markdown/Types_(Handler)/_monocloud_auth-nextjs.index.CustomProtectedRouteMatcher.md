---
rootSdk: Next.js
title: "CustomProtectedRouteMatcher"
category: Handler Types
---

# Handler Type: CustomProtectedRouteMatcher

> **CustomProtectedRouteMatcher** = (`req`: `NextRequest`) => `Promise`\<`boolean`\> \| `boolean`

Function used to dynamically determine whether a request should be treated as a protected route.

## Parameters

| Parameter | Type          | Description                   |
| --------- | ------------- | ----------------------------- |
| `req`     | `NextRequest` | The incoming Next.js request. |

## Returns

`Promise`\<`boolean`\> \| `boolean`

Return `true` to require authentication for the request, or `false` to allow it to continue without protection.
