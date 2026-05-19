---
rootSdk: Next.js
title: "NextMiddlewareOnAccessDenied"
category: Handler Types
description: "Handler invoked when access is denied during Next.js middleware execution."
---

# Handler Type: NextMiddlewareOnAccessDenied

> **NextMiddlewareOnAccessDenied** = (`request`: `NextRequest`, `event`: `NextFetchEvent`) => [`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult) \| `Promise`\<[`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult)\>

Handler invoked when access is denied during Next.js middleware execution.

This callback allows you to customize how unauthenticated or unauthorized requests are handled, for example by redirecting, rewriting, or returning a custom response.

## Parameters

| Parameter | Type             | Description                         |
| --------- | ---------------- | ----------------------------------- |
| `request` | `NextRequest`    | The incoming Next.js request.       |
| `event`   | `NextFetchEvent` | The associated Next.js fetch event. |

## Returns

[`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult) \| `Promise`\<[`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult)\>

A middleware result that determines how the request should proceed.
