---
rootSdk: Next.js
title: "NextMiddlewareOnGroupAccessDenied"
category: Handler Types
---

# Handler Type: NextMiddlewareOnGroupAccessDenied

> **NextMiddlewareOnGroupAccessDenied** = (`request`: `NextRequest`, `event`: `NextFetchEvent`, `user`: [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser)) => [`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult) \| `Promise`\<[`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult)\>

Handler invoked when an authenticated user is denied access during Next.js middleware execution due to group authorization rules.

This callback allows you to customize how authorization failures are handled, for example by redirecting, rewriting, or returning a custom response.

## Parameters

| Parameter | Type                                                                      | Description                                                      |
| --------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `request` | `NextRequest`                                                             | The incoming Next.js request.                                    |
| `event`   | `NextFetchEvent`                                                          | The associated Next.js fetch event.                              |
| `user`    | [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser) | The authenticated user who failed the group authorization check. |

## Returns

[`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult) \| `Promise`\<[`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult)\>

A middleware result that determines how the request should proceed.
