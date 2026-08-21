---
rootSdk: Next.js
title: "OnError"
category: Handler Types
description: "Error handler invoked when an exception occurs during execution of the sign-in, callback, sign-out, userinfo, or back-channel logout endpoints."
---

# Handler Type: OnError

> **OnError** = [`AppOnError`](/sdks/nextjs/api-reference/handler-types/apponerror) \| [`PageOnError`](/sdks/nextjs/api-reference/handler-types/pageonerror)

Error handler invoked when an exception occurs during execution of the sign-in, callback, sign-out, userinfo, or back-channel logout endpoints.

> - In the **App Router**, you must either return a `NextResponse` or throw an error. Otherwise, the request will remain unresolved.
> - In the **Pages Router**, you must send a response (for example, `res.send()` or `res.json()`) after handling the error, or the request will hang.
