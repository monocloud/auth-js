---
rootSdk: Next.js
title: "protectApi"
category: Functions
description: "Wraps an App Router API route handler and ensures that only authenticated (and optionally authorized) requests can access the route."
---

# Function: protectApi

## Call Signature

> **protectApi**(`handler`: [`AppRouterApiHandlerFn`](/sdks/nextjs/api-reference/handler-types/approuterapihandlerfn), `options?`: [`ProtectApiAppOptions`](/sdks/nextjs/api-reference/types/protectapiappoptions)): [`AppRouterApiHandlerFn`](/sdks/nextjs/api-reference/handler-types/approuterapihandlerfn)

Wraps an App Router API route handler and ensures that only authenticated (and optionally authorized) requests can access the route.

Intended for Next.js App Router Route Handlers.

### Parameters

| Parameter  | Type                                                                                                  | Description                                                                   |
| ---------- | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `handler`  | [`AppRouterApiHandlerFn`](/sdks/nextjs/api-reference/handler-types/approuterapihandlerfn) | The route handler to protect.                                                 |
| `options?` | [`ProtectApiAppOptions`](/sdks/nextjs/api-reference/types/protectapiappoptions)               | Optional configuration controlling authentication and authorization behavior. |

### Returns

[`AppRouterApiHandlerFn`](/sdks/nextjs/api-reference/handler-types/approuterapihandlerfn)

Returns a wrapped handler that enforces authentication (and optional authorization) before invoking the original handler.

### Example

```tsx:src/app/api/protected/route.ts
import { protectApi } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export const GET = protectApi(async () => {
  return NextResponse.json({
    message: "You accessed a protected endpoint",
  });
});
```

## Call Signature

> **protectApi**(`handler`: `NextApiHandler`, `options?`: [`ProtectApiPageOptions`](/sdks/nextjs/api-reference/types/protectapipageoptions)): `NextApiHandler`

Wraps a Pages Router API route handler and ensures that only authenticated (and optionally authorized) requests can access the route.

Intended for Next.js Pages Router API routes.

### Parameters

| Parameter  | Type                                                                                      | Description                                                                   |
| ---------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `handler`  | `NextApiHandler`                                                                          | The route handler to protect.                                                 |
| `options?` | [`ProtectApiPageOptions`](/sdks/nextjs/api-reference/types/protectapipageoptions) | Optional configuration controlling authentication and authorization behavior. |

### Returns

`NextApiHandler`

Returns a wrapped handler that enforces authentication (and optional authorization) before invoking the original handler.

### Example

```tsx:src/pages/api/protected.ts
import { protectApi } from "@monocloud/auth-nextjs";
import { NextApiRequest, NextApiResponse } from "next";

export default protectApi(
  async (req: NextApiRequest, res: NextApiResponse) => {
    return res.json({
      message: "You accessed a protected endpoint",
    });
  }
);
```
