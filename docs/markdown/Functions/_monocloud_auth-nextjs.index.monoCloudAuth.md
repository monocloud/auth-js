---
rootSdk: Next.js
title: "monoCloudAuth"
category: Functions
description: "Creates a Next.js catch-all auth route handler (Pages Router and App Router) for the built-in routes (/signin, /callback, /userinfo, /signout)."
---

# Function: monoCloudAuth

> **monoCloudAuth**(`options?`: [`MonoCloudAuthOptions`](/sdks/nextjs/api-reference/types/monocloudauthoptions)): [`MonoCloudAuthHandler`](/sdks/nextjs/api-reference/handler-types/monocloudauthhandler)

Creates a Next.js catch-all auth route handler (Pages Router and App Router) for the built-in routes (`/signin`, `/callback`, `/userinfo`, `/signout`).

Mount this handler on a catch-all route (e.g. `/api/auth/[...monocloud]`).

> If you already use `authMiddleware()`, you typically don’t need this handler. Use `monoCloudAuth()` when middleware cannot be used or when auth routes need customization.

## Parameters

| Parameter  | Type                                                                                    | Description                                  |
| ---------- | --------------------------------------------------------------------------------------- | -------------------------------------------- |
| `options?` | [`MonoCloudAuthOptions`](/sdks/nextjs/api-reference/types/monocloudauthoptions) | Optional configuration for the auth handler. |

## Returns

[`MonoCloudAuthHandler`](/sdks/nextjs/api-reference/handler-types/monocloudauthhandler)

Returns a Next.js-compatible handler for App Router route handlers or Pages Router API routes.

## Examples

```tsx:src/app/api/auth/[...monocloud]/route.ts tab="App Router" tab-group="monoCloudAuth"
import { monoCloudAuth } from "@monocloud/auth-nextjs";

export const GET = monoCloudAuth();
```

```tsx:src/app/api/auth/[...monocloud]/route.ts tab="App Router (Response)" tab-group="monoCloudAuth"
import { monoCloudAuth } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export const GET = (req: NextRequest) => {
  const authHandler = monoCloudAuth();

  const res = new NextResponse();

  res.cookies.set("last_auth_requested", `${Date.now()}`);

  return authHandler(req, res);
};
```

```tsx:src/pages/api/auth/[...monocloud].ts tab="Pages Router" tab-group="monoCloudAuth"
import { monoCloudAuth } from "@monocloud/auth-nextjs";

export default monoCloudAuth();
```

```tsx:src/pages/api/auth/[...monocloud].ts tab="Pages Router (Response)" tab-group="monoCloudAuth"
import { monoCloudAuth } from "@monocloud/auth-nextjs";
import { NextApiRequest, NextApiResponse } from "next";

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const authHandler = monoCloudAuth();

  res.setHeader("last_auth_requested", `${Date.now()}`);

  return authHandler(req, res);
}
```
