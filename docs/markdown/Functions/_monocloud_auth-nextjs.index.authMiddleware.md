---
rootSdk: Next.js
title: "authMiddleware"
category: Functions
---

# Function: authMiddleware

## Call Signature

> **authMiddleware**(`options?`: [`MonoCloudMiddlewareOptions`](/sdks/nextjs/api-reference/types/monocloudmiddlewareoptions)): `NextMiddleware`

Creates a Next.js authentication middleware that protects routes.

By default, all routes matched by `config.matcher` are protected unless configured otherwise.

### Parameters

| Parameter  | Type                                                                                                | Description                                                                                                                                                           |
| ---------- | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `options?` | [`MonoCloudMiddlewareOptions`](/sdks/nextjs/api-reference/types/monocloudmiddlewareoptions) | Optional configuration that controls how authentication is enforced (for example, redirect behavior, route matching, or custom handling of unauthenticated requests). |

### Returns

`NextMiddleware`

Returns a Next.js middleware result, such as a NextResponse, redirect, or undefined to continue processing.

### Examples

```tsx:src/proxy.ts tab="Protect All Routes" tab-group="auth-middleware"
import { authMiddleware } from "@monocloud/auth-nextjs";

export default authMiddleware();

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
};
```

```tsx:src/proxy.ts tab="Protect Selected Routes" tab-group="auth-middleware"
import { authMiddleware } from "@monocloud/auth-nextjs";

export default authMiddleware({
  protectedRoutes: ["/api/admin", "^/api/protected(/.*)?$"],
});

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
};
```

```tsx:src/proxy.ts tab="No Protected Routes" tab-group="auth-middleware"
import { authMiddleware } from "@monocloud/auth-nextjs";

export default authMiddleware({
  protectedRoutes: [],
});

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
};
```

```tsx:src/proxy.ts tab="Dynamic" tab-group="auth-middleware"
import { authMiddleware } from "@monocloud/auth-nextjs";

export default authMiddleware({
  protectedRoutes: (req) => {
    return req.nextUrl.pathname.startsWith("/api/protected");
  },
});

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
};
```

```tsx:src/proxy.ts tab="Group Protection" tab-group="auth-middleware"
import { authMiddleware } from "@monocloud/auth-nextjs";

export default authMiddleware({
  protectedRoutes: [
    {
      groups: ["admin", "editor", "537e7c3d-a442-4b5b-b308-30837aa045a4"],
      routes: ["/internal", "/api/internal(.*)"],
    },
  ],
});

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
};
```

## Call Signature

> **authMiddleware**(`request`: `NextRequest`, `event`: `NextFetchEvent`): [`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult) \| `Promise`\<[`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult)\>

Executes the authentication middleware manually.

Intended for advanced scenarios where the middleware is composed within custom logic.

### Parameters

| Parameter | Type             | Description                                                               |
| --------- | ---------------- | ------------------------------------------------------------------------- |
| `request` | `NextRequest`    | Incoming Next.js middleware request used to resolve authentication state. |
| `event`   | `NextFetchEvent` | Next.js middleware event providing lifecycle hooks such as `waitUntil`.   |

### Returns

[`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult) \| `Promise`\<[`NextMiddlewareResult`](/sdks/nextjs/api-reference/types/nextmiddlewareresult)\>

Returns a Next.js middleware result (`NextResponse`, redirect, or `undefined` to continue processing).

### Example

```tsx:src/proxy.ts title="Composing with custom middleware"
import { authMiddleware } from "@monocloud/auth-nextjs";
import { NextFetchEvent, NextRequest, NextResponse } from "next/server";

export default function customMiddleware(req: NextRequest, evt: NextFetchEvent) {
  if (req.nextUrl.pathname.startsWith("/api/protected")) {
    return authMiddleware(req, evt);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
};
```
