---
rootSdk: Next.js
title: "isAuthenticated"
category: Functions
---

# Function: isAuthenticated

## Call Signature

> **isAuthenticated**(): `Promise`\<`boolean`\>

Checks whether the current user is authenticated using the active server request context.

Intended for Server Components, Server Actions, Route Handlers, and Middleware where the request is implicitly available.

### Returns

`Promise`\<`boolean`\>

Returns `true` if a valid session exists; otherwise `false`.

### Examples

```tsx:src/app/page.tsx tab="Server Component" tab-group="is-authenticated-ssr"
import { isAuthenticated } from "@monocloud/auth-nextjs";

export default async function Home() {
  const authenticated = await isAuthenticated();

  return <div>Authenticated: {authenticated.toString()}</div>;
}
```

```tsx:src/action.ts tab="Server Action" tab-group="is-authenticated-ssr"
"use server";

import { isAuthenticated } from "@monocloud/auth-nextjs";

export async function checkAuthAction() {
  const authenticated = await isAuthenticated();

  return { authenticated };
}
```

```tsx:src/app/api/authenticated/route.ts tab="API Handler" tab-group="is-authenticated-ssr"
import { isAuthenticated } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export const GET = async () => {
  const authenticated = await isAuthenticated();

  return NextResponse.json({ authenticated });
};
```

```tsx:src/proxy.ts tab="Middleware" tab-group="is-authenticated-ssr"
import { isAuthenticated } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export default async function proxy() {
  const authenticated = await isAuthenticated();

  if (!authenticated) {
    return new NextResponse("User not signed in", { status: 401 });
  }

  return NextResponse.next();
}
```

## Call Signature

> **isAuthenticated**(`req`: `Request` \| `NextRequest`, `res?`: `Response` \| `NextResponse`\<`unknown`\>): `Promise`\<`boolean`\>

Checks whether the current user is authenticated using an explicit Web or Next.js request.

Use this overload when you already have access to a `Request` or `NextRequest` (for example, in Middleware or Route Handlers).

### Parameters

| Parameter | Type                                      | Description                                                                              |
| --------- | ----------------------------------------- | ---------------------------------------------------------------------------------------- |
| `req`     | `Request` \| `NextRequest`                | Incoming request used to resolve authentication from cookies and headers.                |
| `res?`    | `Response` \| `NextResponse`\<`unknown`\> | Optional response to update if refreshed authentication cookies or headers are required. |

### Returns

`Promise`\<`boolean`\>

Returns `true` if a valid session exists; otherwise `false`.

### Examples

```tsx:src/proxy.ts tab="Middleware (Request)" tab-group="is-authenticated-route-handler"
import { isAuthenticated } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export default async function proxy(req: NextRequest) {
  const authenticated = await isAuthenticated(req);

  if (!authenticated) {
    return new NextResponse("User not signed in", { status: 401 });
  }

  return NextResponse.next();
}
```

```tsx:src/proxy.ts tab="Middleware (Response)" tab-group="is-authenticated-route-handler"
import { isAuthenticated } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export default async function proxy(req: NextRequest) {
  const res = NextResponse.next();

  const authenticated = await isAuthenticated(req, res);

  if (!authenticated) {
    return new NextResponse("User not signed in", { status: 401 });
  }

  res.headers.set("x-authenticated", "true");

  return res;
}
```

```tsx:src/app/api/authenticated/route.ts tab="API Handler (Request)" tab-group="is-authenticated-route-handler"
import { isAuthenticated } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export const GET = async (req: NextRequest) => {
  const authenticated = await isAuthenticated(req);

  return NextResponse.json({ authenticated });
};
```

```tsx:src/app/api/authenticated/route.ts tab="API Handler (Response)" tab-group="is-authenticated-route-handler"
import { isAuthenticated } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export const GET = async (req: NextRequest) => {
  const res = new NextResponse("YOUR CUSTOM RESPONSE");

  const authenticated = await isAuthenticated(req, res);

  if (authenticated) {
    res.cookies.set("something", "important");
  }

  return res;
};
```

## Call Signature

> **isAuthenticated**(`req`: `NextApiRequest` \| `IncomingMessage`, `res`: `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>): `Promise`\<`boolean`\>

Checks whether the current user is authenticated in the Pages Router or Node.js runtime.

Use this overload in API routes or `getServerSideProps`, where Node.js request and response objects are available.

### Parameters

| Parameter | Type                                                       | Description                                                                             |
| --------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `req`     | `NextApiRequest` \| `IncomingMessage`                      | Incoming Node.js request used to resolve authentication from cookies.                   |
| `res`     | `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\> | Outgoing Node.js response used to apply refreshed authentication cookies when required. |

### Returns

`Promise`\<`boolean`\>

Returns `true` if a valid session exists; otherwise `false`.

### Examples

```tsx:src/pages/index.tsx tab="Pages Router (Pages)" tab-group="is-authenticated-pages"
import { isAuthenticated } from "@monocloud/auth-nextjs";
import { GetServerSideProps } from "next";

type Props = {
  authenticated: boolean;
};

export default function Home({ authenticated }: Props) {
  return <pre>User is {authenticated ? "logged in" : "guest"}</pre>;
}

export const getServerSideProps: GetServerSideProps<Props> = async (ctx) => {
  const authenticated = await isAuthenticated(ctx.req, ctx.res);

  return {
    props: {
      authenticated
    }
  };
};
```

```tsx:src/pages/api/authenticated.ts tab="Pages Router (API)" tab-group="is-authenticated-pages"
import { isAuthenticated } from "@monocloud/auth-nextjs";
import { NextApiRequest, NextApiResponse } from "next";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  const authenticated = await isAuthenticated(req, res);

  res.status(200).json({ authenticated });
}
```
