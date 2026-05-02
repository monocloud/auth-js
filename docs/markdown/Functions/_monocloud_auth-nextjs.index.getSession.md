---
rootSdk: Next.js
title: "getSession"
category: Functions
description: "Retrieves the current user's session using the active server request context."
---

# Function: getSession

## Call Signature

> **getSession**(`options?`: [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions)): `Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

Retrieves the current user's session using the active server request context.

Intended for Server Components, Server Actions, Route Handlers, and Middleware where the request is implicitly available.

### Parameters

| Parameter  | Type                                                                              | Description                                                   |
| ---------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `options?` | [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions) | Optional configuration to control session retrieval behavior. |

### Returns

`Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

Returns the resolved session, or `undefined` if none exists.

### Examples

```tsx:src/app/page.tsx tab="Server Component" tab-group="session-ssr"
import { getSession } from "@monocloud/auth-nextjs";

export default async function Home() {
  const session = await getSession();

  return <div>{session?.user.name}</div>;
}
```

```tsx:src/action.ts tab="Server Action" tab-group="session-ssr"
"use server";

import { getSession } from "@monocloud/auth-nextjs";

export async function getUserAction() {
  const session = await getSession();

  return { name: session?.user.name };
}
```

```tsx:src/app/api/user/route.ts tab="API Handler" tab-group="session-ssr"
import { getSession } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export const GET = async () => {
  const session = await getSession();

  return NextResponse.json({ name: session?.user.name });
};
```

```tsx:src/proxy.ts tab="Middleware" tab-group="session-ssr"
import { getSession } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export default async function proxy() {
  const session = await getSession();

  if (!session) {
    return new NextResponse("User not signed in", { status: 401 });
  }

  return NextResponse.next();
}
```

## Call Signature

> **getSession**(`req`: `Request` \| `NextRequest`, `options?`: [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions)): `Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

Retrieves the current user's session using an explicit Web or Next.js request.

Use this overload when you already have access to a `Request` or `NextRequest` (for example in Middleware or Route Handlers).

### Parameters

| Parameter  | Type                                                                              | Description                                                                                             |
| ---------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `req`      | `Request` \| `NextRequest`                                                        | Incoming request used to read authentication cookies and headers to resolve the current user's session. |
| `options?` | [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions) | Optional configuration to control session retrieval behavior.                                           |

### Returns

`Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

Returns the resolved session, or `undefined` if none exists.

### Examples

```tsx:src/proxy.ts tab="Middleware (Request)" tab-group="session-route-handler"
import { getSession } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export default async function proxy(req: NextRequest) {
  const session = await getSession(req);

  if (!session) {
    return new NextResponse("User not signed in", { status: 401 });
  }

  return NextResponse.next();
}
```

```tsx:src/app/api/user/route.ts tab="API Handler (Request)" tab-group="session-route-handler"
import { getSession } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export const GET = async (req: NextRequest) => {
  const session = await getSession(req);

  return NextResponse.json({ name: session?.user.name });
};
```

## Call Signature

> **getSession**(`req`: `Request` \| `NextRequest`, `res`: `Response` \| `NextResponse`\<`unknown`\>, `options?`: [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions)): `Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

Retrieves the current user's session using explicit request and response objects.

Use this overload when you have already created a response and want refreshed authentication cookies or headers applied to it.

### Parameters

| Parameter  | Type                                                                              | Description                                                                                             |
| ---------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `req`      | `Request` \| `NextRequest`                                                        | Incoming request used to read authentication cookies and headers to resolve the current user's session. |
| `res`      | `Response` \| `NextResponse`\<`unknown`\>                                         | Response object to update when session resolution requires refreshed authentication cookies or headers. |
| `options?` | [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions) | Optional configuration to control session retrieval behavior.                                           |

### Returns

`Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

Returns the resolved session, or `undefined` if none exists.

### Examples

```tsx:src/proxy.ts tab="Middleware (Response)" tab-group="session-route-handler"
import { getSession } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export default async function proxy(req: NextRequest) {
  const res = NextResponse.next();

  const session = await getSession(req, res);

  if (!session) {
    return new NextResponse("User not signed in", { status: 401 });
  }

  res.headers.set("x-auth-status", "active");

  return res;
}
```

```tsx:src/app/api/user/route.ts tab="API Handler (Response)" tab-group="session-route-handler"
import { getSession } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export const GET = async (req: NextRequest) => {
  const res = new NextResponse("YOUR CUSTOM RESPONSE");

  const session = await getSession(req, res);

  if (session?.user) {
    res.cookies.set("something", "important");
  }

  return res;
};
```

## Call Signature

> **getSession**(`req`: `NextApiRequest` \| `IncomingMessage`, `res`: `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>, `options?`: [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions)): `Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

Retrieves the current user's session in the Pages Router or Node.js runtime.

Use this overload in API routes or `getServerSideProps`, where Node.js request and response objects are available.

### Parameters

| Parameter  | Type                                                                              | Description                                                                                          |
| ---------- | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `req`      | `NextApiRequest` \| `IncomingMessage`                                             | Incoming Node.js request used to read authentication cookies and resolve the current user's session. |
| `res`      | `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>                        | Outgoing Node.js response used to apply refreshed authentication cookies when required.              |
| `options?` | [`GetSessionOptions`](/sdks/nextjs/api-reference/types/getsessionoptions) | Optional configuration to control session retrieval behavior.                                        |

### Returns

`Promise`\<[`MonoCloudSession`](/sdks/nextjs/api-reference/types/monocloudsession) \| `undefined`\>

Returns the resolved session, or `undefined` if none exists.

### Examples

```tsx:src/pages/index.tsx tab="Pages Router (Pages)" tab-group="session-pages"
import { getSession, MonoCloudSession } from "@monocloud/auth-nextjs";
import { GetServerSideProps } from "next";

type Props = {
  session?: MonoCloudSession;
};

export default function Home({ session }: Props) {
  return <pre>Session: {JSON.stringify(session, null, 2)}</pre>;
}

export const getServerSideProps: GetServerSideProps<Props> = async (ctx) => {
  const session = await getSession(ctx.req, ctx.res);

  return {
    props: {
      session
    }
  };
};
```

```tsx:src/pages/api/user.ts tab="Pages Router (API)" tab-group="session-pages"
import { getSession } from "@monocloud/auth-nextjs";
import { NextApiRequest, NextApiResponse } from "next";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  const session = await getSession(req, res);

  res.status(200).json({ name: session?.user.name });
}
```
