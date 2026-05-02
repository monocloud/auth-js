---
rootSdk: Next.js
title: "getTokens"
category: Functions
description: "Retrieves the current user's tokens using the active server request context."
---

# Function: getTokens

## Call Signature

> **getTokens**(`options?`: [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions)): `Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

Retrieves the current user's tokens using the active server request context.

### Parameters

| Parameter  | Type                                                                            | Description                                                                       |
| ---------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `options?` | [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions) | Optional configuration controlling refresh behavior and resource/scope selection. |

### Returns

`Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

The current user's tokens, refreshed if necessary.

### Examples

```tsx:src/app/page.tsx tab="Server Component" tab-group="tokens-ssr"
import { getTokens } from "@monocloud/auth-nextjs";

export default async function Home() {
  const tokens = await getTokens();

  return <div>Expired: {tokens.isExpired.toString()}</div>;
}
```

```tsx:src/action.ts tab="Server Action" tab-group="tokens-ssr"
"use server";

import { getTokens } from "@monocloud/auth-nextjs";

export async function getExpiredAction() {
  const tokens = await getTokens();

  return { expired: tokens.isExpired };
}
```

```tsx:src/app/api/tokens/route.ts tab="API Handler" tab-group="tokens-ssr"
import { getTokens } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export const GET = async () => {
  const tokens = await getTokens();

  return NextResponse.json({ expired: tokens.isExpired });
};
```

```tsx:src/proxy.ts tab="Middleware" tab-group="tokens-ssr"
import { getTokens } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export default async function proxy() {
  const tokens = await getTokens();

  if (tokens.isExpired) {
    return new NextResponse("Tokens expired", { status: 401 });
  }

  return NextResponse.next();
}
```

The **default token** is the access token associated with your default authorization parameters:

- Scopes: `MONOCLOUD_AUTH_SCOPES` or `options.defaultAuthParams.scopes`
- Resource: `MONOCLOUD_AUTH_RESOURCE` or `options.defaultAuthParams.resource`

Calling `getTokens()` returns the current token set and **refreshes the default token automatically when needed** (for example, if it has expired). To force a refresh even when it isn’t expired, use `forceRefresh: true`.

```tsx:src/app/page.tsx title="Refresh default token"
import { getTokens } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export const GET = async () => {
  // Forces a refresh of the default token
  const tokens = await getTokens({ forceRefresh: true });

  return NextResponse.json({ accessToken: tokens?.accessToken });
};
```

Use `resource` and `scopes` to request an access token for one or more resources.

> The requested resource and scopes must be included in the initial authorization flow (so the user has consented / the session is eligible to mint that token).

```tsx:src/app/page.tsx title="Request a new access token for resource(s)"
import { getTokens } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export const GET = async () => {
  const tokens = await getTokens({
    resource: "https://first.example.com https://second.example.com",
    scopes: "read:first read:second shared",
  });

  return NextResponse.json({ accessToken: tokens?.accessToken });
};
```

### Throws

[MonoCloudValidationError](/sdks/nextjs/api-reference/error-classes/monocloudvalidationerror) If no valid session exists.

## Call Signature

> **getTokens**(`req`: `Request` \| `NextRequest`, `options?`: [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions)): `Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

Retrieves the current user's tokens using an explicit Web or Next.js request.

Use this overload when you already have access to a `Request` or `NextRequest` (for example, in Middleware or Route Handlers).

### Parameters

| Parameter  | Type                                                                            | Description                                                                       |
| ---------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `req`      | `Request` \| `NextRequest`                                                      | Incoming request used to resolve authentication from cookies and headers.         |
| `options?` | [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions) | Optional configuration controlling refresh behavior and resource/scope selection. |

### Returns

`Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

The current user's tokens, refreshed if necessary.

### Examples

```tsx:src/proxy.ts tab="Middleware (Request)" tab-group="tokens-route-handler-request"
import { getTokens } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export default async function proxy(req: NextRequest) {
  const tokens = await getTokens(req);

  if (tokens.isExpired) {
    return new NextResponse("Tokens expired", { status: 401 });
  }

  return NextResponse.next();
}
```

```tsx:src/app/api/tokens/route.ts tab="API Handler (Request)" tab-group="tokens-route-handler-request"
import { getTokens } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export const GET = async (req: NextRequest) => {
  const tokens = await getTokens(req);

  return NextResponse.json({ expired: tokens?.isExpired });
};
```

### Throws

[MonoCloudValidationError](/sdks/nextjs/api-reference/error-classes/monocloudvalidationerror) If no valid session exists.

## Call Signature

> **getTokens**(`req`: `Request` \| `NextRequest`, `res`: `Response` \| `NextResponse`\<`unknown`\>, `options?`: [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions)): `Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

Retrieves the current user's tokens using an explicit request and response.

Use this overload when you have already created a response and want refreshed authentication cookies or headers applied to it.

### Parameters

| Parameter  | Type                                                                            | Description                                                                       |
| ---------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `req`      | `Request` \| `NextRequest`                                                      | Incoming request used to resolve authentication from cookies and headers.         |
| `res`      | `Response` \| `NextResponse`\<`unknown`\>                                       | Existing response to update with refreshed authentication cookies or headers.     |
| `options?` | [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions) | Optional configuration controlling refresh behavior and resource/scope selection. |

### Returns

`Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

The current user's tokens, refreshed if necessary.

### Examples

```tsx:src/proxy.ts tab="Middleware (Response)" tab-group="tokens-route-handler-response"
import { getTokens } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export default async function proxy(req: NextRequest) {
  const res = NextResponse.next();

  const tokens = await getTokens(req, res);

  res.headers.set("x-tokens-expired", tokens.isExpired.toString());

  return res;
}
```

```tsx:src/app/api/tokens/route.ts tab="API Handler (Response)" tab-group="tokens-route-handler-response"
import { getTokens } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export const GET = async (req: NextRequest) => {
  const res = new NextResponse("Custom Body");

  const tokens = await getTokens(req, res);

  if (!tokens.isExpired) {
    res.headers.set("x-auth-status", "active");
  }

  return res;
};
```

### Throws

[MonoCloudValidationError](/sdks/nextjs/api-reference/error-classes/monocloudvalidationerror) If no valid session exists.

## Call Signature

> **getTokens**(`req`: `NextApiRequest` \| `IncomingMessage`, `res`: `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>, `options?`: [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions)): `Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

Retrieves the current user's tokens in the Pages Router or Node.js runtime.

Use this overload in API routes or `getServerSideProps`, where Node.js request and response objects are available.

### Parameters

| Parameter  | Type                                                                            | Description                                                                             |
| ---------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `req`      | `NextApiRequest` \| `IncomingMessage`                                           | Incoming Node.js request used to resolve authentication from cookies.                   |
| `res`      | `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>                      | Outgoing Node.js response used to apply refreshed authentication cookies when required. |
| `options?` | [`GetTokensOptions`](/sdks/nextjs/api-reference/types/gettokensoptions) | Optional configuration controlling refresh behavior and resource/scope selection.       |

### Returns

`Promise`\<[`MonoCloudTokens`](/sdks/nextjs/api-reference/types/monocloudtokens)\>

The current user's tokens, refreshed if necessary.

### Examples

```tsx:src/pages/index.tsx tab="Pages Router (Pages)" tab-group="tokens-pages"
import { getTokens, MonoCloudTokens } from "@monocloud/auth-nextjs";
import { GetServerSideProps } from "next";

type Props = {
  tokens: MonoCloudTokens;
};

export default function Home({ tokens }: Props) {
  return <pre>Tokens: {JSON.stringify(tokens, null, 2)}</pre>;
}

export const getServerSideProps: GetServerSideProps<Props> = async (ctx) => {
  const tokens = await getTokens(ctx.req, ctx.res);

  return {
    props: {
      tokens: tokens
    }
  };
};
```

```tsx:src/pages/api/tokens.ts tab="Pages Router (API)" tab-group="tokens-pages"
import { getTokens } from "@monocloud/auth-nextjs";
import { NextApiRequest, NextApiResponse } from "next";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  const tokens = await getTokens(req, res);

  res.status(200).json({ accessToken: tokens?.accessToken });
}
```

### Throws

[MonoCloudValidationError](/sdks/nextjs/api-reference/error-classes/monocloudvalidationerror) If no valid session exists.
