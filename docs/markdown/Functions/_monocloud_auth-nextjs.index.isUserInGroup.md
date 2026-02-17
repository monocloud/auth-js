---
rootSdk: Next.js
title: "isUserInGroup"
category: Functions
---

# Function: isUserInGroup

## Call Signature

> **isUserInGroup**(`groups`: `string`[], `options?`: [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions)): `Promise`\<`boolean`\>

Checks whether the currently authenticated user is a member of **any** of the specified groups.

The `groups` parameter accepts group identifiers (IDs or names).

The authenticated user's session may contain groups represented as:

- Group IDs
- Group names
- `Group` objects (for example, `{ id: string; name: string }`)

Matching is always performed against the group's **ID** and **name**, regardless of how the group is represented in the session.

### Parameters

| Parameter  | Type                                                                                    | Description                                                           |
| ---------- | --------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `groups`   | `string`[]                                                                              | Group IDs or names to check against the user's group memberships.     |
| `options?` | [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions) | Optional configuration controlling how group membership is evaluated. |

### Returns

`Promise`\<`boolean`\>

Returns `true` if the user belongs to at least one specified group; otherwise `false`.

### Examples

```tsx:src/app/page.tsx tab="Server Component" tab-group="is-user-in-group-rsc"
import { isUserInGroup } from "@monocloud/auth-nextjs";

export default async function AdminPanel() {
  const isAdmin = await isUserInGroup(["admin"]);

  if (!isAdmin) {
    return <div>Access Denied</div>;
  }

  return <div>Admin Control Panel</div>;
}
```

```tsx:src/action.ts tab="Server Action" tab-group="is-user-in-group-rsc"
"use server";

import { isUserInGroup } from "@monocloud/auth-nextjs";

export async function deletePostAction() {
  const canDelete = await isUserInGroup(["admin", "editor"]);

  if (!canDelete) {
    return { success: false };
  }

  return { success: true };
}
```

```tsx:src/app/api/group-check/route.ts tab="API Handler" tab-group="is-user-in-group-rsc"
import { isUserInGroup } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export const GET = async () => {
  const allowed = await isUserInGroup(["admin", "editor"]);

  if (!allowed) {
    return new NextResponse("Forbidden", { status: 403 });
  }

  return NextResponse.json({ status: "success" });
};
```

```tsx:src/proxy.ts tab="Middleware" tab-group="is-user-in-group-rsc"
import { isUserInGroup } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export default async function proxy() {
  const isAdmin = await isUserInGroup(["admin"]);

  if (!isAdmin) {
    return new NextResponse("User is not admin", { status: 403 });
  }

  return NextResponse.next();
}
```

## Call Signature

> **isUserInGroup**(`req`: `Request` \| `NextRequest`, `groups`: `string`[], `options?`: [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions)): `Promise`\<`boolean`\>

Checks group membership using an explicit Web or Next.js request.

Use this overload when you already have access to a `Request` or `NextRequest` (for example, in Middleware or Route Handlers).

### Parameters

| Parameter  | Type                                                                                    | Description                                                               |
| ---------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `req`      | `Request` \| `NextRequest`                                                              | Incoming request used to resolve authentication from cookies and headers. |
| `groups`   | `string`[]                                                                              | Group IDs or names to check against the user's group memberships.         |
| `options?` | [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions) | Optional configuration controlling how group membership is evaluated.     |

### Returns

`Promise`\<`boolean`\>

Returns `true` if the user belongs to at least one specified group; otherwise `false`.

### Examples

```tsx:src/proxy.ts tab="Middleware (Request)" tab-group="is-user-in-group-request"
import { isUserInGroup } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export default async function proxy(req: NextRequest) {
  const isAdmin = await isUserInGroup(req, ["admin"]);

  if (!isAdmin) {
    return new NextResponse("User is not admin", { status: 403 });
  }

  return NextResponse.next();
}
```

```tsx:src/app/api/group-check/route.ts tab="API Handler (Request)" tab-group="is-user-in-group-request"
import { isUserInGroup } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export const GET = async (req: NextRequest) => {
  const isMember = await isUserInGroup(req, ["admin", "editor"]);

  return NextResponse.json({ isMember });
};
```

## Call Signature

> **isUserInGroup**(`req`: `Request` \| `NextRequest`, `res`: `Response` \| `NextResponse`\<`unknown`\>, `groups`: `string`[], `options?`: [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions)): `Promise`\<`boolean`\>

Checks group membership using an explicit request and response.

Use this overload when you have already created a response and want refreshed authentication cookies or headers applied to it.

### Parameters

| Parameter  | Type                                                                                    | Description                                                                                 |
| ---------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `req`      | `Request` \| `NextRequest`                                                              | Incoming request used to resolve authentication from cookies and headers.                   |
| `res`      | `Response` \| `NextResponse`\<`unknown`\>                                               | Existing response to update with refreshed authentication cookies or headers when required. |
| `groups`   | `string`[]                                                                              | Group IDs or names to check against the user's group memberships.                           |
| `options?` | [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions) | Optional configuration controlling how group membership is evaluated.                       |

### Returns

`Promise`\<`boolean`\>

Returns `true` if the user belongs to at least one specified group; otherwise `false`.

### Examples

```tsx:src/proxy.ts tab="Middleware (Response)" tab-group="is-user-in-group-response"
import { isUserInGroup } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export default async function proxy(req: NextRequest) {
  const res = NextResponse.next();

  const isAdmin = await isUserInGroup(req, res, ["admin"]);

  if (!isAdmin) {
    return new NextResponse("User is not admin", { status: 403 });
  }

  res.headers.set("x-user", "admin");

  return res;
}
```

```tsx:src/app/api/group-check/route.ts tab="API Handler (Response)" tab-group="is-user-in-group-response"
import { isUserInGroup } from "@monocloud/auth-nextjs";
import { NextRequest, NextResponse } from "next/server";

export const GET = async (req: NextRequest) => {
  const res = new NextResponse("Restricted Content");

  const allowed = await isUserInGroup(req, res, ["admin"]);

  if (!allowed) {
    return new NextResponse("Not Allowed", res);
  }

  return res;
};
```

## Call Signature

> **isUserInGroup**(`req`: `NextApiRequest` \| `IncomingMessage`, `res`: `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>, `groups`: `string`[], `options?`: [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions)): `Promise`\<`boolean`\>

Checks group membership in the Pages Router or Node.js runtime.

Use this overload in API routes or `getServerSideProps`, where Node.js request and response objects are available.

### Parameters

| Parameter  | Type                                                                                    | Description                                                                             |
| ---------- | --------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `req`      | `NextApiRequest` \| `IncomingMessage`                                                   | Incoming Node.js request used to resolve authentication from cookies.                   |
| `res`      | `NextApiResponse` \| `ServerResponse`\<`IncomingMessage`\>                              | Outgoing Node.js response used to apply refreshed authentication cookies when required. |
| `groups`   | `string`[]                                                                              | Group IDs or names to check against the user's group memberships.                       |
| `options?` | [`IsUserInGroupOptions`](/sdks/nextjs/api-reference/types/isuseringroupoptions) | Optional configuration controlling how group membership is evaluated.                   |

### Returns

`Promise`\<`boolean`\>

Returns `true` if the user belongs to at least one specified group; otherwise `false`.

### Examples

```tsx:src/pages/index.tsx tab="Pages Router (Pages)" tab-group="is-user-in-group-pages"
import { isUserInGroup } from "@monocloud/auth-nextjs";
import { GetServerSideProps } from "next";

type Props = {
  isAdmin: boolean;
};

export default function Home({ isAdmin }: Props) {
  return <div>User is admin: {isAdmin.toString()}</div>;
}

export const getServerSideProps: GetServerSideProps<Props> = async (ctx) => {
  const isAdmin = await isUserInGroup(ctx.req, ctx.res, ["admin"]);

  return {
    props: {
      isAdmin
    }
  };
};
```

```tsx:src/pages/api/group-check.ts tab="Pages Router (API)" tab-group="is-user-in-group-pages"
import { isUserInGroup } from "@monocloud/auth-nextjs";
import { NextApiRequest, NextApiResponse } from "next";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  const isAdmin = await isUserInGroup(req, res, ["admin"]);

  if (!isAdmin) {
    return res.status(403).json({ error: "Forbidden" });
  }

  res.status(200).json({ message: "Welcome Admin" });
}
```
