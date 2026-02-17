---
rootSdk: Next.js
title: "redirectToSignIn"
category: Functions
---

# Function: redirectToSignIn

> **redirectToSignIn**(`options?`: [`RedirectToSignInOptions`](/sdks/nextjs/api-reference/types/redirecttosigninoptions)): `Promise`\<`void`\>

Redirects the user to the sign-in flow.

> **App Router only**. Intended for use in Server Components, Route Handlers, and Server Actions.

This helper performs a server-side redirect to the configured sign-in route. Execution does not continue after the redirect is triggered.

## Parameters

| Parameter  | Type                                                                                          | Description                                                                                    |
| ---------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `options?` | [`RedirectToSignInOptions`](/sdks/nextjs/api-reference/types/redirecttosigninoptions) | Optional configuration for the redirect, such as `returnUrl` or additional sign-in parameters. |

## Returns

`Promise`\<`void`\>

Never resolves. Triggers a redirect to the sign-in flow.

## Examples

```tsx:src/app/page.tsx tab="Server Component" tab-group="redirect-to-sign-in"
import { isUserInGroup, redirectToSignIn } from "@monocloud/auth-nextjs";

export default async function Home() {
  const allowed = await isUserInGroup(["admin"]);

  if (!allowed) {
    await redirectToSignIn({ returnUrl: "/home" });
  }

  return <>You are signed in.</>;
}
```

```tsx:src/action.ts tab="Server Action" tab-group="redirect-to-sign-in"
"use server";

import { getSession, redirectToSignIn } from "@monocloud/auth-nextjs";

export async function protectedAction() {
  const session = await getSession();

  if (!session) {
    await redirectToSignIn();
  }

  return { data: "Sensitive Data" };
}
```

```tsx:src/app/api/protected/route.ts tab="API Handler" tab-group="redirect-to-sign-in"
import { getSession, redirectToSignIn } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export const GET = async () => {
  const session = await getSession();

  if (!session) {
    await redirectToSignIn({
      returnUrl: "/dashboard",
    });
  }

  return NextResponse.json({ data: "Protected content" });
};
```
