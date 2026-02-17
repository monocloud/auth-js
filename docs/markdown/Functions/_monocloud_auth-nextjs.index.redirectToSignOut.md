---
rootSdk: Next.js
title: "redirectToSignOut"
category: Functions
---

# Function: redirectToSignOut

> **redirectToSignOut**(`options?`: [`RedirectToSignOutOptions`](/sdks/nextjs/api-reference/types/redirecttosignoutoptions)): `Promise`\<`void`\>

Redirects the user to the sign-out flow.

> **App Router only**. Intended for use in Server Components, Route Handlers, and Server Actions.

This helper performs a server-side redirect to the configured sign-out route. Execution does not continue after the redirect is triggered.

## Parameters

| Parameter  | Type                                                                                            | Description                                                                                                 |
| ---------- | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `options?` | [`RedirectToSignOutOptions`](/sdks/nextjs/api-reference/types/redirecttosignoutoptions) | Optional configuration for the redirect, such as `postLogoutRedirectUri` or additional sign-out parameters. |

## Returns

`Promise`\<`void`\>

Never resolves. Triggers a redirect to the sign-out flow.

## Examples

```tsx:src/app/page.tsx tab="Server Component" tab-group="redirect-to-sign-out"
import { getSession, redirectToSignOut } from "@monocloud/auth-nextjs";

export default async function Page() {
  const session = await getSession();

  // Example: Force sign-out if a specific condition is met (e.g., account suspended)
  if (session?.user.isSuspended) {
    await redirectToSignOut();
  }

  return <>Welcome User</>;
}
```

```tsx:src/action.ts tab="Server Action" tab-group="redirect-to-sign-out"
"use server";

import { getSession, redirectToSignOut } from "@monocloud/auth-nextjs";

export async function signOutAction() {
  const session = await getSession();

  if (session) {
    await redirectToSignOut();
  }
}
```

```tsx:src/app/api/signout/route.ts tab="API Handler" tab-group="redirect-to-sign-out"
import { getSession, redirectToSignOut } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export const GET = async () => {
  const session = await getSession();

  if (session) {
    await redirectToSignOut({
      postLogoutRedirectUri: "/goodbye",
    });
  }

  return NextResponse.json({ status: "already_signed_out" });
};
```
