---
rootSdk: Next.js
title: "protect"
category: Functions
---

# Function: protect

> **protect**(`options?`: [`ProtectOptions`](/sdks/nextjs/api-reference/types/protectoptions)): `Promise`\<`void`\>

Ensures the current user is authenticated. If not, redirects to the sign-in flow.

> **App Router only.** Intended for Server Components, Route Handlers, and Server Actions.

## Parameters

| Parameter  | Type                                                                        | Description                                                                                   |
| ---------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `options?` | [`ProtectOptions`](/sdks/nextjs/api-reference/types/protectoptions) | Optional configuration for redirect behavior (for example, return URL or sign-in parameters). |

## Returns

`Promise`\<`void`\>

Resolves if the user is authenticated; otherwise triggers a redirect.

## Examples

```tsx:src/app/page.tsx tab="Server Component" tab-group="protect"
import { protect } from "@monocloud/auth-nextjs";

export default async function Home() {
  await protect();

  return <>You are signed in.</>;
}
```

```tsx:src/action.ts tab="Server Action" tab-group="protect"
"use server";

import { protect } from "@monocloud/auth-nextjs";

export async function getMessage() {
  await protect();

  return { secret: "sssshhhhh!!!" };
}
```

```tsx:src/app/api/protected/route.ts tab="API Handler" tab-group="protect"
import { protect } from "@monocloud/auth-nextjs";
import { NextResponse } from "next/server";

export const GET = async () => {
  await protect();

  return NextResponse.json({ secret: "ssshhhh!!!" });
};
```
