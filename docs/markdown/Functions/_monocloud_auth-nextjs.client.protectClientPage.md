---
rootSdk: Next.js
title: "protectClientPage"
category: Functions
---

# Function: protectClientPage

> **protectClientPage**\<`P`\>(`Component`: `ComponentType`\<`P` & \{ `user`: [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser); \}\>, `options?`: [`ProtectClientPageOptions`](/sdks/nextjs/api-reference/types/protectclientpageoptions)): `FC`\<`P`\>

`protectClientPage()` wraps a **client-rendered page component** and ensures that only authenticated users can access it.

If the user is authenticated, the wrapped component receives a `user` prop.

> This function runs on the client and controls rendering only.
> To enforce access before rendering (server-side), use the server [protectPage()](/sdks/nextjs/api-reference/classes/monocloudnextclient#protectpage) method on [MonoCloudNextClient](/sdks/nextjs/api-reference/classes/monocloudnextclient).

## Type Parameters

| Type Parameter         | Description                                          |
| ---------------------- | ---------------------------------------------------- |
| `P` _extends_ `object` | Props of the protected component (excluding `user`). |

## Parameters

| Parameter   | Type                                                                                                              | Description                   |
| ----------- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| `Component` | `ComponentType`\<`P` & \{ `user`: [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser); \}\> | The page component to protect |
| `options?`  | [`ProtectClientPageOptions`](/sdks/nextjs/api-reference/types/protectclientpageoptions)                  | Optional configuration        |

## Returns

`FC`\<`P`\>

A protected React component.

## Examples

```tsx title="Basic Usage"
"use client";

import { protectClientPage } from "@monocloud/auth-nextjs/client";

export default protectClientPage(function Home({ user }) {
  return <>Signed in as {user.email}</>;
});
```

```tsx title="With Options"
"use client";

import { protectClientPage } from "@monocloud/auth-nextjs/client";

export default protectClientPage(
  function Home({ user }) {
    return <>Signed in as {user.email}</>;
  },
  {
    returnUrl: "/dashboard",
    authParams: { loginHint: "user@example.com" },
  },
);
```

```tsx title="Custom access denied UI"
"use client";

import { protectClientPage } from "@monocloud/auth-nextjs/client";

export default protectClientPage(
  function Home({ user }) {
    return <>Signed in as {user.email}</>;
  },
  {
    onAccessDenied: () => <div>Please sign in to continue</div>,
  },
);
```

```tsx title="Group protection"
"use client";

import { protectClientPage } from "@monocloud/auth-nextjs/client";

export default protectClientPage(
  function Home({ user }) {
    return <>Welcome Admin {user.email}</>;
  },
  {
    groups: ["admin"],
    onGroupAccessDenied: (user) => <div>User {user.email} is not an admin</div>,
  },
);
```
