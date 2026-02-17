---
rootSdk: Next.js
title: "useAuth"
category: Hooks
---

# Hook: useAuth

> **useAuth**(): [`AuthenticationState`](/sdks/nextjs/api-reference/types/authenticationstate)

`useAuth()` is a client-side hook that provides access to the current authentication state.

It can only be used inside **Client Components**.

## Returns

[`AuthenticationState`](/sdks/nextjs/api-reference/types/authenticationstate)

## Examples

```tsx title="Basic Usage"
"use client";

import { useAuth } from "@monocloud/auth-nextjs/client";

export default function Home() {
  const { user, isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <>Not signed in</>;
  }

  return <>User Id: {user?.sub}</>;
}
```

Calling `refetch(true)` forces a refresh of the user profile from the UserInfo endpoint.
Calling `refetch()` refreshes authentication state without forcing a UserInfo request.

```tsx title="Refetch User"
"use client";

import { useAuth } from "@monocloud/auth-nextjs/client";

export default function Home() {
  const { user, refetch } = useAuth();

  return (
    <>
      <pre>{JSON.stringify(user, null, 2)}</pre>
      <button onClick={() => refetch(true)}>Refresh Profile</button>
    </>
  );
}
```
