---
rootSdk: React
title: "useAuth"
category: Hooks
description: "useAuth() is a client-side hook that exposes the current authentication state and actions provided by MonoCloudAuthProvider."
---

# Hook: useAuth

> **useAuth**(): [`MonoCloudAuth`](/sdks/react/api-reference/types/monocloudauth)

`useAuth()` is a client-side hook that exposes the current authentication
state and actions provided by [MonoCloudAuthProvider](/sdks/react/api-reference/components/monocloudauthprovider).

## Returns

[`MonoCloudAuth`](/sdks/react/api-reference/types/monocloudauth)

The current [MonoCloudAuth](/sdks/react/api-reference/types/monocloudauth).

## Examples

```tsx:src/Profile.tsx tab="Reading the authentication state" tab-group="useAuth"
"use client";

import { useAuth } from "@monocloud/auth-react";

export default function Home() {
  const { isLoading, isAuthenticated, user } = useAuth();

  if (isLoading) {
    return <>Loading...</>;
  }

  if (!isAuthenticated) {
    return <>Not signed in</>;
  }

  return <>User Id: {user?.sub}</>;
}
```

```tsx:src/Profile.tsx tab="Triggering actions" tab-group="useAuth"
"use client";

import { useAuth } from "@monocloud/auth-react";

export default function Account() {
  const { signOut, refetchUserInfo } = useAuth();

  return (
    <>
      <button onClick={() => refetchUserInfo()}>Refresh profile</button>
      <button onClick={() => signOut()}>Sign out</button>
    </>
  );
}
```
