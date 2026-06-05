---
rootSdk: React
title: "useClient"
category: Hooks
description: "useClient() returns the underlying MonoCloudWebJSClient created by MonoCloudAuthProvider."
---

# Hook: useClient

> **useClient**(): [`MonoCloudWebJSClient`](/sdks/react/api-reference/classes/monocloudwebjsclient)

`useClient()` returns the underlying [MonoCloudWebJSClient](/sdks/react/api-reference/classes/monocloudwebjsclient) created by
[MonoCloudAuthProvider](/sdks/react/api-reference/components/monocloudauthprovider).

## Returns

[`MonoCloudWebJSClient`](/sdks/react/api-reference/classes/monocloudwebjsclient)

The underlying [MonoCloudWebJSClient](/sdks/react/api-reference/classes/monocloudwebjsclient) instance.

## Remarks

This is intended for advanced, lower-level operations that
[useAuth](/sdks/react/api-reference/hooks/useauth) does not cover - for example token revocation via
`client.oidcClient`. Most applications only need [useAuth](/sdks/react/api-reference/hooks/useauth).

## Example

```tsx title="Revoking the access token"
"use client";

import { useAuth, useClient } from "@monocloud/auth-react";

export default function RevokeButton() {
  const { getTokens } = useAuth();
  const client = useClient();

  const revoke = async () => {
    const tokens = await getTokens();
    await client.oidcClient.revokeToken(tokens.accessToken);
  };

  return <button onClick={() => revoke()}>Revoke</button>;
}
```
