---
rootSdk: React
title: "SignOut"
category: Components
description: "<SignOut> renders a button that starts the sign-out flow when clicked."
---

# Component: &lt;SignOut&gt;

`<SignOut>` renders a button that starts the sign-out flow when clicked.

## Props

| Property                                                    | Type                                                                             | Description                                                                                                                                                                                                                  |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `children`                            | `ReactNode`                                                                      | Content rendered inside the button.                                                                                                                                                                                          |
| `federatedSignOut?`           | `boolean`                                                                        | When `true`, signs the user out from both the application and MonoCloud (Single Sign-Out). Overrides the client-level `federatedSignOut` configuration for this specific call. If omitted, the client-level setting is used. |
| `idTokenHint?`                     | `string`                                                                         | A previously issued ID token to send as the `id_token_hint` on the logout request. When provided, this overrides the ID token from the current session. Use it to supply the hint manually.                                  |
| `mode?`                                   | [`InteractionMode`](/sdks/react/api-reference/enums/interactionmode) | Determines the interaction mode for the sign-out flow.                                                                                                                                                                       |
| `postLogoutRedirectUri?` | `string`                                                                         | URL to redirect the user to after sign-out completes. This URI must be registered in the application's sign-out URLs in MonoCloud.                                                                                           |
| `returnUrl?`                         | `string`                                                                         | Relative URL to navigate to after sign-out completes.                                                                                                                                                                        |


## Examples

```tsx:src/SignOutButton.tsx tab="Basic Usage" tab-group="SignOut"
"use client";

import { SignOut } from "@monocloud/auth-react";

export default function Home() {
  return <SignOut>Sign Out</SignOut>;
}
```

```tsx:src/SignOutButton.tsx tab="Customized" tab-group="SignOut"
"use client";

import { SignOut } from "@monocloud/auth-react";

export default function Home() {
  return (
    <SignOut federatedSignOut>
      Log out
    </SignOut>
  );
}
```
