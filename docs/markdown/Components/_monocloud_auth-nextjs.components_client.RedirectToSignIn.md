---
rootSdk: Next.js
title: "RedirectToSignIn"
category: Components
---

# Component: &lt;RedirectToSignIn&gt;

`<RedirectToSignIn>` is a **client-side component** that immediately redirects the user to the MonoCloud sign-in page when it is rendered.

It does not render any UI.

> This component must be used inside a Client Component (`"use client"`).

## Props

| Property                                            | Type                                                                                  | Description                                                                                                                     |
| --------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `acrValues?`                 | `string`[]                                                                            | Authentication Context Class Reference (ACR) values requesting specific authentication assurance levels or methods.             |
| `authenticatorHint?` | [`Authenticators`](/sdks/nextjs/api-reference/enums/authenticators) | Hint to the authorization server indicating which authenticator or connection should be used.                                   |
| `display?`                     | [`DisplayOptions`](/sdks/nextjs/api-reference/enums/displayoptions) | Preferred display mode for the authentication UI.                                                                               |
| `loginHint?`                 | `string`                                                                              | Hint identifying the user (for example, email or username). Used to prefill or optimize the sign-in experience.                 |
| `maxAge?`                       | `number`                                                                              | Maximum acceptable time (in seconds) since the user last authenticated. If exceeded, the user may be required to sign in again. |
| `prompt?`                       | [`Prompt`](/sdks/nextjs/api-reference/enums/prompt)                 | Controls authentication interaction behavior. For example, forcing login or consent.                                            |
| `resource?`                   | `string`                                                                              | Space-separated list of resource indicators that scope the issued access token.                                                 |
| `returnUrl?`                 | `string`                                                                              | The URL to return to after successful authentication. If not provided, the current URL is used.                                 |
| `scopes?`                       | `string`                                                                              | Space-separated list of scopes requested during authentication.                                                                 |
| `uiLocales?`                 | `string`                                                                              | Preferred UI language.                                                                                                          |


## Examples

```tsx title="Basic Usage"
"use client";

import { useAuth } from "@monocloud/auth-nextjs/client";
import { RedirectToSignIn } from "@monocloud/auth-nextjs/components/client";

export default function Home() {
  const { isLoading, isAuthenticated } = useAuth();

  if (!isLoading && !isAuthenticated) {
    return <RedirectToSignIn />;
  }

  return <>You are signed in</>;
}
```

You can customize the authorization request by passing in props.

```tsx title="With options"
"use client";

import { useAuth } from "@monocloud/auth-nextjs/client";
import { RedirectToSignIn } from "@monocloud/auth-nextjs/components/client";

export default function Home() {
  const { isLoading, isAuthenticated } = useAuth();

  if (!isLoading && !isAuthenticated) {
    return (
      <RedirectToSignIn returnUrl="/dashboard" loginHint="user@example.com" />
    );
  }

  return <>You are signed in</>;
}
```
