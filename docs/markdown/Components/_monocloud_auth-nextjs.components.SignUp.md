---
rootSdk: Next.js
title: "SignUp"
category: Components
description: "<SignUp> renders a link that initiates the MonoCloud sign-up flow."
---

# Component: &lt;SignUp&gt;

`<SignUp>` renders a link that initiates the MonoCloud sign-up flow.

It works in both **App Router** and **Pages Router**, and may be rendered from either **Server** or **Client Components**.

Internally, it behaves like `<SignIn>` but sets `prompt=create` to start the registration flow.

## Props

| Property                                | Type                                                                                  | Description                                                                                                                     |
| --------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `acrValues?`     | `string`[]                                                                            | Authentication Context Class Reference (ACR) values requesting specific authentication assurance levels or methods.             |
| `audience?`       | `string`                                                                              | Identifies the target API (audience) that the issued access token is intended for.                                              |
| `display?`         | [`DisplayOptions`](/sdks/nextjs/api-reference/enums/displayoptions) | Preferred display mode for the authentication UI.                                                                               |
| `idTokenHint?` | `string`                                                                              | A previously issued ID token used as a hint about the user's current or past authenticated session.                             |
| `maxAge?`           | `number`                                                                              | Maximum acceptable time (in seconds) since the user last authenticated. If exceeded, the user may be required to sign in again. |
| `resource?`       | `string`                                                                              | Space-separated list of resource indicators that scope the issued access token.                                                 |
| `returnUrl?`     | `string`                                                                              | URL to redirect to after successful sign-up.                                                                                    |
| `scopes?`           | `string`                                                                              | Space-separated list of scopes requested during authentication.                                                                 |
| `uiLocales?`     | `string`                                                                              | Preferred UI language.                                                                                                          |


## Examples

```tsx title="Basic Usage"
import { SignUp } from "@monocloud/auth-nextjs/components";

export default function Home() {
  return <SignUp>Sign Up</SignUp>;
}
```

You can customize the authorization request by passing in props.

```tsx title="Customize the authorization request"
import { SignUp } from "@monocloud/auth-nextjs/components";

export default function Home() {
  return (
    <SignUp returnUrl="/dashboard" uiLocales="en">
      Sign Up
    </SignUp>
  );
}
```
