---
rootSdk: Next.js
title: "SignIn"
category: Components
description: "<SignIn> renders a link that initiates the MonoCloud sign-in flow."
---

# Component: &lt;SignIn&gt;

`<SignIn>` renders a link that initiates the MonoCloud sign-in flow.

It can be used in both **App Router** and **Pages Router**, and may be rendered from either **Server** or **Client Components**.

## Props

| Property                                            | Type                                                                                  | Description                                                                                                                     |
| --------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `acrValues?`                 | `string`[]                                                                            | Authentication Context Class Reference (ACR) values requesting specific authentication assurance levels or methods.             |
| `audience?`                   | `string`                                                                              | Identifies the target API (audience) that the issued access token is intended for.                                              |
| `authenticatorHint?` | [`Authenticators`](/sdks/nextjs/api-reference/enums/authenticators) | Hint to the authorization server indicating which authenticator or connection should be used.                                   |
| `children`                    | `ReactNode`                                                                           | Content rendered inside the link (for example, button text).                                                                    |
| `display?`                     | [`DisplayOptions`](/sdks/nextjs/api-reference/enums/displayoptions) | Preferred display mode for the authentication UI.                                                                               |
| `idTokenHint?`             | `string`                                                                              | A previously issued ID token used as a hint about the user's current or past authenticated session.                             |
| `loginHint?`                 | `string`                                                                              | Hint identifying the user (for example, email or username). Used to prefill or optimize the sign-in experience.                 |
| `maxAge?`                       | `number`                                                                              | Maximum acceptable time (in seconds) since the user last authenticated. If exceeded, the user may be required to sign in again. |
| `prompt?`                       | [`Prompt`](/sdks/nextjs/api-reference/enums/prompt)                 | Controls authentication interaction behavior. For example, forcing login or consent.                                            |
| `resource?`                   | `string`                                                                              | Space-separated list of resource indicators that scope the issued access token.                                                 |
| `returnUrl?`                 | `string`                                                                              | URL to redirect to after successful sign-in.                                                                                    |
| `scopes?`                       | `string`                                                                              | Space-separated list of scopes requested during authentication.                                                                 |
| `uiLocales?`                 | `string`                                                                              | Preferred UI language.                                                                                                          |


## Examples

```tsx title="Basic Usage"
import { SignIn } from "@monocloud/auth-nextjs/components";

export default function Home() {
  return <SignIn>Sign In</SignIn>;
}
```

You can customize the authorization request by passing props:

```tsx title="Customize the authorization request"
import { SignIn } from "@monocloud/auth-nextjs/components";

export default function Home() {
  return (
    <SignIn
      loginHint="user@example.com"
      authenticatorHint="password"
      returnUrl="/dashboard"
    >
      Sign In
    </SignIn>
  );
}
```
