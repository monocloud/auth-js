---
rootSdk: Next.js
title: "SignOut"
category: Components
description: "<SignOut> renders a link that initiates the MonoCloud sign-out flow."
---

# Component: &lt;SignOut&gt;

`<SignOut>` renders a link that initiates the MonoCloud sign-out flow.

It can be used in both **App Router** and **Pages Router**, and may be rendered from either **Server** or **Client Components**.

## Props

| Property                                    | Type        | Description                                                                                                                                           |
| ------------------------------------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `children`            | `ReactNode` | Content rendered inside the link (for example, button text).                                                                                          |
| `federated?`         | `boolean`   | If `true`, also signs the user out of the MonoCloud server session, ensuring the user is fully logged out of MonoCloud and not just your application. |
| `postLogoutUrl?` | `string`    | URL to redirect the user to after they have been signed out.                                                                                          |


## Examples

```tsx title="Basic Usage"
import { SignOut } from "@monocloud/auth-nextjs/components";

export default function Home() {
  return <SignOut>Sign Out</SignOut>;
}
```

```tsx title="Customize the sign-out request"
import { SignOut } from "@monocloud/auth-nextjs/components";

export default function Home() {
  return (
    <SignOut federated postLogoutUrl="/goodbye">
      Sign Out
    </SignOut>
  );
}
```
