---
rootSdk: Next.js
title: "Protected"
category: Components
---

# Component: &lt;Protected&gt;

`<Protected>` conditionally renders its children based on the user’s authentication state and (optionally) group membership.

> `<Protected>` runs on the client and only affects what is rendered. It does **not** prevent data from being sent to the browser.
> To enforce access before content is rendered or sent to the client, use server-side protection such as [protectPage()](/sdks/nextjs/api-reference/classes/monocloudnextclient#protectpage), or [protect()](/sdks/nextjs/api-reference/classes/monocloudnextclient#protect).

## Props

| Property                                                | Type                                                                                      | Description                                                                                                                                                                 |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `children`                        | `ReactNode`                                                                               | Content to render when access is allowed.                                                                                                                                   |
| `fallback?`                       | `ReactNode`                                                                               | Content to render when the user is not authenticated.                                                                                                                       |
| `groups?`                           | `string`[]                                                                                | Groups required to view the protected content. By default, the user must belong to **any** of the specified groups.                                                         |
| `groupsClaim?`                 | `string`                                                                                  | Name of the claim that contains groups in the user profile.                                                                                                                 |
| `matchAllGroups?`           | `boolean`                                                                                 | If `true`, the user must belong to **all** specified `groups` (instead of any).                                                                                             |
| `onGroupAccessDenied?` | (`user`: [`MonoCloudUser`](/sdks/nextjs/api-reference/types/monoclouduser)) => `ReactNode` | Rendered when the user is authenticated but does not meet the `groups` requirement. If omitted, nothing is rendered (or `fallback` is used only for unauthenticated users). |


## Examples

```tsx title="Basic Usage"
"use client";

import { Protected } from "@monocloud/auth-nextjs/components/client";

export default function Home() {
  return (
    <Protected fallback={<>Sign in to view the message.</>}>
      <>This is the protected content.</>
    </Protected>
  );
}
```

```tsx title="With Groups"
"use client";

import { Protected } from "@monocloud/auth-nextjs/components/client";

export default function Home() {
  return (
    <Protected
      groups={["admin"]}
      onGroupAccessDenied={(user) => (
        <>User {user.email} is not allowed to access admin content.</>
      )}
    >
      <>Signed in as admin</>
    </Protected>
  );
}
```

```tsx title="Requiring all groups"
"use client";

import { Protected } from "@monocloud/auth-nextjs/components/client";

export default function Home() {
  return (
    <Protected
      groups={["admin", "billing"]}
      matchAllGroups
      onGroupAccessDenied={(user) => (
        <>User {user.email} is not allowed to access billing content.</>
      )}
    >
      <>Sensitive settings</>
    </Protected>
  );
}
```
