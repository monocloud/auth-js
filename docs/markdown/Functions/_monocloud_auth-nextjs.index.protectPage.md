---
rootSdk: Next.js
title: "protectPage"
category: Functions
---

# Function: protectPage

## Call Signature

> **protectPage**(`component`: [`ProtectedAppServerComponent`](/sdks/nextjs/api-reference/handler-types/protectedappservercomponent), `options?`: [`ProtectAppPageOptions`](/sdks/nextjs/api-reference/types/protectapppageoptions)): [`AppRouterPageHandler`](/sdks/nextjs/api-reference/handler-types/approuterpagehandler)

Restricts access to App Router server-rendered pages.

**Access control**

- If the user is not authenticated, `onAccessDenied` is invoked (or default behavior applies).
- If the user is authenticated but fails group checks, `onGroupAccessDenied` is invoked (or the default "Access Denied" view is rendered).

Both behaviors can be customized via options.

### Parameters

| Parameter   | Type                                                                                                              | Description                                                                                                                     |
| ----------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `component` | [`ProtectedAppServerComponent`](/sdks/nextjs/api-reference/handler-types/protectedappservercomponent) | The App Router server component to protect.                                                                                     |
| `options?`  | [`ProtectAppPageOptions`](/sdks/nextjs/api-reference/types/protectapppageoptions)                         | Optional configuration for authentication, authorization, and custom access handling (`onAccessDenied`, `onGroupAccessDenied`). |

### Returns

[`AppRouterPageHandler`](/sdks/nextjs/api-reference/handler-types/approuterpagehandler)

A wrapped page component that enforces authentication before rendering.

### Examples

```tsx:src/app/page.tsx tab="Basic Usage" tab-group="protectPage-app"
import { protectPage } from "@monocloud/auth-nextjs";

export default protectPage(async function Home({ user }) {
 return <>Hi {user.email}. You accessed a protected page.</>;
});
```

```tsx:src/app/page.tsx tab="With Options" tab-group="protectPage-app"
import { protectPage } from "@monocloud/auth-nextjs";

export default protectPage(
  async function Home({ user }) {
    return <>Hi {user.email}. You accessed a protected page.</>;
  },
  {
    returnUrl: "/dashboard",
    groups: ["admin"],
  }
);
```

## Call Signature

> **protectPage**\<`P`, `Q`\>(`options?`: [`ProtectPagePageOptions`](/sdks/nextjs/api-reference/types/protectpagepageoptions)\<`P`, `Q`\>): [`ProtectPagePageReturnType`](/sdks/nextjs/api-reference/handler-types/protectpagepagereturntype)\<`P`, `Q`\>

Restricts access to Pages Router server-rendered pages using `getServerSideProps`.

**Access control**

- If the user is not authenticated, `onAccessDenied` is invoked (or default behavior applies).
- If the user is authenticated but fails group checks, the page can still render and `groupAccessDenied` is provided in props. Use `onGroupAccessDenied` to customize the props or behavior.

Both behaviors can be customized via options.

### Type Parameters

| Type Parameter                            | Description                               |
| ----------------------------------------- | ----------------------------------------- |
| `P` _extends_ `Record`\<`string`, `any`\> | Props returned from `getServerSideProps`. |
| `Q` _extends_ `ParsedUrlQuery`            | Query parameters parsed from the URL.     |

### Parameters

| Parameter  | Type                                                                                                    | Description                                                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `options?` | [`ProtectPagePageOptions`](/sdks/nextjs/api-reference/types/protectpagepageoptions)\<`P`, `Q`\> | Optional configuration for authentication, authorization, and custom access handling (`onAccessDenied`, `onGroupAccessDenied`). |

### Returns

[`ProtectPagePageReturnType`](/sdks/nextjs/api-reference/handler-types/protectpagepagereturntype)\<`P`, `Q`\>

A getServerSideProps wrapper that enforces authentication before executing the page logic.

### Examples

```tsx:src/pages/index.tsx tab="Basic Usage" tab-group="protectPage-page"
import { protectPage, MonoCloudUser } from "@monocloud/auth-nextjs";

type Props = {
  user: MonoCloudUser;
};

export default function Home({ user }: Props) {
  return <>Hi {user.email}. You accessed a protected page.</>;
}

export const getServerSideProps = protectPage();
```

```tsx:src/pages/index.tsx tab="With Options" tab-group="protectPage-page"
import { protectPage, MonoCloudUser } from "@monocloud/auth-nextjs";
import { GetServerSidePropsContext } from "next";

type Props = {
  user: MonoCloudUser;
  url: string;
};

export default function Home({ user, url }: Props) {
  console.log(url);
  return <div>Hi {user?.email}. You accessed a protected page.</div>;
}

export const getServerSideProps = protectPage({
  returnUrl: "/dashboard",
  groups: ["admin"],
  getServerSideProps: async (context: GetServerSidePropsContext) => ({
    props: { url: context.resolvedUrl }
  })
});
```
