![MonoCloud Logo](https://raw.githubusercontent.com/monocloud/auth-js/refs/heads/main/MonoCloud.png)

## Introduction

**MonoCloud Auth Next.js SDK – secure authentication and session management for Next.js applications.**

[MonoCloud](https://www.monocloud.com?utm_source=github&utm_medium=auth_js) is a modern, developer-friendly Identity & Access Management platform.

This SDK is designed specifically for **Next.js**, providing first-class integration with both the **App Router** and **Pages Router**. It leverages **Next.js Middleware**, **Server Components**, and **Edge-compatible APIs** to deliver secure, server-side authentication with minimal configuration.

## 📘 Documentation

- **Quickstart:**  [https://www.monocloud.com/docs/quickstarts/nextjs-app-router](https://www.monocloud.com/docs/quickstarts/nextjs-app-router?utm_source=github&utm_medium=auth_js)
- **SDK Reference:**  [https://www.monocloud.com/docs/sdk-reference/nextjs](https://www.monocloud.com/docs/sdk-reference/nextjs/index?utm_source=github&utm_medium=auth_js)

## Supported Platforms

- **Next.js ≥ 13.0.0** (App Router & Pages Router)
- **Node.js ≥ 16.0.0**
- **Edge Runtime** (where supported by Next.js)

## 🚀 Getting Started

### Requirements

- A **MonoCloud Tenant**
- A **Client ID** and **Client Secret**
- A **Random secret** (32+ characters) for encrypting session cookies

## 📦 Installation

```bash
npm install @monocloud/auth-nextjs
```

### Initialization

### Set up environment variables

Create a `.env.local` file in your project root. The SDK automatically reads variables prefixed with `MONOCLOUD_AUTH__`.

```env
MONOCLOUD_AUTH_TENANT_DOMAIN=https://<your-tenant-domain>
MONOCLOUD_AUTH_CLIENT_ID=<your-client-id>
MONOCLOUD_AUTH_CLIENT_SECRET=<your-client-secret>
MONOCLOUD_AUTH_COOKIE_SECRET=<long-random-string>
MONOCLOUD_AUTH_APP_URL=http://localhost:3000
```

Generate a secure cookie secret:

```bash
openssl rand -hex 32
```

⚠️ Security Note: Never commit secrets to source control. Always load them from environment variables.

### Create Next Client

Create a shared MonoCloud client instance (for example, `lib/monocloud.ts`) and reuse it throughout your application.

```typescript
import { MonoCloudNextClient } from '@monocloud/auth-nextjs';

// Environment variables are picked up automatically
export const monoCloud = new MonoCloudNextClient();
```

⚠️ Security Note: Never commit your credentials to version control. Load them from environment variables.

### Add MonoCloud Middleware

Protect your application by registering the MonoCloud middleware. Authentication routes, redirects, and callbacks are handled automatically.

‼️ Important (Next.js v16+): Starting with Next.js 16, authentication middleware is implemented using a **proxy-based approach** rather than traditional middleware files. MonoCloud follows this recommended proxy pattern for handling authentication flows.

```typescript
import { monoCloud } from '<shared-config>';

export default monoCloud.authMiddleware();

// Allow static files
export const config = {
  matcher: ['/((?!.+\\.[\\w]+$|_next).*)', '/', '/(api|trpc)(.*)'],
};
```

### Get Session (Server-side)

Retrieve the authenticated session in **Server Components, Route Handlers, or API routes**.

```tsx
import { monoCloud } from '<shared-config>';

export default async function Page() {
  const session = await monoCloud.getSession();

  return (
    <div>
      <h1>Welcome, {session?.user?.name}</h1>
      <p>Email: {session?.user?.email}</p>
    </div>
  );
}
```

### Get User (Client-side)

Access user data in **Client Components** using the provided hook.

```tsx
'use client';

import { useMonoCloudAuth } from '@monocloud/auth-nextjs/client';

export default function Page() {
  const { user } = useMonoCloudAuth();

  return (
    <div>
      <h1>Welcome, {user?.name}</h1>
      <p>Email: {user?.email}</p>
    </div>
  );
}
```
## When should I use `auth-nextjs`?

Use **`@monocloud/auth-nextjs`** if you are building a **Next.js application** and want a secure authentication solution with minimal configuration.

This package is a good fit if you:

- Are using **Next.js (App Router or Pages Router)**
- Want **secure, cookie-based sessions** managed for you
- Need authentication in **Server Components, Route Handlers, API routes, and middleware/proxy**
- Prefer **framework-native helpers and React hooks**
- Want an **opinionated, batteries-included** authentication experience

## 🤝 Contributing & Support

### Issues & Feedback

- Use **GitHub Issues** for bug reports and feature requests.
- For tenant or account-specific help, contact MonoCloud Support through your dashboard.

### Security

Do **not** report security issues publicly. Please follow the contact instructions at: [https://www.monocloud.com/contact](https://www.monocloud.com/contact?utm_source=github&utm_medium=auth_js)

## 📄 License

Licensed under the **MIT License**. See the included [`LICENSE`](https://github.com/monocloud/auth-js/blob/main/LICENSE) file.
