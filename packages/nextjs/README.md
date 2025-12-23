![MonoCloud Logo](https://raw.githubusercontent.com/monocloud/auth-js/refs/heads/main/MonoCloud.png)

## Introduction

**MonoCloud Auth Next.js SDK – Secure authentication and session management for Next.js applications.**

[MonoCloud](https://www.monocloud.com) is a modern, developer-friendly Identity & Access Management platform.

This SDK is designed specifically for **Next.js**, providing seamless integration with both **App Router** and **Pages Router**. It leverages Next.js Middleware and Edge runtime capabilities to offer secure, server-side authentication with minimal configuration.

## 📘 Documentation

- **Documentation:** [Quickstart](https://www.monocloud.com/docs/quickstarts/nextjs-app-router) | [SDK Reference](https://www.monocloud.com/docs/sdk-reference/nextjs/index)

## Supported Platforms

- **Next.js >= 13.0.0** (App Router & Pages Router)
- **Node.js >= 16.0.0**

## 🚀 Getting Started

### Requirements

- A **MonoCloud Tenant**
- A **Client ID** and **Client Secret**
- A **Random Secret** (32+ characters) for cookie encryption

## 📦 Installation

```bash
npm install @monocloud/auth-nextjs
```

### Initialization

### Setup Environment Variables

Create a `.env.local` file in your project root. The SDK automatically detects variables prefixed with `MONOCLOUD_AUTH_...`.

```env
MONOCLOUD_AUTH_DOMAIN=https://<your-tenant-domain>
MONOCLOUD_AUTH_CLIENT_ID=<your-client-id>
MONOCLOUD_AUTH_CLIENT_SECRET=<your-client-secret>
MONOCLOUD_AUTH_COOKIE_SECRET=<long-random-string>
MONOCLOUD_AUTH_APP_URL=http://localhost:3000
```

Tip: Generate a secure cookie secret using the following command:

```bash
openssl rand -hex 32
```

### Create Next Client

Create a centralized configuration file (e.g., lib/monocloud.ts) to export your SDK instance.

```typescript
import { MonoCloudNextClient } from '@monocloud/auth-nextjs';

// Environment variables is automatically picked up
const monoCloud = new MonoCloudNextClient();
```

⚠️ Security Note: Never commit your credentials to version control. Load them from environment variables.

#### Add MonoCloud Middleware

Protect your application using MonoCloud Middleware/Proxy. All authentication requests are handled by the middleware.

‼️ Important Note for Next.js v16+: Starting with Next.js v16, a `proxy` file strategy is recommended over standard middleware.

```typescript
import { monoCloud } from '<shared-config>';

export default monoCloud.monoCloudMiddleware();

// Allow static files
export const config = {
  matcher: ['/((?!.+\\.[\\w]+$|_next).*)', '/', '/(api|trpc)(.*)'],
};
```

#### Get Session (Server Side)

Retrieve the user session in Server Components, Route Handlers, or API routes.

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

#### Get User (Client Side)

Access user data in Client Components using the provided hook.

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

## 🤝 Contributing & Support

### Issues & Feedback

- Use **GitHub Issues** for bug reports and feature requests.
- For tenant or account-specific help, contact MonoCloud Support through your dashboard.

### Security

Do **not** report security issues publicly. Please follow the contact instructions at: https://www.monocloud.com/contact

## 📄 License

Licensed under the **MIT License**. See the included [`LICENSE`](https://github.com/monocloud/auth-js/blob/main/LICENSE) file.
