---
rootSdk: Node.js Core
title: "@monocloud/auth-node-core"
category: Other
---

# auth-node-core

<div align="center">
  <a href="https://www.monocloud.com?utm_source=github&utm_medium=auth_js" target="_blank" rel="noopener noreferrer">
    <picture>
      <img src="https://raw.githubusercontent.com/monocloud/auth-js/refs/heads/main/packages/node-core/banner.svg" alt="MonoCloud Banner">
    </picture>
  </a>
  <div align="right">
    <a href="https://www.npmjs.com/package/@monocloud/auth-node-core" target="_blank">
      <img src="https://img.shields.io/npm/v/@monocloud/auth-node-core" alt="NPM" />
    </a>
    <a href="https://opensource.org/licenses/MIT">
      <img src="https://img.shields.io/:license-MIT-blue.svg?style=flat" alt="License: MIT" />
    </a>
    <a href="https://github.com/monocloud/auth-js/actions/workflows/build.yml">
      <img src="https://github.com/monocloud/auth-js/actions/workflows/build.yml/badge.svg" alt="Build Status" />
    </a>
  </div>
</div>

## Introduction

**MonoCloud Auth Node SDK – secure authentication and session management for Node.js backends.**

[MonoCloud](https://www.monocloud.com?utm_source=github&utm_medium=auth_js) is a modern, developer-friendly Identity & Access Management platform.

This package provides a **high-level authentication client for Node.js applications**, built on top of MonoCloud’s OpenID Connect (OIDC) implementation. It abstracts the complexity of OAuth/OIDC while remaining framework-agnostic.

The SDK handles:

- **Authorization Code Flow** with PKCE
- **Secure session management** using encrypted cookies
- **Automatic token rotation** via refresh tokens
- **State and CSRF validation** out of the box

> This package builds on **`@monocloud/auth-core`** and adds Node.js–specific session and cookie handling.

## 📘 Documentation

- **Documentation:** [https://www.monocloud.com/docs](https://www.monocloud.com/docs?utm_source=github&utm_medium=auth_js)
- **API Reference:** [https://monocloud.github.io/auth-js](https://monocloud.github.io/auth-js?utm_source=github&utm_medium=auth_js)

## Supported Platforms

- **Node.js >= 20.0.0**

## Requirements

- A **MonoCloud Tenant**
- A **Client ID** and **Client Secret** (configured as a _Web Application_)
- A **Random secret** (32+ characters) for encrypting session cookies

## 📦 Installation

```bash
npm install @monocloud/auth-node-core
```

### Initialization

Initialize the client with your tenant and application configuration.

```typescript
import { MonoCloudCoreClient } from "@monocloud/auth-node-core";

const nodeClient = new MonoCloudCoreClient({
  tenantDomain: "https://<your-tenant-domain>",
  clientId: "<your-client-id>",
  clientSecret: "<your-client-secret>",
  appUrl: "<application-server-url>",
  cookieSecret: "<cookie-secret>", // Used to encrypt the session cookie
});
```

⚠️ Security Note: Never commit secrets to source control. Always load them from environment variables.

## Usage

The SDK is **framework-agnostic**. It operates on generic request/response adapters so it can be used with Express, Fastify, Hapi, or custom servers.

### Sign In

Redirects the user to MonoCloud to start authentication.

```typescript
import type { MonoCloudRequest, MonoCloudResponse } from '@monocloud/auth-node-core';

const request: MonoCloudRequest =   /* framework adapter */;
const response: MonoCloudResponse = /* framework adapter */;

// Default route: /api/auth/signin
await nodeClient.signIn(request, response);
```

### Handle Callback

Handles the redirect from MonoCloud, validates state, exchanges the authorization code for tokens, and sets the encrypted session cookie.

```typescript
import type { MonoCloudRequest, MonoCloudResponse } from '@monocloud/auth-node-core';

const request: MonoCloudRequest =   /* framework adapter */;
const response: MonoCloudResponse = /* framework adapter */;

// Default route: /api/auth/callback
await nodeClient.callback(request, response);
```

### Get Session

Retrieve the current authenticated session from the request.

```typescript
const session = await nodeClient.getSession(request, response);

console.log(session);
```

### Sign Out

Clears the local session and redirects the user to MonoCloud to terminate the SSO session.

```typescript
import type { MonoCloudRequest, MonoCloudResponse } from '@monocloud/auth-node-core';

const request: MonoCloudRequest =   /* framework adapter */;
const response: MonoCloudResponse = /* framework adapter */;

// Default route: /api/auth/signout
await nodeClient.signOut(request, response);
```

## When should I use `auth-node-core`?

Use **`@monocloud/auth-node-core`** if you are building a **Node.js backend** and want a secure authentication solution without tying yourself to a specific framework.

This package is a good fit if you:

- Are building a **server-rendered application or backend** in Node.js that signs users in with cookie sessions
- Want **cookie-based sessions** with encryption handled for you
- Need built-in handling for **OIDC redirects, state validation, and token exchange**
- Want to manage authentication in a **custom server**
- Prefer a **framework-agnostic** solution with sensible security defaults

> If you only need to **validate access tokens** on an API server (Express or Fastify), use [`@monocloud/backend-node`](https://www.npmjs.com/package/@monocloud/backend-node) instead.

`auth-node-core` builds on top of `@monocloud/auth-core` and adds Node-specific features such as encrypted session cookies and refresh token rotation.

Higher-level packages reuse the same underlying OIDC implementation but provide framework-specific ergonomics.

## 🤝 Contributing & Support

### Issues & Feedback

- Use **GitHub Issues** for bug reports and feature requests.
- For tenant or account-specific help, contact MonoCloud Support through your dashboard.

### Security

Do **not** report security issues publicly. Please follow the contact instructions at: [https://www.monocloud.com/contact](https://www.monocloud.com/contact?utm_source=github&utm_medium=auth_js)

## 📄 License

Licensed under the **MIT License**. See the included [`LICENSE`](https://github.com/monocloud/auth-js/blob/main/LICENSE) file.

## Modules

- [index](/sdks/nodejs-core/api-reference/undefined/index)
- [utils](/sdks/nodejs-core/api-reference/undefined/utils)
- [utils/internal](/sdks/nodejs-core/api-reference/undefined/utils_internal)
