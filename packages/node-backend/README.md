<div align="center">
  <a href="https://www.monocloud.com?utm_source=github&utm_medium=auth_js" target="_blank" rel="noopener noreferrer">
    <picture>
      <img src="https://raw.githubusercontent.com/monocloud/auth-js/refs/heads/main/packages/node-backend/banner.svg" alt="MonoCloud Banner">
    </picture>
  </a>
  <div align="right">
    <a href="https://www.npmjs.com/package/@monocloud/backend-node" target="_blank">
      <img src="https://img.shields.io/npm/v/@monocloud/backend-node" alt="NPM" />
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

**MonoCloud Backend Node SDK -- secure access token validation for Node.js API servers.**

[MonoCloud](https://www.monocloud.com?utm_source=github&utm_medium=auth_js) is a modern, developer-friendly Identity & Access Management platform.

This SDK enables **API servers** to validate incoming access tokens issued by MonoCloud. It supports both **JWT validation** and **token introspection**, with built-in framework integrations for **Express** and **Fastify**.

The SDK handles:

- **JWT access token validation** with signature and claims verification
- **Opaque token introspection** via the OpenID Connect introspection endpoint
- **Automatic token format detection** (JWT vs. opaque)
- **Scope and group-based authorization**
- **Optional caching** of token introspection results
- **mTLS certificate-bound token validation**

> This package builds on **`@monocloud/auth-core`** and adds Node.js-specific API protection features.

## 📘 Documentation

- **Documentation:** [https://www.monocloud.com/docs](https://www.monocloud.com/docs?utm_source=github&utm_medium=auth_js)
- **Express Quickstart:** [https://www.monocloud.com/docs/quickstarts/express-backend](https://www.monocloud.com/docs/quickstarts/express-backend?utm_source=github&utm_medium=auth_js)
- **Express SDK Reference:** [https://www.monocloud.com/docs/sdks/express-backend](https://www.monocloud.com/docs/sdks/express-backend/index?utm_source=github&utm_medium=auth_js)
- **Fastify Quickstart:** [https://www.monocloud.com/docs/quickstarts/fastify-backend](https://www.monocloud.com/docs/quickstarts/fastify-backend?utm_source=github&utm_medium=auth_js)
- **Fastify SDK Reference:** [https://www.monocloud.com/docs/sdks/fastify-backend](https://www.monocloud.com/docs/sdks/fastify-backend/index?utm_source=github&utm_medium=auth_js)
- **API Reference:** [https://monocloud.github.io/auth-js](https://monocloud.github.io/auth-js?utm_source=github&utm_medium=auth_js)

## Supported Platforms

- **Node.js >= 20.0.0**

## Requirements

- A **MonoCloud Tenant**
- An **Audience URI** (the identifier for your API)
- Optionally, a **Client ID** and **Client Secret** (required for token introspection)

## 📦 Installation

```bash
npm install @monocloud/backend-node
```

### Configuration

The SDK reads configuration from environment variables prefixed with `MONOCLOUD_BACKEND_`. You can also pass options directly to the client or middleware.

```bash
MONOCLOUD_BACKEND_TENANT_DOMAIN=https://<your-tenant-domain>
MONOCLOUD_BACKEND_AUDIENCE=https://<your-api-identifier>
MONOCLOUD_BACKEND_CLIENT_ID=<your-client-id>          # Required for introspection
MONOCLOUD_BACKEND_CLIENT_SECRET=<your-client-secret>  # Required for introspection
```

⚠️ Security Note: Never commit secrets to source control. Always load them from environment variables.

## Usage

### Express

Protect your Express API routes using the `protectApi` middleware.

```typescript
import express from 'express';
import {
  protectApi,
  type AuthenticatedExpressRequest,
} from '@monocloud/backend-node/express';

const app = express();

// Create the middleware (reads from environment variables)
const protect = protectApi();

// Protect a route — validates the Bearer token automatically
app.get('/api/protected', protect(), (req, res) => {
  const { claims } = req as AuthenticatedExpressRequest;
  res.json({ claims });
});

// Require specific scopes
app.get('/api/data', protect({ scopes: ['data:write'] }), (req, res) => {
  res.json({ message: 'data:write access granted' });
});

// Require specific groups
app.get('/api/team', protect({ groups: ['engineering'] }), (req, res) => {
  res.json({ message: 'team access granted' });
});

app.listen(3000);
```

### Fastify

Protect your Fastify API routes using the `protectApi` hook.

```typescript
import Fastify from 'fastify';
import {
  protectApi,
  type AuthenticatedFastifyRequest,
} from '@monocloud/backend-node/fastify';

const fastify = Fastify();

// Create the hook (reads from environment variables)
const protect = protectApi();

// Protect a route
fastify.get('/api/protected', { onRequest: protect() }, async request => {
  const { claims } = request as AuthenticatedFastifyRequest;
  return { claims };
});

// Require specific scopes
fastify.get(
  '/api/data',
  { onRequest: protect({ scopes: ['data:write'] }) },
  async () => {
    return { message: 'data:write access granted' };
  }
);

// Require specific groups
fastify.get(
  '/api/team',
  { onRequest: protect({ groups: ['engineering'] }) },
  async () => {
    return { message: 'team access granted' };
  }
);

fastify.listen({ port: 3000 });
```

## When should I use `@monocloud/backend-node`?

Use **`@monocloud/backend-node`** if you are building a **Node.js API server** that needs to validate access tokens from incoming requests.

This package is a good fit if you:

- Are building a **backend API** that accepts access tokens from clients or frontends
- Need to validate **JWT** or **opaque** access tokens
- Want built-in **scope and group-based authorization**
- **Validate certificate binding** for mTLS-protected tokens
- Are using **Express** or **Fastify** and want ready-made middleware
- Need a **framework-agnostic client** for custom server implementations

> This SDK is for **API protection** (validating tokens). If you need **user authentication** (sign-in, sessions, cookies), use [`@monocloud/auth-node-core`](https://www.npmjs.com/package/@monocloud/auth-node-core) or [`@monocloud/auth-nextjs`](https://www.npmjs.com/package/@monocloud/auth-nextjs) instead.

## 🤝 Contributing & Support

### Issues & Feedback

- Use **GitHub Issues** for bug reports and feature requests.
- For tenant or account-specific help, contact MonoCloud Support through your dashboard.

### Security

Do **not** report security issues publicly. Please follow the contact instructions at: [https://www.monocloud.com/contact](https://www.monocloud.com/contact?utm_source=github&utm_medium=auth_js)

## 📄 License

Licensed under the **MIT License**. See the included [`LICENSE`](https://github.com/monocloud/auth-js/blob/main/LICENSE) file.
