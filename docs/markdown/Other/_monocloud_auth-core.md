---
rootSdk: Node.js
title: "@monocloud/auth-core"
category: Other
---

# auth-core

<div align="center">
  <a href="https://www.monocloud.com?utm_source=github&utm_medium=auth_js" target="_blank" rel="noopener noreferrer">
    <picture>
      <img src="https://raw.githubusercontent.com/monocloud/auth-js/refs/heads/main/packages/core/banner.svg" alt="MonoCloud Banner">
    </picture>
  </a>
  <div align="right">
    <a href="https://www.npmjs.com/package/@monocloud/auth-core" target="_blank">
      <img src="https://img.shields.io/npm/v/@monocloud/auth-core" alt="NPM" />
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

**MonoCloud OIDC Client for JavaScript — a standards-compliant OpenID Connect client for secure authentication flows.**

[MonoCloud](https://www.monocloud.com?utm_source=github&utm_medium=auth_js) is a modern, developer-friendly Identity & Access Management platform.

This package provides a **framework-agnostic OpenID Connect (OIDC) client** for interacting with MonoCloud. It supports industry-standard authentication flows including **Authorization Code Flow**, **PKCE**, **Pushed Authorization Requests (PAR)**, **Device Authorization Grant**, and token lifecycle management.

> This package focuses on **core OIDC primitives**. Framework-specific integrations (such as Next.js) are provided by higher-level packages built on top of `auth-core`.

## 📘 Documentation

- **Documentation:** [https://www.monocloud.com/docs](https://www.monocloud.com/docs?utm_source=github&utm_medium=auth_js)
- **API Reference:** [https://monocloud.github.io/auth-js](https://monocloud.github.io/auth-js?utm_source=github&utm_medium=auth_js)

## Supported Platforms

- **Node.js >= 16.0.0** (Requires `fetch` and Web Crypto API)
- **Modern Browsers**

## Requirements

- A **MonoCloud Tenant**
- A **Client** configured as a Web Application or SPA

## 📦 Installation

```bash
npm install @monocloud/auth-core
```

### Initialization

```typescript
import { MonoCloudOidcClient } from "@monocloud/auth-core";

const oidcClient = new MonoCloudOidcClient(
  "https://<your-tenant-domain>",
  "<your-client-id>",
  {
    // Optional: clientSecret for confidential clients
    clientSecret: "<your-client-secret>",
  },
);
```

## Usage

### Generate an Authorization URL

Initiate sign-in by generating an authorization URL.

```typescript
import { generateNonce, generateState } from "@monocloud/auth-core/utils";

const authorizeUrl = await oidcClient.authorizationUrl({
  redirectUri: "<registered callback url>",
  scopes: "openid profile email",
  nonce: generateNonce(),
  state: generateState(),
});

// Redirect the user to authorizeUrl
```

> Note: state and nonce should always be generated per request and validated on callback to prevent CSRF and token replay attacks.

### Handle Callback

After authentication, exchange the authorization code for tokens.

```typescript
const session = await oidcClient.authenticate(
  "<code>",
  "<registered callback url>",
  "openid profile email",
);

console.log(session.user); // User profile claims
console.log(session.idToken); // Raw ID Token
```

### Refresh a Session

Rotate tokens using the refresh token flow.

```typescript
const refreshedSession = await oidcClient.refreshSession(session);

console.log(refreshedSession);
```

## When should I use `auth-core`?

Use **`@monocloud/auth-core`** if you need a **low-level, framework-agnostic** OpenID Connect client and want full control over the authentication flow.

This package is a good fit if you:

- Are building a **custom authentication integration**
- Need fine-grained control over **redirects, state, nonce, and PKCE**
- Are targeting **non-framework environments** (custom runtimes)
- Are building your own **framework adapter or SDK**
- Want a **pure OIDC client** without opinions about routing, cookies, or sessions

Higher-level packages are built on top of `auth-core` and provide framework-specific ergonomics while reusing the same underlying OIDC implementation.

## 🤝 Contributing & Support

### Issues & Feedback

- Use **GitHub Issues** for bug reports and feature requests.
- For tenant or account-specific help, contact MonoCloud Support through your dashboard.

### Security

Do **not** report security issues publicly. Please follow the contact instructions at: [https://www.monocloud.com/contact](https://www.monocloud.com/contact?utm_source=github&utm_medium=auth_js)

## 📄 License

Licensed under the **MIT License**. See the included [`LICENSE`](https://github.com/monocloud/auth-js/blob/main/LICENSE) file.

## Modules

- [index](/sdks/nodejs/api-reference/undefined/index)
- [utils](/sdks/nodejs/api-reference/undefined/utils)
- [utils/internal](/sdks/nodejs/api-reference/undefined/utils_internal)
