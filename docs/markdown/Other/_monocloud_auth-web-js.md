---
rootSdk: JavaScript
title: "@monocloud/auth-web-js"
category: Other
---

# auth-web-js

<div align="center">
  <a href="https://www.monocloud.com?utm_source=github&utm_medium=auth_js" target="_blank" rel="noopener noreferrer">
    <picture>
      <img src="https://raw.githubusercontent.com/monocloud/auth-js/refs/heads/main/packages/web-js/banner.svg" alt="MonoCloud Banner">
    </picture>
  </a>
  <div align="right">
    <a href="https://www.npmjs.com/package/@monocloud/auth-web-js" target="_blank">
      <img src="https://img.shields.io/npm/v/@monocloud/auth-web-js" alt="NPM" />
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

**MonoCloud Web Authentication SDK – secure authentication for single-page applications and other browser-based JavaScript environments.**

[MonoCloud](https://www.monocloud.com?utm_source=github&utm_medium=auth_js) is a modern, developer-friendly Identity & Access Management platform.

This SDK provides a **browser-side authentication client** for single-page apps (SPAs) and any JavaScript environment running in the browser. It implements **OAuth 2.0 / OpenID Connect** with **PKCE**, handles redirect and popup flows, manages sessions and tokens, and serves as the foundation for higher-level framework SDKs (React, Vue, Angular, Svelte, Astro, etc.).

## 📘 Documentation

- **Documentation:** [https://www.monocloud.com/docs](https://www.monocloud.com/docs?utm_source=github&utm_medium=auth_js)
- **Quickstart:** [https://www.monocloud.com/docs/quickstarts/web-js](https://www.monocloud.com/docs/quickstarts/web-js?utm_source=github&utm_medium=auth_js)
- **SDK Reference:** [https://www.monocloud.com/docs/sdks/web-js](https://www.monocloud.com/docs/sdks/web-js/index?utm_source=github&utm_medium=auth_js)
- **API Reference:** [https://monocloud.github.io/auth-js](https://monocloud.github.io/auth-js?utm_source=github&utm_medium=auth_js)

## Supported Platforms

- **Modern Browsers** (Chrome, Edge, Firefox, Safari)

## 🚀 Getting Started

### Requirements

- A **MonoCloud Tenant**
- A **Client** configured as a Single Page Application (SPA)
- The application's URL registered in **Callback URLs**, **Sign-out URLs** and **Cross Origin URLs**

## 📦 Installation

```bash
npm install @monocloud/auth-web-js
```

### Initialization

Create a shared `MonoCloudWebJSClient` instance and reuse it throughout your application.

```typescript
import { MonoCloudWebJSClient } from "@monocloud/auth-web-js";

export const client = new MonoCloudWebJSClient({
  tenantDomain: "https://<your-tenant-domain>",
  clientId: "<your-client-id>",
});
```

### Process the Callback

Call `processCallback()` once at application startup. It inspects the current URL and the persisted callback state to automatically complete a pending sign-in or sign-out flow — no per-route dispatch required. When the current URL is not an in-progress callback, it is a no-op.

```typescript
await client.processCallback();
```

### Sign In and Sign Out

Start an authentication flow by redirecting the user to MonoCloud, or end the session and return the user to your sign-out callback.

```typescript
await client.signIn();

await client.signOut();
```

### Silent Sign In (SSO Restore)

Attempt to restore an authenticated session at app bootstrap without disrupting the user. Uses a hidden iframe with `prompt=none`; resolves to the new session on success, or rejects with a `MonoCloudOPError` (typically `login_required`) when the authorization server cannot satisfy the request without interaction.

```typescript
import { MonoCloudOPError } from "@monocloud/auth-web-js";

try {
  const session = await client.signInSilent();
  console.log("Restored session for:", session.user);
} catch (error) {
  if (error instanceof MonoCloudOPError && error.error === "login_required") {
    console.log("Not signed in");
  } else {
    throw error;
  }
}
```

### Get the Current Session

Retrieve the active session, including the authenticated user's profile and tokens. Returns `undefined` when no user is signed in.

```typescript
const session = await client.getSession();

if (session) {
  console.log(session.user);
}
```

## When should I use `auth-web-js`?

Use **`@monocloud/auth-web-js`** if you are building a **browser-based JavaScript application** and want a secure, OIDC-compliant authentication client without tying yourself to a specific UI framework.

This package is a good fit if you:

- Are building a **single-page application (SPA)** in plain JavaScript / TypeScript
- Are writing a **custom framework integration** on top of MonoCloud
- Need full control over **PKCE, redirects, popups, silent refresh, and token storage**
- Want **cross-tab refresh coordination** and pluggable storage out of the box

Higher-level packages build on top of `auth-web-js` and provide framework-specific ergonomics while reusing the same underlying browser implementation.

## 🤝 Contributing & Support

### Issues & Feedback

- Use **GitHub Issues** for bug reports and feature requests.
- For tenant or account-specific help, contact MonoCloud Support through your dashboard.

### Security

Do **not** report security issues publicly. Please follow the contact instructions at: [https://www.monocloud.com/contact](https://www.monocloud.com/contact?utm_source=github&utm_medium=auth_js)

## 📄 License

Licensed under the **MIT License**. See the included [`LICENSE`](https://github.com/monocloud/auth-js/blob/main/LICENSE) file.

## Modules

- [index](/sdks/web-js/api-reference/undefined/index)
- [utils](/sdks/web-js/api-reference/undefined/utils)
- [utils/internal](/sdks/web-js/api-reference/undefined/utils_internal)
