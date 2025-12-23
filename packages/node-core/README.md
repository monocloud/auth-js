![MonoCloud Logo](https://raw.githubusercontent.com/monocloud/auth-js/refs/heads/main/MonoCloud.png)

## Introduction

**MonoCloud Auth Node SDK – Secure authentication and session management for Node.js applications.**

[MonoCloud](https://www.monocloud.com) is a modern, developer-friendly Identity & Access Management platform.

This SDK provides a robust, high-level client for integrating MonoCloud authentication into Node.js backends. It handles the complexity of the OpenID Connect (OIDC) protocol such as:

- **Authorization Code Flow** with PKCE.
- **Session Management** (Encrypted Cookies).
- **Token Rotation** (Automatic Refresh Tokens).

## 📘 Documentation

- **Documentation:** https://www.monocloud.com/docs

## Supported Platforms

- **Node.js >= 16.0.0**

## Requirements

- A **MonoCloud Tenant**
- A **Client ID** and **Client Secret** (configured as a Web Application)
- A **Random Secret** (32+ characters) for cookie encryption

## 📦 Installation

```bash
npm install @monocloud/auth-node-core
```

### Initialization

Initialize the client with your tenant configuration.

```typescript
import { MonoCloudCoreClient } from '@monocloud/auth-node-core';

const nodeClient = new MonoCloudCoreClient({
  tenantDomain: 'https://<your-tenant-domain>',
  clientId: '<your-client-id>',
  clientSecret: '<your-client-secret>',
  appUrl: '<application-server-url>',
  cookieSecret: '<cookie-secret>', // Used to encrypt the session cookie
});
```

⚠️ Security Note: Never commit your credentials to version control. Load them from environment variables.

## Usage

You need to set up routes to handle the OIDC flow. The SDK expects a generic request and response adapter depending on your framework.

### Sign In

Redirects the user to MonoCloud to sign in.

```typescript
import type { MonoCloudRequest, MonoCloudResponse } from '@monocloud/auth-node-core';

const request: MonoCloudRequest = ...;
const response: MonoCloudResponse = ...;

// Mount on any routes. Default - /api/auth/signin
await nodeClient.signIn(request, response);
```

### Handle Callback

Handles the redirect back from MonoCloud, validates the state, exchanges the code for tokens, and sets the session cookie.

```typescript
import type { MonoCloudRequest, MonoCloudResponse } from '@monocloud/auth-node-core';

const request: MonoCloudRequest = ...;
const response: MonoCloudResponse = ...;

// Mount on any routes. Default - /api/auth/callback
await nodeClient.callback(request, response);
```

### Sign Out

Destroys the local session and redirects to MonoCloud to end the SSO session.

```typescript
import type { MonoCloudRequest, MonoCloudResponse } from '@monocloud/auth-node-core';

const request: MonoCloudRequest = ...;
const response: MonoCloudResponse = ...;

// Mount on any routes. Default - /api/auth/signout
await nodeClient.signOut(request, response);
```

### Get Session

```typescript
const session = await nodeClient.getSession(request, response);

console.log(session);
```

## 🤝 Contributing & Support

### Issues & Feedback

- Use **GitHub Issues** for bug reports and feature requests.
- For tenant or account-specific help, contact MonoCloud Support through your dashboard.

### Security

Do **not** report security issues publicly. Please follow the contact instructions at: https://www.monocloud.com/contact

## 📄 License

Licensed under the **MIT License**. See the included [`LICENSE`](https://github.com/monocloud/auth-js/blob/main/LICENSE) file.
