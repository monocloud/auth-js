![MonoCloud Logo](https://raw.githubusercontent.com/monocloud/auth-js/refs/heads/main/MonoCloud.png)

## Introduction

**MonoCloud OIDC Client for JavaScript – Secure OpenID Connect authentication for your applications.**

[MonoCloud](https://www.monocloud.com) is a modern, developer-friendly Identity & Access Management platform.

This SDK provides a standards-compliant OpenID Connect (OIDC) client for interacting with MonoCloud, supporting Authorization Code Flow, PKCE, Pushed Authorization Requests (PAR), and token management.

## 📘 Documentation

- **Documentation:** https://www.monocloud.com/docs

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
import { MonoCloudOidcClient } from '@monocloud/auth-core';

const oidcClient = new MonoCloudOidcClient(
  'https://<your-tenant-domain>',
  '<your-client-id>',
  {
    // Optional: clientSecret for confidential clients
    clientSecret: '<your-client-secret>',
  }
);
```

## Usage

### Generate Authorization URL

Initiate the sign in by generating an authorization URL.

```typescript
import { generateNonce, generateState } from '@monocloud/auth-core/utils';

const authorizeUrl = await oidcClient.authorizationUrl({
  redirectUri: '<registered callback url>',
  scopes: 'openid profile email',
  nonce: generateNonce(),
  state: generateState(),
});

// Redirect the user to authorizeUrl
```

### Handle Callback

After the user authenticates, exchange the returned authorization code for a session.

```typescript
// 'code' comes from the query parameters in the callback URL
const session = await oidcClient.authenticate(
  '<code>',
  '<registered callback url>',
  'openid profile email'
);

console.log(session.user); // User profile info
console.log(session.idToken); // Raw ID Token
```

### Refresh Session

Rotate tokens using the refresh token flow.

```typescript
const refreshedSession = await oidcClient.refreshSession(session);

console.log(refreshedSession);
```

## 🤝 Contributing & Support

### Issues & Feedback

- Use **GitHub Issues** for bug reports and feature requests.
- For tenant or account-specific help, contact MonoCloud Support through your dashboard.

### Security

Do **not** report security issues publicly. Please follow the contact instructions at: https://www.monocloud.com/contact

## 📄 License

Licensed under the **MIT License**. See the included [`LICENSE`](https://github.com/monocloud/auth-js/blob/main/LICENSE) file.
